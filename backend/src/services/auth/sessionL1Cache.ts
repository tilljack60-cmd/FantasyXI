/**
 * Issue #439 — L1 In-Memory Session Cache
 *
 * Node-local LRU cache for active session validation.  Sits in front of the
 * full Redis / DB lookup and answers the overwhelming majority of auth-
 * middleware calls without any network round trip.
 *
 * Design decisions
 * ────────────────
 * • LRU eviction — bounded by SESSION_L1_MAX_SIZE (default 10 000 entries).
 *   Entries are evicted least-recently-used when the ceiling is hit, so hot
 *   sessions stay warm even if many idle sessions exist.
 * • Per-entry TTL — each entry stores its own absolute expiry timestamp so
 *   the cache never serves a structurally expired session even if the LRU
 *   clock hasn't evicted it yet.
 * • Revocation tombstones — a revoked session is *replaced* with a negative
 *   entry (valid: false) rather than deleted, so the cache can answer
 *   "is this revoked?" without falling through to Redis/DB.  Tombstones use
 *   a shorter TTL (SESSION_L1_TOMBSTONE_TTL_MS, default 90 s) to bound
 *   memory usage from rapidly recycled session IDs.
 * • No external dependency beyond lru-cache (already a transitive dep of
 *   @apollo/server).
 *
 * The cache is exposed both as a reusable `SessionL1Cache` class (so tests
 * and multi-node simulations can instantiate independent caches) and as a
 * module-level singleton via the `l1*` helper functions.
 */

import { LRUCache } from "lru-cache";

export interface L1CacheEntry {
  userId: string;
  expiresAt: number; // Unix-ms absolute expiry of the *session* (not the cache entry)
  valid: boolean; // false = revocation tombstone
}

export interface L1CacheStats {
  size: number;
  maxSize: number;
  /** Lookups answered from memory. */
  hits: number;
  /** Lookups that fell through to Redis / the database. */
  misses: number;
  /** Hits that answered "revoked" from a tombstone. */
  tombstoneHits: number;
  /** Entries dropped because the LRU ceiling was reached. */
  evictions: number;
}

export interface SessionL1CacheOptions {
  maxSize?: number;
  tombstoneTtlMs?: number;
  /** Cap (ms) applied to a valid entry's TTL so heartbeats can refresh it. */
  maxEntryTtlMs?: number;
}

const DEFAULT_MAX_SIZE = Number(process.env.SESSION_L1_MAX_SIZE ?? 10_000);
const DEFAULT_TOMBSTONE_TTL_MS = Number(
  process.env.SESSION_L1_TOMBSTONE_TTL_MS ?? 90_000,
);
const DEFAULT_MAX_ENTRY_TTL_MS = 5 * 60 * 1000;

export class SessionL1Cache {
  private readonly maxEntryTtlMs: number;
  private readonly tombstoneTtlMs: number;
  private readonly cache: LRUCache<string, L1CacheEntry>;
  private hits = 0;
  private misses = 0;
  private tombstoneHits = 0;
  private evictions = 0;

  constructor(options: SessionL1CacheOptions = {}) {
    const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE;
    this.tombstoneTtlMs = options.tombstoneTtlMs ?? DEFAULT_TOMBSTONE_TTL_MS;
    this.maxEntryTtlMs = options.maxEntryTtlMs ?? DEFAULT_MAX_ENTRY_TTL_MS;

    this.cache = new LRUCache<string, L1CacheEntry>({
      max: Math.max(1, maxSize),
      ttl: 1,
      ttlAutopurge: false,
      allowStale: false,
      // Count capacity pressure so operators can size SESSION_L1_MAX_SIZE.
      dispose: (_value, _key, reason) => {
        if (reason === "evict") this.evictions += 1;
      },
    });
  }

  get maxSize(): number {
    return this.cache.max;
  }

  get size(): number {
    return this.cache.size;
  }

  get(sessionId: string): L1CacheEntry | undefined {
    return this.l1Get(sessionId);
  }

  l1Get(sessionId: string): L1CacheEntry | undefined {
    const entry = this.cache.get(sessionId);
    if (!entry) {
      this.misses += 1;
      return undefined;
    }
    if (entry.valid && entry.expiresAt <= Date.now()) {
      this.cache.delete(sessionId);
      this.misses += 1;
      return undefined;
    }
    this.hits += 1;
    if (!entry.valid) this.tombstoneHits += 1;
    return entry;
  }

  set(sessionId: string, userId: string, sessionExpiresAt: Date): void {
    this.l1Set(sessionId, userId, sessionExpiresAt);
  }

  l1Set(sessionId: string, userId: string, sessionExpiresAt: Date): void {
    const expiresAt = sessionExpiresAt.getTime();
    const remainingMs = expiresAt - Date.now();
    if (remainingMs <= 0) return;

    const ttl = Math.min(remainingMs, this.maxEntryTtlMs);
    this.cache.set(sessionId, { userId, expiresAt, valid: true }, { ttl });
  }

  revoke(sessionId: string): void {
    this.l1Revoke(sessionId);
  }

  l1Revoke(sessionId: string): void {
    this.cache.set(
      sessionId,
      { userId: "", expiresAt: 0, valid: false },
      { ttl: this.tombstoneTtlMs },
    );
  }

  delete(sessionId: string): void {
    this.l1Delete(sessionId);
  }

  l1Delete(sessionId: string): void {
    this.cache.delete(sessionId);
  }

  clear(): void {
    this.l1Clear();
  }

  l1Clear(): void {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
    this.tombstoneHits = 0;
    this.evictions = 0;
  }

  stats(): L1CacheStats {
    return {
      size: this.cache.size,
      maxSize: this.cache.max,
      hits: this.hits,
      misses: this.misses,
      tombstoneHits: this.tombstoneHits,
      evictions: this.evictions,
    };
  }
}

// ─── Module-level singleton (backward compatible) ────────────────────────────

const defaultCache = new SessionL1Cache();

export function l1Get(sessionId: string): L1CacheEntry | undefined {
  return defaultCache.l1Get(sessionId);
}

export function l1Set(
  sessionId: string,
  userId: string,
  sessionExpiresAt: Date,
): void {
  defaultCache.l1Set(sessionId, userId, sessionExpiresAt);
}

export function l1Revoke(sessionId: string): void {
  defaultCache.l1Revoke(sessionId);
}

export function l1Delete(sessionId: string): void {
  defaultCache.l1Delete(sessionId);
}

export function l1Clear(): void {
  defaultCache.l1Clear();
}

export function l1Size(): number {
  return defaultCache.size;
}

export function getL1CacheStats(): L1CacheStats {
  return defaultCache.stats();
}

/** The process-wide L1 cache instance (used by the session registry). */
export function getDefaultL1Cache(): SessionL1Cache {
  return defaultCache;
}

export function resetL1Cache(): void {
  defaultCache.l1Clear();
}
