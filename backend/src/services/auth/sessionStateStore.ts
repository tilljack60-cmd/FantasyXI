/**
 * Issue #439 — L2 session state store.
 *
 * The L1 cache is node-local, so a request can land on a pod that never saw the
 * `SESSION_CREATED` stream event (a pod restarted, or the event has aged out of
 * the node's 5-minute L1 TTL).  Keeping the minimal session record in Redis
 * lets any node validate — and repopulate its L1 — without touching the primary
 * database.
 *
 * Layout
 * ──────
 *   key   session:state:<sessionId>
 *   value {"sessionId","userId","expiresAt"}
 *   ttl   remaining session lifetime (refreshed by heartbeats, so the record
 *         slides with activity and vanishes at the same time the session does)
 *
 * Revocation deletes the key synchronously on the revoking node before the
 * `SESSION_REVOKED` event is published, so a peer either hydrates before the
 * delete or falls through to the revocation check afterwards.  Both outcomes is
 * a denial; there is no window in which a revoked session hydrates from L2.
 *
 * All operations are best effort: when Redis is unavailable the store degrades
 * to a bounded in-process map (useful for single-node development) and every
 * method resolves instead of throwing.
 */

import { getRedisClient } from "../../config/redis.js";

export interface SessionState {
  sessionId: string;
  userId: string;
  /** Unix-ms absolute session expiry. */
  expiresAt: number;
}

/** The subset of the Redis client the store needs. */
export interface SessionStateRedis {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
}

export const SESSION_STATE_PREFIX = "session:state:";
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Cap on the in-process fallback so a Redis outage cannot cause an OOM. */
const FALLBACK_MAX_ENTRIES = 10_000;

function stateKey(sessionId: string): string {
  return `${SESSION_STATE_PREFIX}${sessionId}`;
}

export class SessionStateStore {
  /** Bounded fallback used when Redis is unavailable. */
  private readonly fallback = new Map<string, SessionState>();

  /**
   * @param redis Explicit client (tests / alternate topology).  When omitted the
   *              shared client from config/redis is resolved on every call.
   */
  constructor(private readonly redis?: SessionStateRedis | null) {}

  private client(): SessionStateRedis | null {
    if (this.redis !== undefined) return this.redis;
    return (getRedisClient() as unknown as SessionStateRedis | null) ?? null;
  }

  /** Persists (or refreshes) a session record. */
  async save(state: SessionState): Promise<void> {
    const remaining = state.expiresAt - Date.now();
    if (remaining <= 0) {
      await this.delete(state.sessionId);
      return;
    }

    const ttl = Math.min(remaining, MAX_TTL_MS);
    const client = this.client();

    if (!client) {
      this.fallbackSet(state);
      return;
    }

    try {
      await client.set(stateKey(state.sessionId), JSON.stringify(state), "PX", ttl);
      this.fallback.delete(state.sessionId);
    } catch {
      this.fallbackSet(state);
    }
  }

  /** Reads a session record; `null` when unknown, expired or unreadable. */
  async load(sessionId: string): Promise<SessionState | null> {
    const client = this.client();

    if (client) {
      try {
        const raw = await client.get(stateKey(sessionId));
        if (raw) {
          const parsed = JSON.parse(raw) as SessionState;
          if (parsed.expiresAt > Date.now()) return parsed;
          await this.delete(sessionId);
          return null;
        }
      } catch {
        /* fall through to the in-process copy */
      }
    }

    const local = this.fallback.get(sessionId);
    if (!local) return null;
    if (local.expiresAt <= Date.now()) {
      this.fallback.delete(sessionId);
      return null;
    }
    return local;
  }

  /**
   * Sliding expiry: refreshes the stored TTL (and expiry) after activity,
   * without any database write.
   */
  async extend(sessionId: string, expiresAt: number): Promise<void> {
    const existing = await this.load(sessionId);
    if (!existing) return;
    await this.save({ ...existing, expiresAt });
  }

  /** Removes a session record (called synchronously on revocation). */
  async delete(sessionId: string): Promise<void> {
    this.fallback.delete(sessionId);

    const client = this.client();
    if (!client) return;
    try {
      await client.del(stateKey(sessionId));
    } catch {
      /* best effort */
    }
  }

  /** Number of records held by the in-process fallback (never the Redis size). */
  get fallbackSize(): number {
    return this.fallback.size;
  }

  private fallbackSet(state: SessionState): void {
    if (!this.fallback.has(state.sessionId) && this.fallback.size >= FALLBACK_MAX_ENTRIES) {
      const oldest = this.fallback.keys().next().value;
      if (oldest !== undefined) this.fallback.delete(oldest);
    }
    this.fallback.set(state.sessionId, state);
  }
}

let store = new SessionStateStore();

/** The process-wide L2 session store. */
export function getSessionStateStore(): SessionStateStore {
  return store;
}

/** Replaces the process-wide store (tests, or an alternate Redis topology). */
export function setSessionStateStore(next: SessionStateStore | null): SessionStateStore {
  store = next ?? new SessionStateStore();
  return store;
}
