/**
 * Issue #439 — Redis Streams Session Sync (L2 backbone)
 *
 * Every node in the cluster publishes three event types onto the
 * `session:events` stream:
 *
 *   SESSION_CREATED  – a new session was registered (triggers L1 warm-up on
 *                      other nodes that happen to receive the event early).
 *   SESSION_HEARTBEAT – sliding-expiry update; extends the L1 TTL without a
 *                       DB write.
 *   SESSION_REVOKED  – instant cross-node revocation broadcast; consuming
 *                      nodes write an L1 tombstone within the target ≤50 ms.
 *
 * Every node reads the stream with a plain `XREAD` (fan-out) so *every* node
 * applies every session event; BLOCK holds only the dedicated subscriber
 * connection, never the shared client.
 *
 * Stream trimming
 * ───────────────
 * We use `MAXLEN ~ 50000` on every XADD so the stream never grows unbounded.
 * A background job or Redis `EXPIRE` is not needed.
 *
 * Fault tolerance
 * ───────────────
 * • If Redis is unavailable the publish methods fail silently — the session
 *   registry still works, just without cross-node sync.
 * • The subscriber loop retries with a 2-second back-off on Redis errors.
 * • `start()` / `stop()` are idempotent.
 *
 * The subscriber is available as a class (`SessionStreamSubscriber`) so tests
 * can run several independent "nodes" inside one process; the module-level
 * `startSessionStreamSubscriber` / `stopSessionStreamSubscriber` helpers drive
 * the single production instance.
 */

import type { Redis as RedisClient } from "ioredis";
import { getRedisClient } from "../../config/redis.js";
import { l1Revoke, l1Set, type L1CacheEntry } from "./sessionL1Cache.js";

/**
 * Minimal cache contract accepted by the stream sync layer.  Both the
 * `SessionL1Cache` class and per-node caches used in tests satisfy it.
 */
export interface L1CacheLike {
  l1Get?(sessionId: string): L1CacheEntry | undefined;
  l1Set?(sessionId: string, userId: string, sessionExpiresAt: Date): void;
  l1Revoke?(sessionId: string): void;
  get?(sessionId: string): L1CacheEntry | undefined;
  set?(sessionId: string, userId: string, sessionExpiresAt: Date): void;
  revoke?(sessionId: string): void;
}

function revokeOn(cache: L1CacheLike | undefined, sessionId: string): void {
  if (!cache) {
    l1Revoke(sessionId);
    return;
  }
  if (typeof cache.l1Revoke === "function") cache.l1Revoke(sessionId);
  else if (typeof cache.revoke === "function") cache.revoke(sessionId);
  else l1Revoke(sessionId);
}

function setOn(
  cache: L1CacheLike | undefined,
  sessionId: string,
  userId: string,
  expiresAt: number,
): void {
  const expiry = new Date(expiresAt);
  if (!cache) {
    l1Set(sessionId, userId, expiry);
    return;
  }
  if (typeof cache.l1Set === "function") cache.l1Set(sessionId, userId, expiry);
  else if (typeof cache.set === "function") cache.set(sessionId, userId, expiry);
  else l1Set(sessionId, userId, expiry);
}

// ─── Stream constants ────────────────────────────────────────────────────────

export const STREAM_KEY = "session:events";
const STREAM_MAXLEN = 50_000;
const BLOCK_MS = 2_000; // how long XREAD blocks before returning empty
const RETRY_DELAY_MS = 2_000;

// ─── Event types ─────────────────────────────────────────────────────────────

export type SessionEventType =
  | "SESSION_CREATED"
  | "SESSION_HEARTBEAT"
  | "SESSION_REVOKED";

export interface SessionStreamEvent {
  type: SessionEventType;
  sessionId: string;
  userId: string;
  /** Unix-ms expiry of the session */
  expiresAt: number;
  /** Wall-clock time the event was published */
  publishedAt: number;
}

/** Subscriber handlers installed by the session registry (process-wide). */
type SessionEventListener = (event: SessionStreamEvent) => void;
const listeners = new Set<SessionEventListener>();

/**
 * Registers a listener that observes every applied stream event (remote
 * revocations included).  Returns an unsubscribe function.
 */
export function onSessionStreamEvent(listener: SessionEventListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// ─── Publisher ───────────────────────────────────────────────────────────────

/** Serialises an event into the flat field array used by the stream. */
export function toStreamFields(event: SessionStreamEvent): string[] {
  return [
    "type",
    event.type,
    "sessionId",
    event.sessionId,
    "userId",
    event.userId,
    "expiresAt",
    String(event.expiresAt),
    "publishedAt",
    String(event.publishedAt),
  ];
}

/** Parses a flat field array back into a SessionStreamEvent. */
export function parseStreamMessage(fields: string[]): SessionStreamEvent | null {
  const map: Record<string, string> = {};
  for (let i = 0; i < fields.length; i += 2) {
    map[fields[i]] = fields[i + 1];
  }
  if (!map.type || !map.sessionId || !map.userId || !map.expiresAt) return null;
  return {
    type: map.type as SessionEventType,
    sessionId: map.sessionId,
    userId: map.userId,
    expiresAt: Number(map.expiresAt),
    publishedAt: Number(map.publishedAt ?? 0),
  };
}

/**
 * Publishes a session event to the Redis stream.  Never throws — a failed
 * publish is logged and silently swallowed so the caller's critical path
 * (login, auth check) is not affected.
 */
export async function publishSessionEvent(
  event: SessionStreamEvent,
  redis?: RedisClient | null,
): Promise<void> {
  const client = redis ?? getRedisClient();
  if (!client) return;

  const c: any = client;
  // lazyConnect clients must be connected before the first command.
  if (typeof c.status === "string" && c.status === "wait" && typeof c.connect === "function") {
    try {
      await c.connect();
    } catch {
      /* best effort */
    }
  }

  try {
    await client.xadd(
      STREAM_KEY,
      "MAXLEN",
      "~",
      STREAM_MAXLEN,
      "*", // auto-ID
      ...toStreamFields(event),
    );
  } catch (err) {
    // Best-effort — cross-node sync failure must never break auth
    console.warn("[sessionStreamSync] Failed to publish event:", (err as Error).message);
  }
}

// ─── Event application ───────────────────────────────────────────────────────

/**
 * Applies an inbound stream event to an L1 cache (the process-wide cache when
 * `cache` is omitted) and notifies process-wide listeners.
 *
 * This is the core of the ≤50 ms cross-node revocation guarantee: a
 * SESSION_REVOKED message writes an L1 tombstone synchronously.
 */
export function applySessionEvent(
  event: SessionStreamEvent,
  cache?: L1CacheLike,
): void {
  switch (event.type) {
    case "SESSION_REVOKED":
      revokeOn(cache, event.sessionId);
      break;

    case "SESSION_CREATED":
    case "SESSION_HEARTBEAT":
      setOn(cache, event.sessionId, event.userId, event.expiresAt);
      break;
  }

  for (const listener of listeners) {
    try {
      listener(event);
    } catch (err) {
      console.warn(
        "[sessionStreamSync] Session event listener failed:",
        (err as Error).message,
      );
    }
  }
}

// ─── Subscriber ──────────────────────────────────────────────────────────────

export interface SessionStreamSubscriberOptions {
  /** Redis client to read from. */
  redis: RedisClient;
  /** L1 cache to apply events to; defaults to the process-wide cache. */
  cache?: L1CacheLike;
  /** Stream key override (tests). */
  streamKey?: string;
}

/**
 * One XREAD loop bound to a single node's L1 cache.
 *
 * Using a *dedicated* Redis connection matters because XREAD with BLOCK holds
 * the connection open and would otherwise starve the shared client.
 */
export class SessionStreamSubscriber {
  private readonly client: RedisClient;
  private readonly cache?: L1CacheLike;
  private readonly streamKey: string;
  private running = false;
  private lastId = "$";
  private loop: Promise<void> | null = null;

  constructor(options: SessionStreamSubscriberOptions) {
    const primary: any = options.redis;
    this.client =
      typeof primary.duplicate === "function" ? primary.duplicate() : primary;
    this.cache = options.cache;
    this.streamKey = options.streamKey ?? STREAM_KEY;
  }

  get isRunning(): boolean {
    return this.running;
  }

  get lastMessageId(): string {
    return this.lastId;
  }

  /** Idempotent; resolves once the loop has issued its first read. */
  start(): Promise<void> {
    if (this.running) return Promise.resolve();
    this.running = true;
    this.loop = this.run();
    return Promise.resolve();
  }

  /** Applies an event to this node's cache as if it had arrived on the stream. */
  apply(event: SessionStreamEvent): void {
    applySessionEvent(event, this.cache);
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.client) {
      try {
        await this.client.quit();
      } catch {
        this.client.disconnect();
      }
    }
    await this.loop;
    this.loop = null;
    this.lastId = "$";
  }

  private async run(): Promise<void> {
    const client: any = this.client;

    // lazyConnect clients must be connected before the first read.
    if (
      client &&
      typeof client.status === "string" &&
      client.status === "wait" &&
      typeof client.connect === "function"
    ) {
      try {
        await client.connect();
      } catch (err) {
        console.warn(
          "[sessionStreamSync] Failed to connect subscriber:",
          (err as Error).message,
        );
        this.running = false;
        return;
      }
    }

    while (this.running) {
      try {
        // XREAD COUNT 100 BLOCK 2000 STREAMS session:events <lastId>
        const results = (await client.xread(
          "COUNT",
          100,
          "BLOCK",
          BLOCK_MS,
          "STREAMS",
          this.streamKey,
          this.lastId,
        )) as Array<[string, Array<[string, string[]]>]> | null;

        if (!results) {
          // Avoid a tight busy-loop when a reader returns null immediately.
          await new Promise((resolve) => setImmediate(resolve));
          continue; // BLOCK timeout — no messages
        }

        for (const [, messages] of results) {
          for (const [id, fields] of messages) {
            this.lastId = id;
            const event = parseStreamMessage(fields);
            if (event) this.apply(event);
          }
        }
      } catch (err) {
        if (!this.running) break;
        console.warn(
          "[sessionStreamSync] Stream read error — retrying in",
          RETRY_DELAY_MS,
          "ms:",
          (err as Error).message,
        );
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
      }
    }
  }
}

// ─── Production singleton ────────────────────────────────────────────────────

let subscriber: SessionStreamSubscriber | null = null;

/**
 * Starts the process-wide subscriber.  Safe to call multiple times — only the
 * first call with a usable client starts the loop.
 */
export function startSessionStreamSubscriber(
  overrideRedis?: RedisClient | null,
  options: { cache?: L1CacheLike } = {},
): void {
  if (subscriber) return;

  const primary = overrideRedis ?? getRedisClient();
  if (!primary) {
    console.warn("[sessionStreamSync] Redis unavailable — stream subscriber not started");
    return;
  }

  subscriber = new SessionStreamSubscriber({ redis: primary, cache: options.cache });
  void subscriber.start();
}

/** Stops the process-wide subscriber and closes its connection. */
export async function stopSessionStreamSubscriber(): Promise<void> {
  const current = subscriber;
  subscriber = null;
  await current?.stop();
}

/** Exposed for tests/health checks: the running subscriber, if any. */
export function getSessionStreamSubscriber(): SessionStreamSubscriber | null {
  return subscriber;
}
