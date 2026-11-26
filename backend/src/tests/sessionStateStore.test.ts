/**
 * Issue #439 — L2 Redis session state store.
 *
 * Covers the record any node can hydrate its L1 from, sliding-expiry refreshes,
 * revocation deletes, and the Redis-outage fallback.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  SessionStateStore,
  SESSION_STATE_PREFIX,
  setSessionStateStore,
} from "../services/auth/sessionStateStore.js";
import { SessionL1Cache, l1Clear, l1Get } from "../services/auth/sessionL1Cache.js";
import { SessionRegistryService } from "../services/auth/sessionRegistryService.js";

/** Minimal Redis key/value stand-in with millisecond PX expiry. */
class FakeKvRedis {
  public readonly store = new Map<string, { value: string; expiresAt: number }>();
  public sets = 0;
  public gets = 0;
  public deletes = 0;

  async get(key: string): Promise<string | null> {
    this.gets += 1;
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ...args: unknown[]): Promise<unknown> {
    this.sets += 1;
    const pxAt = args.indexOf("PX");
    const ttl = pxAt >= 0 ? Number(args[pxAt + 1]) : 60_000;
    this.store.set(key, { value, expiresAt: Date.now() + ttl });
    return "OK";
  }

  async del(...keys: string[]): Promise<number> {
    this.deletes += 1;
    let removed = 0;
    for (const key of keys) if (this.store.delete(key)) removed += 1;
    return removed;
  }
}

const session = (overrides: Partial<{ sessionId: string; userId: string; expiresAt: number }> = {}) => ({
  sessionId: "sid-1",
  userId: "user-1",
  expiresAt: Date.now() + 60_000,
  ...overrides,
});

describe("Issue #439 — L2 session state store", () => {
  let redis: FakeKvRedis;

  beforeEach(() => {
    redis = new FakeKvRedis();
  });

  it("saves a session under a prefixed key with the session's remaining TTL", async () => {
    const store = new SessionStateStore(redis);
    const state = session();
    await store.save(state);

    const key = `${SESSION_STATE_PREFIX}${state.sessionId}`;
    const entry = redis.store.get(key);
    assert.ok(entry, "record must be written");
    assert.equal(JSON.parse(entry.value).userId, "user-1");
    const ttl = entry.expiresAt - Date.now();
    assert.ok(ttl > 50_000 && ttl <= 60_000, `TTL ${ttl} ms should track the session expiry`);
  });

  it("loads a record written by another node, so its L1 can be repopulated", async () => {
    // Node A writes the record; node B has an empty L1 cache.
    const nodeA = new SessionStateStore(redis);
    const nodeB = new SessionStateStore(redis);
    const state = session({ sessionId: "sid-cross-node" });
    await nodeA.save(state);

    const loaded = await nodeB.load(state.sessionId);
    assert.deepEqual(loaded, state);

    const l1 = new SessionL1Cache({ maxSize: 50 });
    assert.equal(l1.l1Get(state.sessionId), undefined);
    l1.l1Set(loaded!.sessionId, loaded!.userId, new Date(loaded!.expiresAt));
    assert.equal(l1.l1Get(state.sessionId)?.valid, true);
  });

  it("does not return expired or revoked records", async () => {
    const store = new SessionStateStore(redis);
    await store.save(session({ sessionId: "sid-expired", expiresAt: Date.now() - 1 }));
    assert.equal(await store.load("sid-expired"), null);

    await store.save(session({ sessionId: "sid-revoked" }));
    assert.ok(await store.load("sid-revoked"));
    await store.delete("sid-revoked");
    assert.equal(await store.load("sid-revoked"), null);
    assert.equal(redis.store.has(`${SESSION_STATE_PREFIX}sid-revoked`), false);
  });

  it("refreshes the TTL on a heartbeat without a database write", async () => {
    const store = new SessionStateStore(redis);
    const state = session({ sessionId: "sid-slide", expiresAt: Date.now() + 60_000 });
    await store.save(state);

    const extended = Date.now() + 24 * 3600 * 1000;
    await store.extend(state.sessionId, extended);

    const key = `${SESSION_STATE_PREFIX}${state.sessionId}`;
    const entry = redis.store.get(key)!;
    assert.equal(JSON.parse(entry.value).expiresAt, extended);
    assert.ok(entry.expiresAt - Date.now() > 23 * 3600 * 1000, "TTL must slide with the session");
  });

  it("falls back to a bounded in-process map when Redis fails", async () => {
    const broken = {
      async get(): Promise<string | null> {
        throw new Error("ECONNREFUSED");
      },
      async set(): Promise<unknown> {
        throw new Error("ECONNREFUSED");
      },
      async del(): Promise<number> {
        throw new Error("ECONNREFUSED");
      },
    };
    const store = new SessionStateStore(broken);
    await store.save(session({ sessionId: "sid-fallback" }));
    assert.equal((await store.load("sid-fallback"))?.userId, "user-1");

    await store.delete("sid-fallback");
    assert.equal(await store.load("sid-fallback"), null);
  });
});

describe("Issue #439 — registry hydration from L2", () => {
  let redis: FakeKvRedis;
  let registry: SessionRegistryService;

  beforeEach(() => {
    redis = new FakeKvRedis();
    setSessionStateStore(new SessionStateStore(redis));
    registry = SessionRegistryService.getInstance();
    registry.clearAll();
    l1Clear();
  });

  afterEach(() => {
    setSessionStateStore(null);
    registry.clearAll();
  });

  it("validates a session whose L1 entry aged out by reading the L2 record once", async () => {
    const created = await registry.createSession("user-l2", { ip: "10.0.0.1" });
    await new Promise((resolve) => setImmediate(resolve)); // let the async save land
    assert.ok(redis.store.has(`${SESSION_STATE_PREFIX}${created.id}`));

    // Simulate the 5-minute L1 TTL expiring on this node.
    l1Clear();
    assert.equal(l1Get(created.id), undefined);

    const getsBefore = redis.gets;
    assert.equal(await registry.isSessionValid(created.id, "user-l2"), true);
    assert.equal(redis.gets - getsBefore, 1, "exactly one Redis GET, no DB round trip");
    assert.equal(l1Get(created.id)?.valid, true, "L1 must be repopulated for the next hit");

    const latency = performance.now();
    assert.equal(await registry.isSessionValid(created.id, "user-l2"), true);
    assert.ok(performance.now() - latency < 5, "subsequent validations must be served from L1");
  });

  it("rejects a stored record presented for the wrong user", async () => {
    const created = await registry.createSession("user-owner", { ip: "10.0.0.2" });
    await new Promise((resolve) => setImmediate(resolve));
    l1Clear();

    assert.equal(await registry.isSessionValid(created.id, "user-attacker"), false);
    assert.equal(l1Get(created.id)?.valid, false, "the mismatch must be tombstoned");
  });

  it("revocation deletes the L2 record so no node can hydrate it afterwards", async () => {
    const created = await registry.createSession("user-revoke-l2", { ip: "10.0.0.3" });
    await new Promise((resolve) => setImmediate(resolve));
    const key = `${SESSION_STATE_PREFIX}${created.id}`;
    assert.ok(redis.store.has(key));

    await registry.revokeSession(created.id, "logout");

    assert.equal(redis.store.has(key), false, "L2 record must be gone");
    l1Clear();
    assert.equal(await registry.isSessionValid(created.id, "user-revoke-l2"), false);
  });

  it("purges expired session records so the registry cannot grow without bound", async () => {
    for (let i = 0; i < 20; i++) {
      await registry.createSession(`bulk-user-${i % 5}`, { ip: "10.0.0.4" }, 1);
    }
    assert.equal((registry as any).sessions.size, 20);

    const removed = registry.purgeExpired(new Date(Date.now() + 2_000));
    assert.equal(removed, 20);
    assert.equal((registry as any).sessions.size, 0);
    assert.deepEqual(await registry.listUserSessions("bulk-user-0"), []);
  });
});
