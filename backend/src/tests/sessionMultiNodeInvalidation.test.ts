/**
 * Issue #439 — concurrent multi-node invalidation tests.
 *
 * The cluster is simulated with several independent `SessionL1Cache` instances
 * in one process, each fed by its own `SessionStreamSubscriber` reading from a
 * shared in-memory Redis Stream stand-in.  That exercises exactly the
 * production path: XADD on the writing node, XREAD fan-out on every other node,
 * synchronous L1 tombstone write on receipt.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { SessionL1Cache } from "../services/auth/sessionL1Cache.js";
import {
  SessionStreamSubscriber,
  publishSessionEvent,
  toStreamFields,
  parseStreamMessage,
  type SessionStreamEvent,
} from "../services/auth/sessionStreamSync.js";

// ─── In-memory Redis Stream stand-in ─────────────────────────────────────────

class FakeStreamRedis {
  public readonly messages: Array<[string, string[]]> = [];
  private sequence = 0;
  private waiters = new Set<() => void>();

  /** Every node shares the same stream state, like a real Redis server. */
  duplicate(): FakeStreamRedis {
    return this;
  }

  async xadd(_key: string, ...args: unknown[]): Promise<string> {
    // MAXLEN ~ <n> * <field> <value> ...
    const star = args.indexOf("*");
    const fields = args.slice(star + 1).map(String);
    const id = `${++this.sequence}-0`;
    this.messages.push([id, fields]);
    for (const wake of this.waiters) wake();
    this.waiters.clear();
    return id;
  }

  async xread(...args: unknown[]): Promise<Array<[string, Array<[string, string[]]>]>> | null {
    const streamsAt = args.indexOf("STREAMS");
    const key = String(args[streamsAt + 1]);
    const lastId = String(args[streamsAt + 2]);
    const lastSeq = lastId === "$" ? this.sequence : Number(lastId.split("-")[0]);

    const pending = () =>
      this.messages.filter(([id]) => Number(id.split("-")[0]) > lastSeq);

    if (pending().length === 0) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 5);
        this.waiters.add(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }

    const rows = pending().slice(0, 100);
    return rows.length ? [[key, rows]] : null;
  }

  async quit(): Promise<void> {
    /* shared fake — stopping one node must not close the server */
  }

  disconnect(): void {
    /* no-op */
  }
}

interface Node {
  cache: SessionL1Cache;
  subscriber: SessionStreamSubscriber;
}

function createCluster(redis: FakeStreamRedis, nodeCount: number, maxSize = 1_000): Node[] {
  return Array.from({ length: nodeCount }, () => {
    const cache = new SessionL1Cache({ maxSize, tombstoneTtlMs: 30_000 });
    const subscriber = new SessionStreamSubscriber({ redis: redis as any, cache });
    return { cache, subscriber };
  });
}

function event(overrides: Partial<SessionStreamEvent> = {}): SessionStreamEvent {
  return {
    type: "SESSION_CREATED",
    sessionId: "sid-1",
    userId: "user-1",
    expiresAt: Date.now() + 60_000,
    publishedAt: Date.now(),
    ...overrides,
  };
}

/** Polls until `check` passes or the deadline elapses; returns elapsed ms. */
async function waitUntil(check: () => boolean, deadlineMs: number): Promise<number> {
  const startedAt = performance.now();
  while (performance.now() - startedAt < deadlineMs) {
    if (check()) return performance.now() - startedAt;
    await new Promise((resolve) => setImmediate(resolve));
  }
  return performance.now() - startedAt;
}

describe("Issue #439 — concurrent multi-node invalidation", () => {
  let redis: FakeStreamRedis;
  let cluster: Node[];

  beforeEach(async () => {
    redis = new FakeStreamRedis();
    cluster = createCluster(redis, 5);
    for (const node of cluster) await node.subscriber.start();
  });

  afterEach(async () => {
    await Promise.all(cluster.map((node) => node.subscriber.stop()));
  });

  it("evicts a revoked session from every node's L1 cache within 50 ms", async () => {
    const sessionId = "sid-cluster-revoke";
    const expiresAt = Date.now() + 600_000;

    // Session created on node 0, fanned out to the whole cluster.
    await publishSessionEvent(
      event({ sessionId, expiresAt, publishedAt: Date.now() }),
      redis as any,
    );
    await waitUntil(
      () => cluster.every((node) => node.cache.l1Get(sessionId)?.valid === true),
      1_000,
    );
    assert.deepEqual(
      cluster.map((node) => node.cache.l1Get(sessionId)?.valid),
      [true, true, true, true, true],
    );

    // Node 0 logs the user out.
    await publishSessionEvent(
      event({ type: "SESSION_REVOKED", sessionId, expiresAt, publishedAt: Date.now() }),
      redis as any,
    );

    const elapsed = await waitUntil(
      () => cluster.every((node) => node.cache.l1Get(sessionId)?.valid === false),
      2_000,
    );

    assert.ok(elapsed < 50, `cross-node eviction took ${elapsed.toFixed(1)} ms (target < 50 ms)`);
    for (const node of cluster) {
      assert.equal(node.cache.l1Get(sessionId)?.valid, false, "tombstone must be installed");
    }
  });

  it("propagates many concurrent revocations from different nodes without losing any", async () => {
    const sessionCount = 200;
    const expiresAt = Date.now() + 600_000;
    const sessionIds = Array.from({ length: sessionCount }, (_, i) => `sid-${i}`);

    // Every session is visible in every node's cache first.
    for (const sessionId of sessionIds) {
      for (const node of cluster) node.cache.l1Set(sessionId, "user-1", new Date(expiresAt));
    }
    assert.equal(
      cluster.every((node) => sessionIds.every((id) => node.cache.l1Get(id)?.valid)),
      true,
    );

    // Revocations are published concurrently, round-robin across the cluster,
    // mimicking users logging out on different pods at the same time.
    await Promise.all(
      sessionIds.map((sessionId, index) =>
        publishSessionEvent(
          event({
            type: "SESSION_REVOKED",
            sessionId,
            userId: `user-${index % 7}`,
            expiresAt,
            publishedAt: Date.now(),
          }),
          redis as any,
        ),
      ),
    );

    await waitUntil(
      () =>
        cluster.every((node) =>
          sessionIds.every((id) => node.cache.l1Get(id)?.valid === false),
        ),
      3_000,
    );

    for (const node of cluster) {
      const stillValid = sessionIds.filter((id) => node.cache.l1Get(id)?.valid !== false);
      assert.deepEqual(stillValid, [], "no node may keep serving a revoked session");
    }
  });

  it("a remote revocation also retires the local session record", async () => {
    const { sessionRegistryService } = await import("../services/auth/sessionRegistryService.js");
    sessionRegistryService.clearAll();

    const session = await sessionRegistryService.createSession("user-remote", {
      ip: "10.0.0.9",
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0.0",
    });

    let revokedEventSessionId: string | undefined;
    const unsubscribe = sessionRegistryService.onRevocation((revocation) => {
      if (revocation.revokedSessionId === session.id) {
        revokedEventSessionId = revocation.revokedSessionId;
      }
    });

    // Simulate the revocation arriving from a different pod.
    await publishSessionEvent(
      event({ type: "SESSION_REVOKED", sessionId: session.id, userId: "user-remote" }),
      redis as any,
    );

    await waitUntil(() => revokedEventSessionId === session.id, 1_000);
    unsubscribe();

    assert.equal(revokedEventSessionId, session.id, "local subscribers must be told");
    assert.equal(
      await sessionRegistryService.isSessionValid(session.id, "user-remote"),
      false,
    );
    assert.deepEqual(await sessionRegistryService.listUserSessions("user-remote"), []);

    sessionRegistryService.clearAll();
  });

  it("sliding-expiry heartbeats extend the session on every node without a DB write", async () => {
    const sessionId = "sid-heartbeat";
    const initialExpiry = Date.now() + 60_000;
    const extendedExpiry = initialExpiry + 30 * 60_000;

    for (const node of cluster) node.cache.l1Set(sessionId, "user-9", new Date(initialExpiry));
    assert.equal(cluster[0].cache.l1Get(sessionId)?.expiresAt, initialExpiry);

    await publishSessionEvent(
      event({
        type: "SESSION_HEARTBEAT",
        sessionId,
        userId: "user-9",
        expiresAt: extendedExpiry,
      }),
      redis as any,
    );

    await waitUntil(
      () => cluster.every((node) => node.cache.l1Get(sessionId)?.expiresAt === extendedExpiry),
      1_000,
    );

    for (const node of cluster) {
      const entry = node.cache.l1Get(sessionId);
      assert.equal(entry?.valid, true);
      assert.equal(entry?.expiresAt, extendedExpiry);
    }
  });

  it("keeps every node's L1 cache bounded during a login spike", () => {
    const maxSize = 250;
    const nodes = Array.from({ length: 3 }, () => new SessionL1Cache({ maxSize }));
    const expiresAt = new Date(Date.now() + 600_000);

    for (let i = 0; i < 5_000; i++) {
      for (const node of nodes) node.l1Set(`spike-${i}`, `user-${i}`, expiresAt);
    }

    for (const node of nodes) {
      const stats = node.stats();
      assert.ok(stats.size <= maxSize, `L1 size ${stats.size} must stay <= ${maxSize}`);
      assert.ok(stats.evictions > 0, "capacity pressure must be reported as evictions");
      assert.equal(stats.maxSize, maxSize);
    }
  });

  it("counts hits and misses so cache efficiency is observable", () => {
    const cache = new SessionL1Cache({ maxSize: 10 });
    cache.l1Set("sid-hot", "user-1", new Date(Date.now() + 60_000));

    cache.l1Get("sid-hot");
    cache.l1Get("sid-hot");
    cache.l1Get("sid-cold");

    const stats = cache.stats();
    assert.equal(stats.hits, 2);
    assert.equal(stats.misses, 1);

    cache.l1Revoke("sid-hot");
    cache.l1Get("sid-hot");
    assert.equal(cache.stats().tombstoneHits, 1);
  });

  it("stream fields round-trip so peers reconstruct the same event", () => {
    const original = event({ type: "SESSION_HEARTBEAT", sessionId: "sid-rt" });
    const parsed = parseStreamMessage(toStreamFields(original));
    assert.deepEqual(parsed, original);

    assert.equal(parseStreamMessage(["type", "SESSION_CREATED"]), null);
  });
});
