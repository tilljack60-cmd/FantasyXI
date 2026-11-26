/**
 * Issue #439 — session cache benchmarks.
 *
 * Run with: npm run bench:session
 *
 * Verifies the two acceptance-criteria budgets that can be measured locally:
 *   • L1 cache-hit validation latency  < 1 ms (p99)
 *   • cross-node revocation propagation < 50 ms (worst case of N nodes)
 *
 * The cluster is an in-process simulation: several `SessionL1Cache` instances
 * fed by `SessionStreamSubscriber`s reading from an in-memory stream, i.e. the
 * same code path a real node runs, minus the network hop.
 */

import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { SessionL1Cache } from "../services/auth/sessionL1Cache.js";
import {
  SessionStreamSubscriber,
  publishSessionEvent,
  type SessionStreamEvent,
} from "../services/auth/sessionStreamSync.js";

const HIT_BUDGET_MS = 1;
const REVOCATION_BUDGET_MS = 50;

class FakeStreamRedis {
  private readonly messages: Array<[string, string[]]> = [];
  private sequence = 0;
  private waiters = new Set<() => void>();

  duplicate(): FakeStreamRedis {
    return this;
  }

  async xadd(_key: string, ...args: unknown[]): Promise<string> {
    const star = args.indexOf("*");
    const id = `${++this.sequence}-0`;
    this.messages.push([id, args.slice(star + 1).map(String)]);
    for (const wake of this.waiters) wake();
    this.waiters.clear();
    return id;
  }

  async xread(...args: unknown[]): Promise<Array<[string, Array<[string, string[]]>]>> | null {
    const streamsAt = args.indexOf("STREAMS");
    const key = String(args[streamsAt + 1]);
    const lastId = String(args[streamsAt + 2]);
    const lastSeq = lastId === "$" ? this.sequence : Number(lastId.split("-")[0]);

    const pending = () => this.messages.filter(([id]) => Number(id.split("-")[0]) > lastSeq);
    if (pending().length === 0) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 1);
        this.waiters.add(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }

    const rows = pending().slice(0, 100);
    return rows.length ? [[key, rows]] : null;
  }

  async quit(): Promise<void> {}

  disconnect(): void {}
}

function percentile(sorted: number[], p: number): number {
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index];
}

async function benchmarkCacheHits(): Promise<void> {
  const cache = new SessionL1Cache({ maxSize: 10_000 });
  const expiresAt = new Date(Date.now() + 3_600_000);
  const sessionIds = Array.from({ length: 10_000 }, (_, i) => `sid-${i}`);
  for (const id of sessionIds) cache.l1Set(id, "user-1", expiresAt);

  const samples: number[] = [];
  const iterations = 200_000;
  for (let i = 0; i < iterations; i++) {
    const id = sessionIds[i % sessionIds.length];
    const startedAt = performance.now();
    const entry = cache.l1Get(id);
    const elapsed = performance.now() - startedAt;
    assert.equal(entry?.valid, true);
    samples.push(elapsed);
  }

  samples.sort((a, b) => a - b);
  const p50 = percentile(samples, 50);
  const p99 = percentile(samples, 99);
  const max = samples[samples.length - 1];
  const stats = cache.stats();

  console.log(
    `L1 cache hit: ${iterations.toLocaleString()} lookups, ` +
      `p50 ${(p50 * 1_000).toFixed(2)} µs, p99 ${(p99 * 1_000).toFixed(2)} µs, ` +
      `max ${(max * 1_000).toFixed(2)} µs ` +
      `(hits ${stats.hits}, misses ${stats.misses}, size ${stats.size}/${stats.maxSize})`,
  );

  assert.ok(p99 < HIT_BUDGET_MS, `p99 cache-hit latency ${p99.toFixed(3)} ms exceeds ${HIT_BUDGET_MS} ms`);
}

async function benchmarkRevocationFanout(): Promise<void> {
  const redis = new FakeStreamRedis();
  const nodeCount = 10;
  const sessionsPerNode = 500;
  const expiresAt = Date.now() + 3_600_000;

  const nodes = Array.from({ length: nodeCount }, () => {
    const cache = new SessionL1Cache({ maxSize: 5_000 });
    const subscriber = new SessionStreamSubscriber({ redis: redis as any, cache });
    return { cache, subscriber };
  });

  for (const node of nodes) {
    for (let i = 0; i < sessionsPerNode; i++) {
      node.cache.l1Set(`bench-${i}`, "user-bench", new Date(expiresAt));
    }
  }
  for (const node of nodes) await node.subscriber.start();

  const revocations: SessionStreamEvent[] = Array.from({ length: sessionsPerNode }, (_, i) => ({
    type: "SESSION_REVOKED",
    sessionId: `bench-${i}`,
    userId: "user-bench",
    expiresAt,
    publishedAt: Date.now(),
  }));

  // Worst case: every revoked session reaches every node.
  const startedAt = performance.now();
  for (const event of revocations) {
    await publishSessionEvent(event, redis as any);
  }
  const publishedAt = performance.now();

  let allRevoked = false;
  const deadline = publishedAt + REVOCATION_BUDGET_MS * 10;
  while (performance.now() < deadline) {
    allRevoked = nodes.every((node) =>
      revocations.every((event) => node.cache.l1Get(event.sessionId)?.valid === false),
    );
    if (allRevoked) break;
    await new Promise((resolve) => setImmediate(resolve));
  }
  const propagatedAt = performance.now();

  await Promise.all(nodes.map((node) => node.subscriber.stop()));

  assert.equal(allRevoked, true, "every node must tombstone every revoked session");
  const publishMs = publishedAt - startedAt;
  const propagationMs = propagatedAt - publishedAt;

  console.log(
    `Revocation fan-out: ${sessionsPerNode} sessions × ${nodeCount} nodes ` +
      `(published in ${publishMs.toFixed(1)} ms, last node tombstoned ` +
      `${propagationMs.toFixed(1)} ms after the final XADD, ` +
      `budget ${REVOCATION_BUDGET_MS} ms)`,
  );

  assert.ok(
    propagationMs < REVOCATION_BUDGET_MS,
    `cross-node revocation took ${propagationMs.toFixed(1)} ms (target < ${REVOCATION_BUDGET_MS} ms)`,
  );
}

async function benchmarkHeartbeats(): Promise<void> {
  const cache = new SessionL1Cache({ maxSize: 10_000 });
  const sessionIds = Array.from({ length: 5_000 }, (_, i) => `hb-${i}`);
  const expiresAt = Date.now() + 3_600_000;

  const startedAt = performance.now();
  const revisions = 20;
  for (let round = 0; round < revisions; round++) {
    for (const id of sessionIds) cache.l1Set(id, "user-hb", new Date(expiresAt + round * 1_000));
  }
  const elapsed = performance.now() - startedAt;
  const operations = revisions * sessionIds.length;

  console.log(
    `Sliding expiry: ${operations.toLocaleString()} TTL refreshes in ` +
      `${elapsed.toFixed(1)} ms (${Math.round((operations * 1000) / elapsed).toLocaleString()} ops/sec, no DB writes)`,
  );
}

async function main(): Promise<void> {
  await benchmarkCacheHits();
  await benchmarkRevocationFanout();
  await benchmarkHeartbeats();
  console.log("Session cache benchmarks passed.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
