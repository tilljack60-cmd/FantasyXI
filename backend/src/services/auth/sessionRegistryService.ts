/**
 * Active Session Registry & Device Fingerprinting Service
 *
 * Implements:
 * 1. Device fingerprinting from request headers (OS, Browser, Device Type, IP).
 * 2. Active session registry backed by a two-tier cache (Issue #439):
 *    - L1: node-local LRU in-memory cache (sub-millisecond lookups).
 *    - L2: Redis Streams backbone for cross-node session creation,
 *          heartbeat, and revocation broadcast (≤50 ms eviction).
 * 3. Cross-tab and multi-device real-time invalidation dispatch.
 */

import crypto from "crypto";
import { EventEmitter } from "events";
import { sessionRevocationBloom } from "./sessionRevocationBloom.js";
import {
  l1Get,
  l1Set,
  l1Revoke,
  l1Clear,
  getL1CacheStats,
  type L1CacheStats,
} from "./sessionL1Cache.js";
import { onSessionStreamEvent, publishSessionEvent } from "./sessionStreamSync.js";
import { getSessionStateStore } from "./sessionStateStore.js";

/**
 * Upper bound on the authoritative per-node session records.  Sessions are
 * also kept in the L1 cache, which is bounded independently; this cap stops a
 * login spike from growing the registry maps without limit.
 */
const REGISTRY_MAX_SESSIONS = Number(
  process.env.SESSION_REGISTRY_MAX_SESSIONS ?? 50_000,
);

export interface DeviceInfo {
  browser: string;
  os: string;
  deviceType: "desktop" | "mobile" | "tablet" | "unknown";
  ip: string;
  userAgent: string;
  fingerprintHash: string;
}

export interface UserSession {
  id: string; // Session ID (UUID)
  userId: string;
  device: DeviceInfo;
  createdAt: Date;
  lastActiveAt: Date;
  expiresAt: Date;
  isRevoked: boolean;
  revokedAt?: Date;
  revocationReason?: string;
}

export interface SessionRevocationEvent {
  userId: string;
  revokedSessionId?: string;
  revokedAllExcept?: string;
  reason?: string;
  timestamp: Date;
}

export class SessionRegistryService {
  private static instance: SessionRegistryService;
  private sessions = new Map<string, UserSession>();
  private userSessionsIndex = new Map<string, Set<string>>(); // userId -> Set<sessionId>
  private revokedSessionIds = new Set<string>();
  private eventEmitter = new EventEmitter();
  private createsSincePurge = 0;
  private static readonly PURGE_INTERVAL = 1_000;

  constructor() {
    this.eventEmitter.setMaxListeners(500);

    // Issue #439: a revocation published by another node evicts our L1 entry
    // (handled by the stream layer) and must also retire our local record so
    // device lists and SSE subscribers stay consistent across the cluster.
    onSessionStreamEvent((event) => {
      if (event.type !== "SESSION_REVOKED") return;
      const session = this.sessions.get(event.sessionId);
      if (!session || session.isRevoked) return;
      session.isRevoked = true;
      session.revokedAt = new Date(event.publishedAt || Date.now());
      session.revocationReason = "Revoked on another node";
      this.revokedSessionIds.add(event.sessionId);
      this.dispatchRevocationEvent({
        userId: session.userId,
        revokedSessionId: event.sessionId,
        reason: session.revocationReason,
        timestamp: session.revokedAt,
      });
    });
  }

  /**
   * Durable revocation record (Redis Bloom bit + DB row).  Best effort: an
   * outage must never delay or prevent the in-memory tombstone, the L2 delete
   * or the cross-node broadcast — the stream event is what makes revocation
   * immediate, the Bloom filter is the backstop for nodes that missed it.
   */
  private async recordDurableRevocation(
    sessionId: string,
    userId: string | null,
    reason: string,
    expiresAt: Date,
  ): Promise<void> {
    try {
      await sessionRevocationBloom.add(sessionId, userId, reason, expiresAt);
    } catch (err) {
      console.warn(
        "[sessionRegistry] Could not persist revocation record:",
        (err as Error).message,
      );
    }
  }

  /**
   * Bounds the registry by evicting the least-recently-active sessions once
   * the configured ceiling is exceeded, and drops expired records eagerly.
   */
  private evictIfNeeded(): void {
    if (this.sessions.size <= REGISTRY_MAX_SESSIONS) return;

    const overflow = this.sessions.size - REGISTRY_MAX_SESSIONS;
    const oldest = [...this.sessions.values()]
      .sort((a, b) => a.lastActiveAt.getTime() - b.lastActiveAt.getTime())
      .slice(0, overflow);

    for (const session of oldest) {
      this.sessions.delete(session.id);
      this.userSessionsIndex.get(session.userId)?.delete(session.id);
    }
  }

  /** Removes expired, non-revoked session records (memory hygiene). */
  public purgeExpired(now: Date = new Date()): number {
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) {
        this.sessions.delete(id);
        this.userSessionsIndex.get(session.userId)?.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  /** L1 cache counters for the health/metrics endpoints. */
  public getCacheStats(): L1CacheStats {
    return getL1CacheStats();
  }

  public static getInstance(): SessionRegistryService {
    if (!SessionRegistryService.instance) {
      SessionRegistryService.instance = new SessionRegistryService();
    }
    return SessionRegistryService.instance;
  }

  /**
   * Parses DeviceInfo from IP and User-Agent headers.
   */
  public parseDeviceInfo(ip: string, userAgent: string = ""): DeviceInfo {
    const cleanIp = ip.replace(/^.*:/, "") || "127.0.0.1";
    const ua = userAgent || "Unknown Client";

    let browser = "Other";
    if (ua.includes("Firefox/")) browser = "Firefox";
    else if (ua.includes("Edg/")) browser = "Edge";
    else if (ua.includes("Chrome/") && !ua.includes("Edg/")) browser = "Chrome";
    else if (ua.includes("Safari/") && !ua.includes("Chrome/")) browser = "Safari";

    let os = "Unknown";
    if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";
    else if (ua.includes("Android")) os = "Android";
    else if (ua.includes("Mac OS X") || ua.includes("Macintosh")) os = "macOS";
    else if (ua.includes("Windows NT")) os = "Windows";
    else if (ua.includes("Linux")) os = "Linux";

    let deviceType: DeviceInfo["deviceType"] = "desktop";
    if (ua.includes("Mobile") || ua.includes("Android") || ua.includes("iPhone")) {
      deviceType = "mobile";
    } else if (ua.includes("iPad") || ua.includes("Tablet")) {
      deviceType = "tablet";
    }

    const fingerprintHash = crypto
      .createHash("sha256")
      .update(`${cleanIp}::${ua}`)
      .digest("hex");

    return {
      browser,
      os,
      deviceType,
      ip: cleanIp,
      userAgent: ua,
      fingerprintHash,
    };
  }

  /**
   * Registers a new session upon login or refresh.
   * Writes to L1 and publishes a SESSION_CREATED event to Redis Streams (L2).
   */
  public async createSession(
    userId: string,
    reqContext: { ip: string; userAgent?: string | null },
    ttlSeconds: number = 7 * 24 * 3600 // 7 days
  ): Promise<UserSession> {
    const sessionId = crypto.randomUUID();
    const device = this.parseDeviceInfo(reqContext.ip, reqContext.userAgent || "");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    const session: UserSession = {
      id: sessionId,
      userId,
      device,
      createdAt: now,
      lastActiveAt: now,
      expiresAt,
      isRevoked: false,
    };

    this.sessions.set(sessionId, session);

    if (!this.userSessionsIndex.has(userId)) {
      this.userSessionsIndex.set(userId, new Set());
    }
    this.userSessionsIndex.get(userId)!.add(sessionId);
    this.evictIfNeeded();

    // Amortised housekeeping: drop expired records every PURGE_INTERVAL logins
    // so long-lived nodes do not accumulate dead sessions between restarts.
    if (++this.createsSincePurge >= SessionRegistryService.PURGE_INTERVAL) {
      this.createsSincePurge = 0;
      this.purgeExpired(now);
    }

    // L1 warm-up: prime the local cache immediately
    l1Set(sessionId, userId, expiresAt);

    // L2: keep the record where any node can hydrate its L1 from it, then
    // broadcast so caches that are already warm update immediately.
    void getSessionStateStore().save({
      sessionId,
      userId,
      expiresAt: expiresAt.getTime(),
    });
    void publishSessionEvent({
      type: "SESSION_CREATED",
      sessionId,
      userId,
      expiresAt: expiresAt.getTime(),
      publishedAt: now.getTime(),
    });

    return session;
  }

  public async getSession(sessionId: string): Promise<UserSession | null> {
    return this.sessions.get(sessionId) || null;
  }

  /**
   * Lists all non-revoked active sessions for a user.
   */
  public async listUserSessions(userId: string): Promise<UserSession[]> {
    const sessionIds = this.userSessionsIndex.get(userId);
    if (!sessionIds) return [];

    const now = new Date();
    const result: UserSession[] = [];

    for (const id of sessionIds) {
      const session = this.sessions.get(id);
      if (session && !session.isRevoked && session.expiresAt > now) {
        result.push(session);
      }
    }

    // Sort newest first
    return result.reverse().sort((a, b) => b.lastActiveAt.getTime() - a.lastActiveAt.getTime());
  }

  /**
   * Checks whether a session ID is currently valid (not revoked and not expired).
   *
   * Fast path (Issue #439):
   *  1. Check L1 cache — answers immediately without Redis or DB I/O.
   *     a. Positive hit  → valid (also sends a heartbeat to L2).
   *     b. Tombstone hit → invalid (revoked/expired).
   *  2. L1 miss → hydrate from the L2 Redis session record (one GET, no DB
   *     write) and repopulate L1.
   *  3. Otherwise fall through to the revocation Bloom filter + DB, then
   *     populate L1 on success.
   */
  public async isSessionValid(sessionId: string, userId: string): Promise<boolean> {
    // ── L1 fast path ──────────────────────────────────────────────────────────
    const l1Entry = l1Get(sessionId);
    if (l1Entry !== undefined) {
      if (!l1Entry.valid || l1Entry.userId !== userId) return false;

      const now = new Date();
      const session = this.sessions.get(sessionId);

      // A local record revoked out-of-band (remote revocation, admin action)
      // must never be served from a stale positive L1 entry, even if the
      // tombstone was evicted by LRU pressure before the next heartbeat.
      if (session && (session.isRevoked || session.expiresAt <= now)) {
        l1Revoke(sessionId);
        return false;
      }

      // Sliding expiry heartbeat, at most once every 5 minutes so a hot
      // session cannot flood the stream: refresh the L1/L2 TTLs and let every
      // peer do the same, without touching the primary database.
      if (session && now.getTime() - session.lastActiveAt.getTime() > 300_000) {
        session.lastActiveAt = now;
        void getSessionStateStore().extend(sessionId, session.expiresAt.getTime());
        void publishSessionEvent({
          type: "SESSION_HEARTBEAT",
          sessionId,
          userId,
          expiresAt: session.expiresAt.getTime(),
          publishedAt: now.getTime(),
        });
      }
      return true;
    }

    // ── L2 / authoritative path ───────────────────────────────────────────────
    if (this.revokedSessionIds.has(sessionId)) {
      l1Revoke(sessionId);
      return false;
    }

    // Hydrate from the Redis-backed L2 record when this node never saw the
    // session (another pod issued it, or the L1 entry aged out).  A hit costs
    // one Redis GET instead of a primary-database round trip.
    const stored = await getSessionStateStore().load(sessionId);
    if (stored) {
      if (stored.userId !== userId || stored.expiresAt <= Date.now()) {
        l1Revoke(sessionId);
        return false;
      }
      l1Set(sessionId, stored.userId, new Date(stored.expiresAt));
      return true;
    }

    if (await sessionRevocationBloom.isRevoked(sessionId)) {
      this.revokedSessionIds.add(sessionId);
      l1Revoke(sessionId);
      return false;
    }

    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    if (session.userId !== userId || session.isRevoked) {
      l1Revoke(sessionId);
      return false;
    }

    if (session.expiresAt < new Date()) {
      return false;
    }

    // Update lastActiveAt periodically (e.g. at most once every 5 mins)
    const now = new Date();
    if (now.getTime() - session.lastActiveAt.getTime() > 300_000) {
      session.lastActiveAt = now;
    }

    // Populate L1 for future fast-path hits
    l1Set(sessionId, userId, session.expiresAt);

    return true;
  }

  /**
   * Revokes an individual session immediately.
   * Writes an L1 tombstone locally and broadcasts a SESSION_REVOKED event to
   * all other nodes via Redis Streams (Issue #439 ≤50 ms cross-node eviction).
   */
  public async revokeSession(sessionId: string, reason: string = "User logged out"): Promise<boolean> {
    // L1 tombstone — instant local eviction
    l1Revoke(sessionId);

    const session = this.sessions.get(sessionId);
    if (!session) {
      this.revokedSessionIds.add(sessionId);
      await getSessionStateStore().delete(sessionId);
      await this.recordDurableRevocation(
        sessionId,
        null,
        reason,
        new Date(Date.now() + 7 * 24 * 3600 * 1000),
      );

      void publishSessionEvent({
        type: "SESSION_REVOKED",
        sessionId,
        userId: "",
        expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
        publishedAt: Date.now(),
      });
      return false;
    }

    session.isRevoked = true;
    session.revokedAt = new Date();
    session.revocationReason = reason;
    this.revokedSessionIds.add(sessionId);
    // Drop the L2 record before broadcasting so no peer can hydrate it again.
    await getSessionStateStore().delete(sessionId);
    await this.recordDurableRevocation(sessionId, session.userId, reason, session.expiresAt);

    // L2: notify all other nodes to evict from their L1 caches
    void publishSessionEvent({
      type: "SESSION_REVOKED",
      sessionId,
      userId: session.userId,
      expiresAt: session.expiresAt.getTime(),
      publishedAt: Date.now(),
    });

    this.dispatchRevocationEvent({
      userId: session.userId,
      revokedSessionId: sessionId,
      reason,
      timestamp: new Date(),
    });

    return true;
  }

  /**
   * Revokes all sessions for a user, optionally preserving one (e.g. current device).
   * L1 tombstones and L2 stream events are emitted for each revoked session.
   */
  public async revokeAllUserSessions(
    userId: string,
    exceptSessionId?: string,
    reason: string = "Logged out other devices"
  ): Promise<number> {
    const sessionIds = this.userSessionsIndex.get(userId);
    if (!sessionIds) return 0;

    let revokedCount = 0;
    const now = new Date();

    for (const id of sessionIds) {
      if (exceptSessionId && id === exceptSessionId) {
        continue;
      }

      // L1 tombstone immediately
      l1Revoke(id);

      const session = this.sessions.get(id);
      if (session && !session.isRevoked) {
        session.isRevoked = true;
        session.revokedAt = now;
        session.revocationReason = reason;
        this.revokedSessionIds.add(id);
        await getSessionStateStore().delete(id);
        await this.recordDurableRevocation(id, userId, reason, session.expiresAt);

        void publishSessionEvent({
          type: "SESSION_REVOKED",
          sessionId: id,
          userId,
          expiresAt: session.expiresAt.getTime(),
          publishedAt: now.getTime(),
        });
        revokedCount++;
      } else {
        this.revokedSessionIds.add(id);
        await getSessionStateStore().delete(id);
      }
    }

    this.dispatchRevocationEvent({
      userId,
      revokedAllExcept: exceptSessionId,
      reason,
      timestamp: now,
    });

    return revokedCount;
  }

  /**
   * Real-time listener subscription for SSE or WebSocket streaming.
   */
  public onRevocation(listener: (event: SessionRevocationEvent) => void): () => void {
    this.eventEmitter.on("revocation", listener);
    return () => this.eventEmitter.off("revocation", listener);
  }

  private dispatchRevocationEvent(event: SessionRevocationEvent): void {
    this.eventEmitter.emit("revocation", event);
  }

  public clearAll(): void {
    this.sessions.clear();
    this.userSessionsIndex.clear();
    this.revokedSessionIds.clear();
    this.createsSincePurge = 0;
    l1Clear();
  }
}

export const sessionRegistryService = SessionRegistryService.getInstance();
