import { createHash } from "node:crypto";
import type IORedis from "ioredis";
import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "./config";
import { withDbRetry } from "./db";

export type RateLimitResult = {
  allowed: boolean;
  retryAfterSeconds: number;
  reason?: "concurrency_limit" | "hourly_ip_limit" | "daily_ip_limit" | "global_daily_limit" | "rate_limited";
  message?: string;
};

/**
 * Derives an unguessable, non-reversible client rate-limiting key.
 *
 * Anti-spoofing defense:
 * 1. Checks verified reverse proxy headers first (`cf-connecting-ip`, `fly-client-ip`, `x-real-ip`).
 * 2. If `x-forwarded-for` is used:
 *    Reverse proxies append the actual remote IP to the END (rightmost) of X-Forwarded-For.
 *    Blindly taking index 0 allows an attacker to bypass rate limits by injecting arbitrary IPs:
 *    `X-Forwarded-For: attacker_ip_1, real_proxy_ip`.
 *    We therefore inspect the rightmost entry appended by the proxy (or configurable hops).
 * 3. Binds user-agent and client entropy to prevent evading limits if IP headers are omitted.
 */
export function clientKey(headers: Headers, options?: { trustProxyHops?: number }): string {
  // Edge proxy headers set directly by verified edge CDNs
  const edgeIp =
    headers.get("cf-connecting-ip")?.trim() ||
    headers.get("fly-client-ip")?.trim() ||
    headers.get("x-real-ip")?.trim();

  let ip = edgeIp;

  if (!ip) {
    const xff = headers.get("x-forwarded-for");
    if (xff) {
      const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
      const hops = options?.trustProxyHops ?? 1;
      const targetIndex = Math.max(0, parts.length - hops);
      ip = parts[targetIndex] || parts[parts.length - 1];
    }
  }

  const effectiveIp = ip && ip.length <= 45 ? ip : "unknown";
  const ua = (headers.get("user-agent") || "").slice(0, 100);
  const rawKey = effectiveIp === "unknown" ? `unknown:${ua}` : effectiveIp;

  return createHash("sha256").update(rawKey).digest("hex").slice(0, 32);
}

/** Fixed-window limiter. Throws if Redis is unavailable (caller fails closed). */
export async function checkRateLimit(
  redis: Pick<IORedis, "incr" | "expire" | "ttl">,
  key: string,
  max: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  const k = `rl:scan:${key}`;
  const count = await redis.incr(k);
  if (count === 1) await redis.expire(k, windowSeconds);
  if (count <= max) return { allowed: true, retryAfterSeconds: 0 };
  const ttl = await redis.ttl(k);
  if (ttl < 0) await redis.expire(k, windowSeconds); // self-heal a key lost its TTL
  return { allowed: false, retryAfterSeconds: ttl > 0 ? ttl : windowSeconds, reason: "rate_limited" };
}

/**
 * Checks free-tier database quotas and global concurrency limits (Rule 8).
 * Powered entirely by PostgreSQL (Neon Free), eliminating Redis dependency in serverless production.
 */
export async function checkDatabaseQuotas(
  prismaClient: Pick<PrismaClient, "scanJob">,
  ipHash: string,
  config: Pick<
    ServerConfig,
    "maxScansPerIpHourly" | "maxScansPerIpDaily" | "globalDailyScanCap" | "maxConcurrentHeavyScans" | "jobTimeoutMs"
  >,
  now: Date = new Date(),
): Promise<RateLimitResult> {
  return withDbRetry(async () => {
    const activeThreshold = new Date(now.getTime() - config.jobTimeoutMs);
    const oneHourAgo = new Date(now.getTime() - 3600_000);
    const oneDayAgo = new Date(now.getTime() - 86400_000);

    // 1. Check active heavy scan concurrency (Rule 8: 1 active scan at a time)
    const activeCount = await prismaClient.scanJob.count({
      where: {
        status: { in: ["queued", "retrieving", "ready_for_scan", "scanning"] },
        createdAt: { gte: activeThreshold },
      },
    });

    if (activeCount >= config.maxConcurrentHeavyScans) {
      return {
        allowed: false,
        retryAfterSeconds: 60,
        reason: "concurrency_limit",
        message:
          "A security scan is currently running. Free-tier quota allows 1 active scan at a time. Please retry in 1 minute.",
      };
    }

    // 2. Check per-IP hourly limit (Rule 8: 3 per IP per hour)
    const ipHourlyCount = await prismaClient.scanJob.count({
      where: {
        clientIpHash: ipHash,
        createdAt: { gte: oneHourAgo },
      },
    });

    if (ipHourlyCount >= config.maxScansPerIpHourly) {
      return {
        allowed: false,
        retryAfterSeconds: 1800,
        reason: "hourly_ip_limit",
        message: `Free-tier quota: maximum ${config.maxScansPerIpHourly} scan submissions per client IP per hour reached.`,
      };
    }

    // 3. Check per-IP daily limit (Rule 8: 5 per IP per day)
    const ipDailyCount = await prismaClient.scanJob.count({
      where: {
        clientIpHash: ipHash,
        createdAt: { gte: oneDayAgo },
      },
    });

    if (ipDailyCount >= config.maxScansPerIpDaily) {
      return {
        allowed: false,
        retryAfterSeconds: 3600,
        reason: "daily_ip_limit",
        message: `Free-tier quota: maximum ${config.maxScansPerIpDaily} scan submissions per client IP per day reached.`,
      };
    }

    // 4. Check global daily cap (Rule 8: 20 scans per day)
    const globalDailyCount = await prismaClient.scanJob.count({
      where: {
        createdAt: { gte: oneDayAgo },
      },
    });

    if (globalDailyCount >= config.globalDailyScanCap) {
      return {
        allowed: false,
        retryAfterSeconds: 7200,
        reason: "global_daily_limit",
        message: `Global daily free-tier scan limit (${config.globalDailyScanCap} scans) reached. The queue resets in 24 hours.`,
      };
    }

    return { allowed: true, retryAfterSeconds: 0 };
  });
}

