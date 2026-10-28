import { createHash } from "node:crypto";
import type IORedis from "ioredis";
import { withDbRetry } from "./db";
import { countWaitingScans, evaluateQuota, type QuotaClient, type QuotaCounts, type QuotaLimits } from "./quota";

export { countActiveHeavyWork, evaluateQuota, type QuotaCounts } from "./quota";

export type RateLimitResult = {
  allowed: boolean;
  retryAfterSeconds: number;
  reason?: "concurrency_limit" | "queue_full" | "hourly_ip_limit" | "daily_ip_limit" | "global_daily_limit" | "rate_limited";
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
 * Fast, unlocked pre-check of free-tier quotas (Rule 8) so obviously over-quota requests are rejected
 * before Turnstile and GitHub calls. The authoritative check runs again inside `createWithQuota`.
 */
export async function checkDatabaseQuotas(
  prismaClient: QuotaClient,
  ipHash: string,
  config: QuotaLimits,
  now: Date = new Date(),
): Promise<RateLimitResult> {
  return withDbRetry(async () => {
    const counts: QuotaCounts = { waiting: await countWaitingScans(prismaClient) };
    let result = evaluateQuota(counts, config);
    if (!result.allowed) return result;

    counts.ipHourly = await prismaClient.scanJob.count({
      where: { clientIpHash: ipHash, createdAt: { gte: new Date(now.getTime() - 3600_000) } },
    });
    result = evaluateQuota(counts, config);
    if (!result.allowed) return result;

    counts.ipDaily = await prismaClient.scanJob.count({
      where: { clientIpHash: ipHash, createdAt: { gte: new Date(now.getTime() - 86400_000) } },
    });
    result = evaluateQuota(counts, config);
    if (!result.allowed) return result;

    counts.globalDaily = await prismaClient.scanJob.count({
      where: { createdAt: { gte: new Date(now.getTime() - 86400_000) } },
    });
    return evaluateQuota(counts, config);
  });
}
