import { createHash } from "node:crypto";
import type IORedis from "ioredis";

export type RateLimitResult = { allowed: boolean; retryAfterSeconds: number };

/** Hash so raw IPs are never stored in Redis or logs. */
export function clientKey(headers: Headers): string {
  const fwd = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const ip = fwd || headers.get("x-real-ip")?.trim() || "unknown";
  return createHash("sha256").update(ip).digest("hex").slice(0, 32);
}

/** Fixed-window limiter. Throws if Redis is unavailable (caller fails closed). */
export async function checkRateLimit(redis: Pick<IORedis, "incr" | "expire" | "ttl">, key: string, max: number, windowSeconds: number): Promise<RateLimitResult> {
  const k = `rl:scan:${key}`;
  const count = await redis.incr(k);
  if (count === 1) await redis.expire(k, windowSeconds);
  if (count <= max) return { allowed: true, retryAfterSeconds: 0 };
  const ttl = await redis.ttl(k);
  if (ttl < 0) await redis.expire(k, windowSeconds); // self-heal a key lost its TTL
  return { allowed: false, retryAfterSeconds: ttl > 0 ? ttl : windowSeconds };
}
