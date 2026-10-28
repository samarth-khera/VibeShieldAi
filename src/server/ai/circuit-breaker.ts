import { PrismaClient } from "@prisma/client";
import { prisma as defaultPrisma, withDbRetry } from "../db";
import { getConfig } from "../config";

export type AiQuotaCheckResult = {
  allowed: boolean;
  reason?: "circuit_breaker_open" | "ip_hourly_limit" | "ip_daily_limit" | "global_daily_cap";
  message?: string;
  retryAfterSeconds?: number;
};

export type TripCircuitBreakerOptions = {
  reason: "quota_exhausted" | "rate_limited" | "api_error" | "manual";
  message?: string;
  cooldownMs?: number;
};

const GLOBAL_BREAKER_ID = "global";

/**
 * Checks database-backed circuit breaker and enforces per-IP and global daily limits.
 * Does NOT increment request count if rejected.
 */
export async function checkAiQuotaAndCircuitBreaker(
  clientIpHash: string,
  deps?: {
    prisma?: PrismaClient;
    now?: Date;
    config?: Partial<ReturnType<typeof getConfig>>;
  }
): Promise<AiQuotaCheckResult> {
  const db = deps?.prisma || defaultPrisma;
  const now = deps?.now || new Date();
  const config = { ...getConfig(), ...deps?.config };

  return withDbRetry(async () => {
    // 1. Check Circuit Breaker status
    const breaker = await db.aiCircuitBreaker.findUnique({
      where: { id: GLOBAL_BREAKER_ID },
    });

    if (breaker && breaker.isOpen) {
      if (breaker.cooldownUntil && now >= breaker.cooldownUntil) {
        // Cooldown has expired: automatically reset breaker to allow gradual recovery
        await db.aiCircuitBreaker.update({
          where: { id: GLOBAL_BREAKER_ID },
          data: {
            isOpen: false,
            reason: null,
            message: null,
            cooldownUntil: null,
            consecutiveFailures: 0,
          },
        });
      } else {
        const retryAfterSeconds = breaker.cooldownUntil
          ? Math.max(1, Math.ceil((breaker.cooldownUntil.getTime() - now.getTime()) / 1000))
          : (config.aiCircuitBreakerCooldownHours ?? 24) * 3600;

        return {
          allowed: false,
          reason: "circuit_breaker_open",
          message:
            breaker.message ||
            "AI Security Analyst is temporarily paused due to upstream quota limits. Security scan findings remain available.",
          retryAfterSeconds,
        };
      }
    }

    const oneHourAgo = new Date(now.getTime() - 3600 * 1000);
    const oneDayAgo = new Date(now.getTime() - 24 * 3600 * 1000);

    // 2. Check per-IP hourly limit
    const ipHourlyCount = await db.aiRequestLog.count({
      where: {
        clientIpHash,
        createdAt: { gte: oneHourAgo },
      },
    });

    if (ipHourlyCount >= (config.aiMaxRequestsPerIpHourly ?? 8)) {
      return {
        allowed: false,
        reason: "ip_hourly_limit",
        message: "Hourly AI request limit reached for this IP. Please wait before requesting more explanations.",
        retryAfterSeconds: 3600,
      };
    }

    // 3. Check per-IP daily limit
    const ipDailyCount = await db.aiRequestLog.count({
      where: {
        clientIpHash,
        createdAt: { gte: oneDayAgo },
      },
    });

    if (ipDailyCount >= (config.aiMaxRequestsPerIpDaily ?? 25)) {
      return {
        allowed: false,
        reason: "ip_daily_limit",
        message: "Daily AI request limit reached for this IP. Please try again tomorrow.",
        retryAfterSeconds: 86400,
      };
    }

    // 4. Check global daily cap
    const globalDailyCount = await db.aiRequestLog.count({
      where: {
        createdAt: { gte: oneDayAgo },
      },
    });

    if (globalDailyCount >= (config.aiGlobalDailyCap ?? 50)) {
      return {
        allowed: false,
        reason: "global_daily_cap",
        message: "Global daily AI analysis capacity reached. Please try again tomorrow.",
        retryAfterSeconds: 86400,
      };
    }

    return { allowed: true };
  });
}

/**
 * Trips the global circuit breaker across all serverless instances.
 */
export async function tripAiCircuitBreaker(
  options: TripCircuitBreakerOptions,
  deps?: { prisma?: PrismaClient; now?: Date }
): Promise<void> {
  const db = deps?.prisma || defaultPrisma;
  const now = deps?.now || new Date();
  const config = getConfig();

  const defaultCooldownMs =
    options.reason === "rate_limited"
      ? 15 * 60 * 1000 // 15 mins for temporary rate limits
      : (config.aiCircuitBreakerCooldownHours ?? 24) * 3600 * 1000; // 24h for quota exhaustion

  const cooldownUntil = new Date(now.getTime() + (options.cooldownMs ?? defaultCooldownMs));

  const safeMessage =
    options.message ||
    (options.reason === "quota_exhausted"
      ? "AI Security Analyst is temporarily offline due to upstream daily quota exhaustion. Security scanners remain fully functional."
      : "AI Security Analyst is temporarily throttled to prevent quota exhaustion.");

  await withDbRetry(() =>
    db.aiCircuitBreaker.upsert({
      where: { id: GLOBAL_BREAKER_ID },
      create: {
        id: GLOBAL_BREAKER_ID,
        isOpen: true,
        openedAt: now,
        reason: options.reason,
        message: safeMessage,
        cooldownUntil,
        consecutiveFailures: 1,
        lastFailureAt: now,
      },
      update: {
        isOpen: true,
        openedAt: now,
        reason: options.reason,
        message: safeMessage,
        cooldownUntil,
        consecutiveFailures: { increment: 1 },
        lastFailureAt: now,
      },
    })
  );
}

/**
 * Resets the circuit breaker (admin-authorized or automated recovery).
 */
export async function resetAiCircuitBreaker(deps?: { prisma?: PrismaClient }): Promise<void> {
  const db = deps?.prisma || defaultPrisma;

  await withDbRetry(() =>
    db.aiCircuitBreaker.upsert({
      where: { id: GLOBAL_BREAKER_ID },
      create: {
        id: GLOBAL_BREAKER_ID,
        isOpen: false,
        reason: null,
        message: null,
        cooldownUntil: null,
        consecutiveFailures: 0,
      },
      update: {
        isOpen: false,
        reason: null,
        message: null,
        cooldownUntil: null,
        consecutiveFailures: 0,
      },
    })
  );
}

/**
 * Records an executed on-demand AI request for auditing and quota tracking.
 */
export async function recordAiRequest(
  params: {
    clientIpHash: string;
    scanJobId?: string;
    findingId?: string;
    action: "explain" | "remediation";
    success: boolean;
  },
  deps?: { prisma?: PrismaClient }
): Promise<void> {
  const db = deps?.prisma || defaultPrisma;

  await withDbRetry(() =>
    db.aiRequestLog.create({
      data: {
        clientIpHash: params.clientIpHash,
        scanJobId: params.scanJobId,
        findingId: params.findingId,
        action: params.action,
        success: params.success,
      },
    })
  );
}

/**
 * Retrieves the full circuit breaker and rate limit status for administrative diagnostics.
 */
export async function getAiCircuitBreakerStatus(deps?: { prisma?: PrismaClient; now?: Date }) {
  const db = deps?.prisma || defaultPrisma;
  const now = deps?.now || new Date();
  const oneHourAgo = new Date(now.getTime() - 3600 * 1000);
  const oneDayAgo = new Date(now.getTime() - 24 * 3600 * 1000);

  return withDbRetry(async () => {
    const breaker = await db.aiCircuitBreaker.findUnique({
      where: { id: GLOBAL_BREAKER_ID },
    });

    const [requestsLastHour, requestsLast24h] = await Promise.all([
      db.aiRequestLog.count({ where: { createdAt: { gte: oneHourAgo } } }),
      db.aiRequestLog.count({ where: { createdAt: { gte: oneDayAgo } } }),
    ]);

    const isOpen = Boolean(breaker?.isOpen && (!breaker.cooldownUntil || now < breaker.cooldownUntil));

    return {
      circuitBreaker: {
        isOpen,
        openedAt: breaker?.openedAt ?? null,
        reason: breaker?.reason ?? null,
        message: breaker?.message ?? null,
        cooldownUntil: breaker?.cooldownUntil ?? null,
        consecutiveFailures: breaker?.consecutiveFailures ?? 0,
        lastFailureAt: breaker?.lastFailureAt ?? null,
      },
      stats: {
        requestsLastHour,
        requestsLast24h,
      },
    };
  });
}
