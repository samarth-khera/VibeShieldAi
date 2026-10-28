import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "./config";
import { ACTIVE_STATUSES } from "./job-store";
import type { RateLimitResult } from "./rate-limit";

// Pure quota logic with no database client import, so in-memory test stores can share it.

export type QuotaCounts = {
  /** Scans holding a slot plus remediation verifications in flight. */
  active: number;
  ipHourly?: number;
  ipDaily?: number;
  globalDaily?: number;
};

export type QuotaLimits = Pick<
  ServerConfig,
  "maxScansPerIpHourly" | "maxScansPerIpDaily" | "globalDailyScanCap" | "maxConcurrentHeavyScans"
>;

/** Single source of truth for quota decisions, shared by the pre-check and the locked reservation. */
export function evaluateQuota(counts: QuotaCounts, config: QuotaLimits): RateLimitResult {
  if (counts.active >= config.maxConcurrentHeavyScans) {
    const slots = config.maxConcurrentHeavyScans;
    return {
      allowed: false,
      retryAfterSeconds: 60,
      reason: "concurrency_limit",
      message: `All ${slots} free-tier scan worker slot${slots === 1 ? " is" : "s are"} busy, so this request was not queued. Please retry in about a minute.`,
    };
  }
  if (counts.ipHourly !== undefined && counts.ipHourly >= config.maxScansPerIpHourly) {
    return {
      allowed: false,
      retryAfterSeconds: 1800,
      reason: "hourly_ip_limit",
      message: `Free-tier quota: maximum ${config.maxScansPerIpHourly} scan submissions per client IP per hour reached.`,
    };
  }
  if (counts.ipDaily !== undefined && counts.ipDaily >= config.maxScansPerIpDaily) {
    return {
      allowed: false,
      retryAfterSeconds: 3600,
      reason: "daily_ip_limit",
      message: `Free-tier quota: maximum ${config.maxScansPerIpDaily} scan submissions per client IP per day reached.`,
    };
  }
  if (counts.globalDaily !== undefined && counts.globalDaily >= config.globalDailyScanCap) {
    return {
      allowed: false,
      retryAfterSeconds: 7200,
      reason: "global_daily_limit",
      message: `Global daily free-tier scan limit (${config.globalDailyScanCap} scans) reached. The queue resets in 24 hours.`,
    };
  }
  return { allowed: true, retryAfterSeconds: 0 };
}

export type QuotaClient = {
  scanJob: Pick<PrismaClient["scanJob"], "count">;
  remediation?: Pick<PrismaClient["remediation"], "count">;
};

/**
 * Counts heavy work that currently holds a worker slot. Progress is tracked by `updatedAt`, so a
 * retried job created long ago still counts, and a job that stopped reporting stops counting.
 */
export async function countActiveHeavyWork(client: QuotaClient, activeSince: Date): Promise<number> {
  const scans = await client.scanJob.count({
    where: { status: { in: [...ACTIVE_STATUSES] }, updatedAt: { gte: activeSince } },
  });
  const verifications = client.remediation
    ? await client.remediation.count({ where: { status: "applied", updatedAt: { gte: activeSince } } })
    : 0;
  return scans + verifications;
}

