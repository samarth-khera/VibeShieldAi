import type { PrismaClient } from "@prisma/client";
import type { ServerConfig } from "./config";
import { ACTIVE_STATUSES } from "./job-store";
import type { RateLimitResult } from "./rate-limit";

// Pure quota logic with no database client import, so in-memory test stores can share it.
//
// Queue model: a scan is *waiting* while `status = queued` and `startedAt` is null, and *holds a
// slot* once an executor (GitHub Actions dispatch or the warm worker) claims it and sets
// `startedAt`. Submissions are limited by the waiting-queue length; execution is limited by
// `maxConcurrentHeavyScans`, shared with in-flight Auto-Fix verifications.

export type QuotaCounts = {
  /** Claimed scans plus remediation verifications in flight. Checked only where a slot is taken. */
  active?: number;
  /** Scans waiting for a slot. */
  waiting?: number;
  ipHourly?: number;
  ipDaily?: number;
  globalDaily?: number;
};

export type QuotaLimits = Pick<
  ServerConfig,
  "maxScansPerIpHourly" | "maxScansPerIpDaily" | "globalDailyScanCap" | "maxConcurrentHeavyScans" | "maxQueuedScans"
>;

/** Single source of truth for quota decisions, shared by the pre-check and the locked reservation. */
export function evaluateQuota(counts: QuotaCounts, config: QuotaLimits): RateLimitResult {
  if (counts.active !== undefined && counts.active >= config.maxConcurrentHeavyScans) {
    const slots = config.maxConcurrentHeavyScans;
    return {
      allowed: false,
      retryAfterSeconds: 60,
      reason: "concurrency_limit",
      message: `All ${slots} free-tier scan worker slot${slots === 1 ? " is" : "s are"} busy, so this request was not queued. Please retry in about a minute.`,
    };
  }
  if (counts.waiting !== undefined && counts.waiting >= config.maxQueuedScans) {
    return {
      allowed: false,
      retryAfterSeconds: 120,
      reason: "queue_full",
      message: `The free-tier scan queue is full (${config.maxQueuedScans} scans waiting), so this request was not queued. Please retry in a few minutes.`,
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

/** Where-clause for scans waiting for a slot. */
export const WAITING_WHERE = { status: "queued" as const, startedAt: null };

/** Heavy work holding a slot: claimed scans plus in-flight verifications. Stale work is reaped first by callers. */
export async function countActiveHeavyWork(client: QuotaClient): Promise<number> {
  const scans = await client.scanJob.count({
    where: { status: { in: [...ACTIVE_STATUSES] }, startedAt: { not: null } },
  });
  const verifications = client.remediation ? await client.remediation.count({ where: { status: "applied" } }) : 0;
  return scans + verifications;
}

export async function countWaitingScans(client: QuotaClient): Promise<number> {
  return client.scanJob.count({ where: WAITING_WHERE });
}

/** Lease owners written to ScanJob.workflowRunId when a slot is claimed. */
export const GHA_DISPATCH_LEASE = "gha:dispatching";
export const WARM_LEASE_PREFIX = "warm:";
export const isWarmLease = (lease: string | null | undefined) => Boolean(lease?.startsWith(WARM_LEASE_PREFIX));
