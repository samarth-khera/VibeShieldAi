import { randomBytes } from "node:crypto";
import { verificationClaimOf, withVerificationClaim as withClaim } from "./remediation/claims";
import { Prisma, PrismaClient } from "@prisma/client";
import {
  countActiveHeavyWork,
  countWaitingScans,
  evaluateQuota,
  isWarmLease,
  WAITING_WHERE,
  WARM_LEASE_PREFIX,
  type QuotaCounts,
} from "./quota";
import {
  ACTIVE_STATUSES,
  MAX_WARM_ATTEMPTS,
  type QuotaConfig,
  type ScanExecutor,
  newJobId,
  RETRYABLE_STATUSES,
  STALE_JOB_PATCH,
  type SlotReservation,
  type VerificationReservation,
  type CreateJobWithQuotaResult,
  type FindingRecord,
  type FindingsFilter,
  type JobPatch,
  type JobRecord,
  type JobStore,
  type NewJob,
} from "./job-store";
import type { NormalizedFinding } from "./scanners/types";

const g = globalThis as unknown as { __prisma?: PrismaClient };
export const prisma = g.__prisma ?? new PrismaClient({ log: ["error"] });
if (process.env.NODE_ENV !== "production") g.__prisma = prisma;

/** Checks whether a database error is a transient connection failure (e.g., Neon serverless scale-from-zero). */
export function isTransientDbError(err: unknown): boolean {
  if (!err) return false;
  if (err instanceof Prisma.PrismaClientInitializationError) return true;
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    return ["P1001", "P1002", "P1017", "P2024"].includes(err.code);
  }
  const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
  return (
    msg.includes("can't reach database") ||
    msg.includes("connection closed") ||
    msg.includes("econnreset") ||
    msg.includes("etimedout") ||
    msg.includes("server has closed the connection") ||
    msg.includes("terminating connection")
  );
}

/** Executes a database operation with exponential backoff on transient connection failures. */
export async function withDbRetry<T>(
  fn: () => Promise<T>,
  retries = 3,
  delayMs = 300,
): Promise<T> {
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      attempt++;
      if (attempt > retries || !isTransientDbError(err)) {
        throw err;
      }
      const wait = delayMs * Math.pow(2, attempt - 1) + Math.random() * 100;
      await new Promise((r) => setTimeout(r, wait));
    }
  }
}

export const prismaJobStore: JobStore = {
  create: (data: NewJob) =>
    withDbRetry(() => prisma.scanJob.create({ data: { id: newJobId(), ...data } }) as Promise<JobRecord>),

  async createWithQuota(data: NewJob, config, now = new Date()): Promise<CreateJobWithQuotaResult> {
    return withHeavySlotLock(config, now, async (tx) => {
      const counts: QuotaCounts = { waiting: await countWaitingScans(tx) };
      let limit = evaluateQuota(counts, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };

      if (data.clientIpHash) {
        counts.ipHourly = await tx.scanJob.count({
          where: { clientIpHash: data.clientIpHash, createdAt: { gte: new Date(now.getTime() - 3600_000) } },
        });
        limit = evaluateQuota(counts, config);
        if (!limit.allowed) return { ok: false, rateLimit: limit };

        counts.ipDaily = await tx.scanJob.count({
          where: { clientIpHash: data.clientIpHash, createdAt: { gte: new Date(now.getTime() - 86400_000) } },
        });
        limit = evaluateQuota(counts, config);
        if (!limit.allowed) return { ok: false, rateLimit: limit };
      }

      counts.globalDaily = await tx.scanJob.count({ where: { createdAt: { gte: new Date(now.getTime() - 86400_000) } } });
      limit = evaluateQuota(counts, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };

      // Created waiting (no slot yet) inside the locked transaction; an executor claims it next.
      const job = (await tx.scanJob.create({ data: { id: newJobId(), status: "queued", ...data } })) as unknown as JobRecord;
      return { ok: true, job };
    });
  },

  async requeueWithQuota(id, from, maxAttempts, config, now = new Date()) {
    return withHeavySlotLock(config, now, async (tx): Promise<SlotReservation> => {
      const job = await tx.scanJob.findUnique({ where: { id }, select: { status: true, attempts: true } });
      if (!job || !from.includes(job.status) || job.attempts >= maxAttempts) return { ok: false };

      const limit = evaluateQuota({ waiting: await countWaitingScans(tx) }, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };

      // Back to waiting: it must be claimed through the same slot reservation as a new scan.
      await tx.scanJob.update({ where: { id }, data: WAITING_RESET });
      return { ok: true };
    });
  },

  async claimNextScan(executor, config, now = new Date(), opts) {
    return withHeavySlotLock(config, now, async (tx, active) => {
      if (evaluateQuota({ active }, config).allowed === false) return null;
      const waitedSince = new Date(now.getTime() - (opts?.minWaitMs ?? 0));
      const next = await tx.scanJob.findFirst({
        where: { ...WAITING_WHERE, updatedAt: { lte: waitedSince } },
        orderBy: { createdAt: "asc" },
        select: { id: true },
      });
      if (!next) return null;
      const lease = newLease(executor);
      const job = (await tx.scanJob.update({
        where: { id: next.id },
        data: { startedAt: now, workflowRunId: lease, attempts: { increment: 1 } },
      })) as unknown as JobRecord;
      return { job, lease };
    });
  },

  async queuePosition(jobId) {
    return withDbRetry(async () => {
      const job = await prisma.scanJob.findUnique({ where: { id: jobId }, select: { status: true, startedAt: true, createdAt: true } });
      if (!job || job.status !== "queued" || job.startedAt) return null;
      return 1 + (await prisma.scanJob.count({ where: { ...WAITING_WHERE, createdAt: { lt: job.createdAt } } }));
    });
  },

  async renewLease(lease, now = new Date()) {
    return withDbRetry(async () => {
      const scans = await prisma.scanJob.updateMany({
        where: { workflowRunId: lease, status: { in: [...ACTIVE_STATUSES] } },
        data: { updatedAt: now },
      });
      const verifications = await prisma.remediation.updateMany({
        where: { status: "applied", approvedOperations: { path: ["verificationClaim", "lease"], equals: lease } },
        data: { updatedAt: now },
      });
      return scans.count + verifications.count;
    });
  },

  async recordWorkerHeartbeat(input, now = new Date()) {
    return withDbRetry(async () => {
      const data = {
        lastRequestMs: BigInt(input.requestMs),
        lastSeenAt: now,
        capacity: input.capacity,
        activeJobs: input.activeJobs,
        version: input.version?.slice(0, 40) ?? null,
        arch: input.arch?.slice(0, 40) ?? null,
        scannerVersions: (input.scannerVersions ?? Prisma.DbNull) as Prisma.InputJsonValue,
      };
      // Monotonic per worker: a replayed or reordered signed request never updates the row.
      const updated = await prisma.workerHeartbeat.updateMany({
        where: { id: input.workerId, lastRequestMs: { lt: BigInt(input.requestMs) } },
        data,
      });
      if (updated.count === 1) return true;
      const existing = await prisma.workerHeartbeat.findUnique({ where: { id: input.workerId }, select: { id: true } });
      if (existing) return false;
      await prisma.workerHeartbeat.create({ data: { id: input.workerId, startedAt: now, ...data } }).catch(() => undefined);
      return true;
    });
  },

  async warmWorkerHealthy(now, healthyMs) {
    return withDbRetry(async () => {
      const n = await prisma.workerHeartbeat.count({ where: { lastSeenAt: { gte: new Date(now.getTime() - healthyMs) } } });
      return n > 0;
    });
  },

  async transition(id, from, patch) {
    return withDbRetry(async () => {
      const r = await prisma.scanJob.updateMany({
        where: { id, status: { in: [...from] } },
        data: patch as Prisma.ScanJobUpdateManyMutationInput,
      });
      return r.count === 1;
    });
  },

  async reapStale(now, config) {
    return withDbRetry(() => reapStaleWork(prisma, now, config));
  },

  get: (id) =>
    withDbRetry(() => prisma.scanJob.findUnique({ where: { id } }) as Promise<JobRecord | null>),

  async claim(id, staleBefore) {
    return withDbRetry(async () => {
      const r = await prisma.scanJob.updateMany({
        where: {
          id,
          OR: [{ status: "queued" }, { status: "retrieving", startedAt: { lt: staleBefore } }],
        },
        data: { status: "retrieving", startedAt: new Date(), attempts: { increment: 1 }, failureCategory: null, errorMessage: null },
      });
      return r.count === 1;
    });
  },
  async claimForScan(id, staleBefore) {
    return withDbRetry(async () => {
      const r = await prisma.scanJob.updateMany({
        where: {
          id,
          OR: [
            { status: "ready_for_scan" },
            { status: "retrieving" },
            { status: "scanning", startedAt: { lt: staleBefore } },
          ],
        },
        data: { status: "scanning", failureCategory: null, errorMessage: null },
      });
      return r.count === 1;
    });
  },
  async update(id, patch: JobPatch) {
    await withDbRetry(() => prisma.scanJob.update({ where: { id }, data: patch as Prisma.ScanJobUpdateInput }));
  },
  async requeue(id, maxAttempts) {
    return withDbRetry(async () => {
      const r = await prisma.scanJob.updateMany({
        where: { id, status: { in: [...RETRYABLE_STATUSES] }, attempts: { lt: maxAttempts } },
        data: { status: "queued", failureCategory: null, errorMessage: null, completedAt: null },
      });
      return r.count === 1;
    });
  },
  async deleteExpired(now) {
    return withDbRetry(async () => {
      return (await prisma.scanJob.deleteMany({ where: { expiresAt: { lt: now } } })).count;
    });
  },

  async saveFindings(jobId: string, findings: NormalizedFinding[]) {
    await withDbRetry(() =>
      prisma.$transaction(async (tx) => {
        // Remove old findings if re-scanning
        await tx.finding.deleteMany({ where: { scanJobId: jobId } });

        if (findings.length === 0) return;

        await tx.finding.createMany({
          data: findings.map((f) => ({
            scanJobId: jobId,
            fingerprint: f.fingerprint,
            scanner: f.scanner,
            ruleId: f.ruleId,
            category: f.category,
            severity: f.severity,
            originalSeverity: f.originalSeverity ?? null,
            title: f.title,
            description: f.description,
            filePath: f.filePath,
            startLine: f.startLine,
            endLine: f.endLine,
            redactedEvidence: f.redactedEvidence,
            vulnerabilityId: f.vulnerabilityId,
            remediation: f.remediation,
            packageInfo: (f.packageInfo ?? Prisma.DbNull) as Prisma.InputJsonValue,
            metadata: (f.metadata ?? Prisma.DbNull) as Prisma.InputJsonValue,
          })),
          skipDuplicates: true,
        });
      })
    );
  },

  async getFindings(jobId: string, filter?: FindingsFilter) {
    return withDbRetry(async () => {
      const where: Prisma.FindingWhereInput = { scanJobId: jobId };

      if (filter?.severity && filter.severity !== "all") {
        where.severity = filter.severity;
      }
      if (filter?.category && filter.category !== "all") {
        where.category = filter.category;
      }
      if (filter?.query) {
        const q = filter.query.trim();
        where.OR = [
          { title: { contains: q, mode: "insensitive" } },
          { description: { contains: q, mode: "insensitive" } },
          { filePath: { contains: q, mode: "insensitive" } },
          { ruleId: { contains: q, mode: "insensitive" } },
          { vulnerabilityId: { contains: q, mode: "insensitive" } },
        ];
      }

      const [total, findings] = await Promise.all([
        prisma.finding.count({ where }),
        prisma.finding.findMany({
          where,
          take: filter?.limit ?? 100,
          skip: filter?.offset ?? 0,
          orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
        }),
      ]);

      return { findings: findings as FindingRecord[], total };
    });
  },

  async getFinding(jobId: string, findingId: string) {
    return withDbRetry(async () => {
      const finding = await prisma.finding.findFirst({
        where: { id: findingId, scanJobId: jobId },
      });
      return (finding as FindingRecord) || null;
    });
  },

  async saveFindingAiExplanation(jobId: string, findingId: string, aiExplanation: unknown) {
    await withDbRetry(() =>
      prisma.finding.updateMany({
        where: { id: findingId, scanJobId: jobId },
        data: { aiExplanation: aiExplanation as Prisma.InputJsonValue },
      })
    );
  },

  async createRemediation(data) {
    return withDbRetry(async () => {
      const created = await prisma.remediation.create({
        data: {
          id: data.id,
          scanJobId: data.scanJobId,
          status: data.status,
          findingFingerprints: data.findingFingerprints as Prisma.InputJsonValue,
          commitSha: data.commitSha,
          patchSummary: data.patchSummary,
          unifiedDiff: data.unifiedDiff,
          affectedFiles: data.affectedFiles as Prisma.InputJsonValue,
          eligibility: data.eligibility,
          eligibilityReason: data.eligibilityReason,
          requiresRotation: data.requiresRotation,
          warnings: (data.warnings || []) as Prisma.InputJsonValue,
          approvedAt: data.approvedAt,
          approvedOperations: data.approvedOperations as Prisma.InputJsonValue,
          rescanStatus: data.rescanStatus,
          rescanSummary: data.rescanSummary as Prisma.InputJsonValue,
          branchName: data.branchName,
          pullRequestUrl: data.pullRequestUrl,
        },
      });
      return created as unknown as import("./remediation/types").RemediationRecord;
    });
  },

  async getRemediation(scanJobId, remediationId) {
    return withDbRetry(async () => {
      const r = await prisma.remediation.findFirst({
        where: { id: remediationId, scanJobId },
      });
      return (r as unknown as import("./remediation/types").RemediationRecord) || null;
    });
  },

  async listRemediations(scanJobId) {
    return withDbRetry(async () => {
      const list = await prisma.remediation.findMany({
        where: { scanJobId },
        orderBy: { createdAt: "desc" },
      });
      return list as unknown as import("./remediation/types").RemediationRecord[];
    });
  },

  async transitionRemediation(scanJobId, remediationId, from, patch) {
    return withDbRetry(async () => {
      const r = await prisma.remediation.updateMany({
        where: { id: remediationId, scanJobId, status: { in: [...from] } },
        data: remediationPatchData(patch) as Prisma.RemediationUpdateManyMutationInput,
      });
      if (r.count !== 1) return null;
      const updated = await prisma.remediation.findUnique({ where: { id: remediationId } });
      return updated as unknown as import("./remediation/types").RemediationRecord;
    });
  },

  async beginRemediationVerification(scanJobId, remediationId, config, now = new Date()) {
    return withHeavySlotLock(config, now, async (tx, active): Promise<VerificationReservation> => {
      const limit = evaluateQuota({ active }, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };

      const r = await tx.remediation.updateMany({
        where: { id: remediationId, scanJobId, status: "approved", approvedAt: { not: null } },
        data: { status: "applied", rescanStatus: null, rescanSummary: Prisma.DbNull },
      });
      if (r.count !== 1) return { ok: false };
      const remediation = await tx.remediation.findUnique({ where: { id: remediationId } });
      return { ok: true, remediation: remediation as unknown as import("./remediation/types").RemediationRecord };
    });
  },

  async assignVerification(scanJobId, remediationId, lease) {
    return withDbRetry(() =>
      prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(84239105)`;
        const r = await tx.remediation.findFirst({ where: { id: remediationId, scanJobId, status: "applied" } });
        if (!r || verificationClaimOf(r.approvedOperations)) return false;
        await tx.remediation.update({
          where: { id: remediationId },
          data: { approvedOperations: withVerificationClaim(r.approvedOperations, lease) },
        });
        return true;
      }),
    );
  },

  async claimNextVerification(workerId, config, now = new Date()) {
    return withHeavySlotLock(config, now, async (tx) => {
      // The slot was already reserved when the verification was approved and applied.
      const pending = await tx.remediation.findMany({ where: { status: "applied" }, orderBy: { updatedAt: "asc" }, take: 20 });
      const next = pending.find((r) => !verificationClaimOf(r.approvedOperations));
      if (!next) return null;
      const lease = newLease({ kind: "warm", workerId });
      const remediation = await tx.remediation.update({
        where: { id: next.id },
        data: { approvedOperations: withVerificationClaim(next.approvedOperations, lease), updatedAt: now },
      });
      const job = (await tx.scanJob.findUnique({ where: { id: next.scanJobId } })) as unknown as JobRecord;
      return { job, lease, remediation: remediation as unknown as import("./remediation/types").RemediationRecord };
    });
  },

  async updateRemediation(scanJobId, remediationId, patch) {
    return withDbRetry(async () => {
      const updated = await prisma.remediation.update({
        where: { id: remediationId, scanJobId },
        data: remediationPatchData(patch) as Prisma.RemediationUpdateInput,
      });
      return updated as unknown as import("./remediation/types").RemediationRecord;
    });
  },
};

function remediationPatchData(patch: Partial<import("./remediation/types").RemediationRecord>) {
  return {
    ...patch,
    findingFingerprints: patch.findingFingerprints ? (patch.findingFingerprints as Prisma.InputJsonValue) : undefined,
    affectedFiles: patch.affectedFiles ? (patch.affectedFiles as Prisma.InputJsonValue) : undefined,
    warnings: patch.warnings ? (patch.warnings as Prisma.InputJsonValue) : undefined,
    approvedOperations: patch.approvedOperations ? (patch.approvedOperations as Prisma.InputJsonValue) : undefined,
    rescanSummary: patch.rescanSummary ? (patch.rescanSummary as Prisma.InputJsonValue) : undefined,
  };
}

type Tx = Prisma.TransactionClient;

/** Fields reset when a scan goes back to waiting for a slot. */
const WAITING_RESET = {
  status: "queued",
  startedAt: null,
  workflowRunId: null,
  workflowRunUrl: null,
  failureCategory: null,
  errorMessage: null,
  completedAt: null,
  gitleaksStatus: null,
  semgrepStatus: null,
  osvStatus: null,
} as const;

function newLease(executor: ScanExecutor): string {
  const token = randomBytes(9).toString("base64url");
  return executor.kind === "warm" ? `${WARM_LEASE_PREFIX}${executor.workerId.slice(0, 64)}:${token}` : `gha:${token}`;
}

const withVerificationClaim = (ops: unknown, lease: string | null) => withClaim(ops, lease) as Prisma.InputJsonValue;

const VERIFICATION_TIMEOUT_SUMMARY = {
  targetResolved: false,
  originalFindingsCount: 0,
  postRescanFindingsCount: 0,
  newFindingsCount: 0,
  resolvedFingerprints: [],
  remainingFingerprints: [],
  regressions: [],
  reason: "verification_timeout",
  detail: "The verification worker did not report a result in time. Nothing was verified.",
};

/** Releases work that stopped reporting progress, so it never holds a slot or a status forever. */
async function reapStaleWork(client: Tx | PrismaClient, now: Date, config: QuotaConfig): Promise<number> {
  const leaseExpired = new Date(now.getTime() - config.warmLeaseMs);
  const jobExpired = new Date(now.getTime() - config.jobTimeoutMs);
  const queueExpired = new Date(now.getTime() - config.queueTimeoutMs);
  let changed = 0;

  // Warm-worker scans whose lease lapsed (worker crashed or restarted): re-queue a bounded number of times.
  const lost = await client.scanJob.findMany({
    where: {
      status: { in: [...ACTIVE_STATUSES] },
      startedAt: { not: null },
      workflowRunId: { startsWith: WARM_LEASE_PREFIX },
      updatedAt: { lt: leaseExpired },
    },
    select: { id: true, attempts: true },
  });
  for (const job of lost) {
    if (job.attempts < MAX_WARM_ATTEMPTS) {
      await client.finding.deleteMany({ where: { scanJobId: job.id } }); // partial results of the lost run
      await client.scanJob.update({ where: { id: job.id }, data: WAITING_RESET });
    } else {
      await client.scanJob.update({ where: { id: job.id }, data: { ...STALE_JOB_PATCH, completedAt: now } });
    }
    changed++;
  }

  const stuck = await client.scanJob.updateMany({
    where: {
      status: { in: [...ACTIVE_STATUSES] },
      startedAt: { not: null },
      NOT: { workflowRunId: { startsWith: WARM_LEASE_PREFIX } },
      updatedAt: { lt: jobExpired },
    },
    data: { ...STALE_JOB_PATCH, completedAt: now },
  });
  const expiredInQueue = await client.scanJob.updateMany({
    where: { ...WAITING_WHERE, updatedAt: { lt: queueExpired } },
    data: {
      status: "failed",
      failureCategory: "queue_timeout",
      errorMessage: "No scan worker became available in time. Please retry the scan.",
      completedAt: now,
    },
  });
  changed += stuck.count + expiredInQueue.count;

  for (const r of await client.remediation.findMany({ where: { status: "applied", updatedAt: { lt: leaseExpired } } })) {
    const claim = verificationClaimOf(r.approvedOperations);
    if (isWarmLease(claim?.lease)) {
      // Unassign so a live worker (or the Actions fallback) picks it up again.
      await client.remediation.update({ where: { id: r.id }, data: { approvedOperations: withVerificationClaim(r.approvedOperations, null) } });
      changed++;
    } else if (r.updatedAt < jobExpired) {
      await client.remediation.update({
        where: { id: r.id },
        data: { status: "failed", rescanStatus: "failed", rescanSummary: VERIFICATION_TIMEOUT_SUMMARY },
      });
      changed++;
    }
  }
  return changed;
}

/**
 * Runs `fn` while holding the global heavy-work advisory lock (key 84239105) inside one transaction.
 * Stale work is reaped first, then `fn` receives the number of slots in use. Because every slot
 * reservation goes through this lock and commits before releasing it, concurrent requests cannot
 * both observe a free slot.
 */
async function withHeavySlotLock<T>(
  config: QuotaConfig,
  now: Date,
  fn: (tx: Tx, activeSlots: number) => Promise<T>,
): Promise<T> {
  return withDbRetry(() =>
    prisma.$transaction(
      async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(84239105)`;
        await reapStaleWork(tx, now, config);
        const active = await countActiveHeavyWork(tx);
        return fn(tx, active);
      },
      { timeout: 15000, isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
    ),
  );
}
