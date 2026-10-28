import { randomBytes } from "node:crypto";
import type { ScanStatus } from "@prisma/client";
import { evaluateQuota, isWarmLease, WARM_LEASE_PREFIX } from "@/server/quota";
import { verificationClaimOf, withVerificationClaim } from "@/server/remediation/claims";
import type { RemediationRecord, RemediationStatus } from "@/server/remediation/types";
import {
  ACTIVE_STATUSES,
  MAX_WARM_ATTEMPTS,
  STALE_JOB_PATCH,
  type ScanExecutor,
  type WorkerHeartbeatInput,
  newJobId,
  type QuotaConfig,
  type SlotReservation,
  type VerificationReservation,
  type JobRecord,
  type JobStore,
  type NewJob,
  type JobPatch,
  type FindingRecord,
  type CreateJobWithQuotaResult,
} from "@/server/job-store";
import type { NormalizedFinding } from "@/server/scanners/types";

export class InMemoryJobStore implements JobStore {
  private jobs = new Map<string, JobRecord>();
  private findings = new Map<string, FindingRecord[]>();
  private mutex = Promise.resolve();
  private remediations = new Map<string, RemediationRecord[]>();

  /** Serializes slot reservations exactly like the Postgres advisory lock does in production. */
  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    let release: () => void;
    const nextMutex = new Promise<void>((resolve) => {
      release = resolve;
    });
    const currentMutex = this.mutex;
    this.mutex = nextMutex;
    await currentMutex;
    try {
      return await fn();
    } finally {
      release!();
    }
  }

  private heartbeats = new Map<string, { lastRequestMs: number; lastSeenAt: Date }>();

  private activeSlots(): number {
    let active = 0;
    for (const job of this.jobs.values()) if (ACTIVE_STATUSES.includes(job.status) && job.startedAt) active++;
    for (const list of this.remediations.values()) for (const r of list) if (r.status === "applied") active++;
    return active;
  }

  private waiting(): JobRecord[] {
    return [...this.jobs.values()]
      .filter((j) => j.status === "queued" && !j.startedAt)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  }

  private resetToWaiting(job: JobRecord, now: Date) {
    Object.assign(job, {
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
      updatedAt: now,
    });
  }

  async createWithQuota(data: NewJob, config: QuotaConfig, now: Date = new Date()): Promise<CreateJobWithQuotaResult> {
    return this.withLock(async () => {
      await this.reapStale(now, config);
      const oneHourAgo = new Date(now.getTime() - 3600_000);
      const oneDayAgo = new Date(now.getTime() - 86400_000);
      const counts = { waiting: this.waiting().length, ipHourly: 0, ipDaily: 0, globalDaily: 0 };

      for (const job of this.jobs.values()) {
        if (job.createdAt < oneDayAgo) continue;
        counts.globalDaily++;
        if (data.clientIpHash && job.clientIpHash === data.clientIpHash) {
          counts.ipDaily++;
          if (job.createdAt >= oneHourAgo) counts.ipHourly++;
        }
      }

      const limit = evaluateQuota(data.clientIpHash ? counts : { waiting: counts.waiting, globalDaily: counts.globalDaily }, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };
      const job = await this.create(data);
      return { ok: true, job };
    });
  }

  async requeueWithQuota(
    id: string,
    from: readonly ScanStatus[],
    maxAttempts: number,
    config: QuotaConfig,
    now: Date = new Date(),
  ): Promise<SlotReservation> {
    return this.withLock(async () => {
      await this.reapStale(now, config);
      const job = this.jobs.get(id);
      if (!job || !from.includes(job.status) || job.attempts >= maxAttempts) return { ok: false };
      const limit = evaluateQuota({ waiting: this.waiting().length }, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };
      this.resetToWaiting(job, now);
      return { ok: true };
    });
  }

  async claimNextScan(executor: ScanExecutor, config: QuotaConfig, now: Date = new Date(), opts?: { minWaitMs?: number }) {
    return this.withLock(async () => {
      await this.reapStale(now, config);
      if (!evaluateQuota({ active: this.activeSlots() }, config).allowed) return null;
      const cutoff = now.getTime() - (opts?.minWaitMs ?? 0);
      const next = this.waiting().find((j) => j.updatedAt.getTime() <= cutoff);
      if (!next) return null;
      const lease = executor.kind === "warm" ? `${WARM_LEASE_PREFIX}${executor.workerId}:${randomBytes(6).toString("hex")}` : `gha:${randomBytes(6).toString("hex")}`;
      Object.assign(next, { startedAt: now, workflowRunId: lease, attempts: next.attempts + 1, updatedAt: now });
      return { job: next, lease };
    });
  }

  async queuePosition(jobId: string) {
    const list = this.waiting();
    const i = list.findIndex((j) => j.id === jobId);
    return i === -1 ? null : i + 1;
  }

  async renewLease(lease: string, now: Date = new Date()) {
    let n = 0;
    for (const job of this.jobs.values()) {
      if (job.workflowRunId === lease && ACTIVE_STATUSES.includes(job.status)) {
        job.updatedAt = now;
        n++;
      }
    }
    for (const list of this.remediations.values()) {
      for (const r of list) {
        if (r.status === "applied" && verificationClaimOf(r.approvedOperations)?.lease === lease) {
          r.updatedAt = now;
          n++;
        }
      }
    }
    return n;
  }

  async recordWorkerHeartbeat(input: WorkerHeartbeatInput, now: Date = new Date()) {
    const prev = this.heartbeats.get(input.workerId);
    if (prev && input.requestMs <= prev.lastRequestMs) return false;
    this.heartbeats.set(input.workerId, { lastRequestMs: input.requestMs, lastSeenAt: now });
    return true;
  }

  async warmWorkerHealthy(now: Date, healthyMs: number) {
    return [...this.heartbeats.values()].some((h) => now.getTime() - h.lastSeenAt.getTime() <= healthyMs);
  }

  async transition(id: string, from: readonly ScanStatus[], patch: JobPatch): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job || !from.includes(job.status)) return false;
    Object.assign(job, patch, { updatedAt: new Date() });
    return true;
  }

  async reapStale(now: Date, config: QuotaConfig): Promise<number> {
    const leaseExpired = now.getTime() - config.warmLeaseMs;
    const jobExpired = now.getTime() - config.jobTimeoutMs;
    const queueExpired = now.getTime() - config.queueTimeoutMs;
    let reaped = 0;
    for (const job of this.jobs.values()) {
      const t = job.updatedAt.getTime();
      if (!ACTIVE_STATUSES.includes(job.status)) continue;
      if (!job.startedAt) {
        if (job.status === "queued" && t < queueExpired) {
          Object.assign(job, { status: "failed", failureCategory: "queue_timeout", errorMessage: "No scan worker became available in time. Please retry the scan.", completedAt: now, updatedAt: now });
          reaped++;
        }
      } else if (isWarmLease(job.workflowRunId) && t < leaseExpired) {
        if (job.attempts < MAX_WARM_ATTEMPTS) {
          this.findings.set(job.id, []);
          this.resetToWaiting(job, now);
        } else {
          Object.assign(job, STALE_JOB_PATCH, { completedAt: now, updatedAt: now });
        }
        reaped++;
      } else if (!isWarmLease(job.workflowRunId) && t < jobExpired) {
        Object.assign(job, STALE_JOB_PATCH, { completedAt: now, updatedAt: now });
        reaped++;
      }
    }
    for (const list of this.remediations.values()) {
      for (const r of list) {
        if (r.status !== "applied") continue;
        const claim = verificationClaimOf(r.approvedOperations);
        if (isWarmLease(claim?.lease) && r.updatedAt.getTime() < leaseExpired) {
          r.approvedOperations = withVerificationClaim(r.approvedOperations, null);
          reaped++;
        } else if (!isWarmLease(claim?.lease) && r.updatedAt.getTime() < jobExpired) {
          Object.assign(r, {
            status: "failed",
            rescanStatus: "failed",
            rescanSummary: {
              targetResolved: false,
              originalFindingsCount: 0,
              postRescanFindingsCount: 0,
              newFindingsCount: 0,
              resolvedFingerprints: [],
              remainingFingerprints: [],
              regressions: [],
              reason: "verification_timeout",
            },
            updatedAt: now,
          });
          reaped++;
        }
      }
    }
    return reaped;
  }

  /** Test helper: pretend a job or remediation last reported progress at `at`. */
  backdate(id: string, at: Date): void {
    const job = this.jobs.get(id);
    if (job) job.updatedAt = at;
    for (const list of this.remediations.values()) {
      for (const r of list) if (r.id === id) r.updatedAt = at;
    }
  }

  async create(data: NewJob): Promise<JobRecord> {
    const id = data.id ?? newJobId();
    const record: JobRecord = {
      id,
      status: "queued",
      owner: data.owner,
      repo: data.repo,
      repositoryUrl: data.repositoryUrl,
      defaultBranch: null,
      commitSha: null,
      description: null,
      repoSizeKb: null,
      stars: null,
      primaryLanguage: null,
      archiveBytes: null,
      fileCount: null,
      unpackedBytes: null,
      failureCategory: null,
      errorMessage: null,
      gitleaksStatus: null,
      gitleaksDurationMs: null,
      gitleaksError: null,
      semgrepStatus: null,
      semgrepDurationMs: null,
      semgrepError: null,
      osvStatus: null,
      osvDurationMs: null,
      osvError: null,
      scannerVersions: null,
      scanCoverage: null,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      clientIpHash: data.clientIpHash ?? null,
      workflowRunId: null,
      workflowRunUrl: null,
      attempts: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
      startedAt: null,
      completedAt: null,
      expiresAt: data.expiresAt,
    };
    this.jobs.set(id, record);
    return record;
  }

  async get(id: string): Promise<JobRecord | null> {
    return this.jobs.get(id) || null;
  }

  async claim(id: string): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job || job.status !== "queued") return false;
    job.status = "retrieving";
    job.startedAt = new Date();
    job.attempts++;
    return true;
  }

  async claimForScan(id: string): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job) return false;
    job.status = "scanning";
    return true;
  }

  async update(id: string, patch: JobPatch): Promise<void> {
    const job = this.jobs.get(id);
    if (!job) return;
    Object.assign(job, patch, { updatedAt: new Date() });
  }

  async requeue(id: string, maxAttempts: number): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job) return false;
    if (!["download_failed", "failed"].includes(job.status)) return false;
    if (job.attempts >= maxAttempts) return false;
    job.status = "queued";
    job.failureCategory = null;
    job.errorMessage = null;
    return true;
  }

  async deleteExpired(now: Date): Promise<number> {
    let count = 0;
    for (const [id, job] of this.jobs) {
      if (job.expiresAt < now) {
        this.jobs.delete(id);
        count++;
      }
    }
    return count;
  }

  async saveFindings(jobId: string, items: NormalizedFinding[]): Promise<void> {
    const existing = this.findings.get(jobId) || [];
    const converted: FindingRecord[] = items.map((f, i) => ({
      id: f.id || `f-${existing.length + i + 1}`,
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
      vulnerabilityId: f.vulnerabilityId ?? null,
      remediation: f.remediation ?? null,
      packageInfo: f.packageInfo,
      metadata: f.metadata,
      createdAt: new Date(),
    }));
    this.findings.set(jobId, [...existing, ...converted]);
  }

  async getFindings(jobId: string): Promise<{ findings: FindingRecord[]; total: number }> {
    const list = this.findings.get(jobId) || [];
    return { findings: list, total: list.length };
  }

  async getFinding(jobId: string, findingId: string): Promise<FindingRecord | null> {
    const list = this.findings.get(jobId) || [];
    return list.find((f) => f.id === findingId) || null;
  }

  async saveFindingAiExplanation(jobId: string, findingId: string, aiExplanation: unknown): Promise<void> {
    const list = this.findings.get(jobId) || [];
    const item = list.find((f) => f.id === findingId);
    if (item) item.aiExplanation = aiExplanation;
  }



  async createRemediation(data: import("@/server/remediation/types").NewRemediation) {
    const record: import("@/server/remediation/types").RemediationRecord = {
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const list = this.remediations.get(data.scanJobId) || [];
    list.push(record);
    this.remediations.set(data.scanJobId, list);
    return record;
  }

  async getRemediation(scanJobId: string, remediationId: string) {
    const list = this.remediations.get(scanJobId) || [];
    return list.find((r) => r.id === remediationId) || null;
  }

  async listRemediations(scanJobId: string) {
    return this.remediations.get(scanJobId) || [];
  }

  async updateRemediation(
    scanJobId: string,
    remediationId: string,
    patch: Partial<import("@/server/remediation/types").RemediationRecord>,
  ) {
    const list = this.remediations.get(scanJobId) || [];
    const index = list.findIndex((r) => r.id === remediationId);
    if (index === -1) throw new Error("Remediation not found");
    const updated = {
      ...list[index],
      ...patch,
      updatedAt: new Date(),
    };
    list[index] = updated;
    return updated;
  }

  async transitionRemediation(
    scanJobId: string,
    remediationId: string,
    from: readonly RemediationStatus[],
    patch: Partial<RemediationRecord>,
  ) {
    const current = await this.getRemediation(scanJobId, remediationId);
    if (!current || !from.includes(current.status)) return null;
    return this.updateRemediation(scanJobId, remediationId, patch);
  }

  async beginRemediationVerification(
    scanJobId: string,
    remediationId: string,
    config: QuotaConfig,
    now: Date = new Date(),
  ): Promise<VerificationReservation> {
    return this.withLock(async () => {
      await this.reapStale(now, config);
      const limit = evaluateQuota({ active: this.activeSlots() }, config);
      if (!limit.allowed) return { ok: false, rateLimit: limit };
      const current = await this.getRemediation(scanJobId, remediationId);
      if (!current || current.status !== "approved" || !current.approvedAt) return { ok: false };
      const remediation = await this.updateRemediation(scanJobId, remediationId, {
        status: "applied",
        rescanStatus: null,
        rescanSummary: null,
      });
      return { ok: true, remediation };
    });
  }

  async assignVerification(scanJobId: string, remediationId: string, lease: string) {
    return this.withLock(async () => {
      const r = await this.getRemediation(scanJobId, remediationId);
      if (!r || r.status !== "applied" || verificationClaimOf(r.approvedOperations)) return false;
      r.approvedOperations = withVerificationClaim(r.approvedOperations, lease);
      return true;
    });
  }

  async claimNextVerification(workerId: string, config: QuotaConfig, now: Date = new Date()) {
    return this.withLock(async () => {
      await this.reapStale(now, config);
      const all = [...this.remediations.values()].flat().filter((r) => r.status === "applied" && !verificationClaimOf(r.approvedOperations));
      all.sort((a, b) => a.updatedAt.getTime() - b.updatedAt.getTime());
      const next = all[0];
      if (!next) return null;
      const lease = `${WARM_LEASE_PREFIX}${workerId}:${randomBytes(6).toString("hex")}`;
      next.approvedOperations = withVerificationClaim(next.approvedOperations, lease);
      next.updatedAt = now;
      return { job: this.jobs.get(next.scanJobId)!, remediation: next, lease };
    });
  }
}
