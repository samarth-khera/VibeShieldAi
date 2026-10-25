import {
  newJobId,
  type JobRecord,
  type JobStore,
  type NewJob,
  type JobPatch,
  type FindingRecord,
  type CreateJobWithQuotaResult,
} from "@/server/job-store";
import type { NormalizedFinding } from "@/server/scanners/types";
import type { ServerConfig } from "@/server/config";

export class InMemoryJobStore implements JobStore {
  private jobs = new Map<string, JobRecord>();
  private findings = new Map<string, FindingRecord[]>();
  private mutex = Promise.resolve();

  async createWithQuota(
    data: NewJob,
    config: Pick<
      ServerConfig,
      "maxScansPerIpHourly" | "maxScansPerIpDaily" | "globalDailyScanCap" | "maxConcurrentHeavyScans" | "jobTimeoutMs"
    >,
    now: Date = new Date(),
  ): Promise<CreateJobWithQuotaResult> {
    let release: () => void;
    const nextMutex = new Promise<void>((resolve) => {
      release = resolve;
    });
    const currentMutex = this.mutex;
    this.mutex = nextMutex;

    await currentMutex;
    try {
      const activeThreshold = new Date(now.getTime() - config.jobTimeoutMs);
      const oneHourAgo = new Date(now.getTime() - 3600_000);
      const oneDayAgo = new Date(now.getTime() - 86400_000);

      let activeCount = 0;
      let ipHourlyCount = 0;
      let ipDailyCount = 0;
      let globalDailyCount = 0;

      for (const job of this.jobs.values()) {
        const createdAt = job.createdAt;
        if (
          ["queued", "retrieving", "ready_for_scan", "scanning"].includes(job.status) &&
          createdAt >= activeThreshold
        ) {
          activeCount++;
        }
        if (createdAt >= oneDayAgo) {
          globalDailyCount++;
          if (data.clientIpHash && job.clientIpHash === data.clientIpHash) {
            ipDailyCount++;
            if (createdAt >= oneHourAgo) {
              ipHourlyCount++;
            }
          }
        }
      }

      if (activeCount >= config.maxConcurrentHeavyScans) {
        return {
          ok: false,
          rateLimit: {
            allowed: false,
            retryAfterSeconds: 60,
            reason: "concurrency_limit",
            message:
              "A security scan is currently running. Free-tier quota allows 1 active scan at a time. Please retry in 1 minute.",
          },
        };
      }

      if (data.clientIpHash && ipHourlyCount >= config.maxScansPerIpHourly) {
        return {
          ok: false,
          rateLimit: {
            allowed: false,
            retryAfterSeconds: 1800,
            reason: "hourly_ip_limit",
            message: `Free-tier quota: maximum ${config.maxScansPerIpHourly} scan submissions per client IP per hour reached.`,
          },
        };
      }

      if (data.clientIpHash && ipDailyCount >= config.maxScansPerIpDaily) {
        return {
          ok: false,
          rateLimit: {
            allowed: false,
            retryAfterSeconds: 3600,
            reason: "daily_ip_limit",
            message: `Free-tier quota: maximum ${config.maxScansPerIpDaily} scan submissions per client IP per day reached.`,
          },
        };
      }

      if (globalDailyCount >= config.globalDailyScanCap) {
        return {
          ok: false,
          rateLimit: {
            allowed: false,
            retryAfterSeconds: 7200,
            reason: "global_daily_limit",
            message: `Global daily free-tier scan limit (${config.globalDailyScanCap} scans) reached. The queue resets in 24 hours.`,
          },
        };
      }

      const job = await this.create(data);
      return { ok: true, job };
    } finally {
      release!();
    }
  }

  async create(data: NewJob): Promise<JobRecord> {
    const id = newJobId();
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

  private remediations = new Map<string, import("@/server/remediation/types").RemediationRecord[]>();

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
}
