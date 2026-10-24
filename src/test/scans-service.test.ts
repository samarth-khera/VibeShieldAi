import { describe, it, expect, beforeEach } from "vitest";
import { submitScan, getScan, retryScan, type ScanDeps } from "@/server/scans-service";
import { newJobId, type JobRecord, type JobStore, type NewJob, type JobPatch } from "@/server/job-store";
import type { ServerConfig } from "@/server/config";

class InMemoryJobStore implements JobStore {
  private jobs = new Map<string, JobRecord>();

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

  async saveFindings(): Promise<void> {}
  async getFindings(): Promise<{ findings: []; total: 0 }> {
    return { findings: [], total: 0 };
  }
  async getFinding(): Promise<null> {
    return null;
  }
  async saveFindingAiExplanation(): Promise<void> {}
}

describe("scans-service API logic", () => {
  let store: InMemoryJobStore;
  let enqueued: { jobId: string; attempt: number }[];
  let config: ServerConfig;
  let deps: ScanDeps;

  beforeEach(() => {
    store = new InMemoryJobStore();
    enqueued = [];
    config = {
      maxArchiveBytes: 50 * 1024 * 1024,
      maxUnpackedBytes: 200 * 1024 * 1024,
      maxFileCount: 10000,
      maxRepoSizeKb: 200 * 1024,
      retrievalTimeoutMs: 30000,
      githubApiTimeoutMs: 5000,
      rateLimitMax: 10,
      rateLimitWindowSeconds: 3600,
      workerConcurrency: 2,
      jobTtlHours: 24,
    };
    deps = {
      store,
      config,
      enqueue: async (jobId, attempt) => {
        enqueued.push({ jobId, attempt });
      },
      rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: async () => true,
    };
  });

  it("submits a valid public GitHub URL and returns 202 Accepted", async () => {
    const req = new Request("http://localhost/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repositoryUrl: "https://github.com/facebook/react" }),
    });

    const res = await submitScan(req, deps);
    expect(res.status).toBe(202);
    const json = await res.json();
    expect(json.data.status).toBe("queued");
    expect(json.data.repository.owner).toBe("facebook");
    expect(json.data.repository.name).toBe("react");
    expect(json.data.scanPerformed).toBe(false);
    expect(enqueued.length).toBe(1);
  });

  it("rejects invalid repository URLs with 400 Bad Request", async () => {
    const req = new Request("http://localhost/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repositoryUrl: "https://evil.com/owner/repo" }),
    });

    const res = await submitScan(req, deps);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error.code).toBe("unsupported_host");
  });

  it("enforces rate limits", async () => {
    deps.rateLimit = async () => ({ allowed: false, retryAfterSeconds: 42 });

    const req = new Request("http://localhost/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repositoryUrl: "https://github.com/facebook/react" }),
    });

    const res = await submitScan(req, deps);
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("42");
  });

  it("retrieves a job by ID", async () => {
    const created = await store.create({
      owner: "vercel",
      repo: "next.js",
      repositoryUrl: "https://github.com/vercel/next.js",
      expiresAt: new Date(Date.now() + 86400000),
    });

    const res = await getScan(created.id, deps);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.data.id).toBe(created.id);
    expect(json.data.repository.name).toBe("next.js");
  });

  it("handles retry for retryable failed jobs", async () => {
    const job = await store.create({
      owner: "acme",
      repo: "test",
      repositoryUrl: "https://github.com/acme/test",
      expiresAt: new Date(Date.now() + 86400000),
    });
    await store.update(job.id, { status: "download_failed", failureCategory: "network_error", errorMessage: "Failed" });

    const res = await retryScan(job.id, deps);
    expect(res.status).toBe(202);
    const json = await res.json();
    expect(json.data.status).toBe("queued");
  });
});
