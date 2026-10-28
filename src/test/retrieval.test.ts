import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { runRetrieval, type RetrievalDeps } from "@/server/retrieval";
import type { JobRecord, JobStore, NewJob, JobPatch } from "@/server/job-store";
import { newJobId } from "@/server/job-store";
import type { ServerConfig } from "@/server/config";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";

class MockJobStore implements JobStore {
  public jobs = new Map<string, JobRecord>();

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
      clientIpHash: null,
      workflowRunId: null,
      workflowRunUrl: null,
      expiresAt: data.expiresAt,
    };
    this.jobs.set(id, record);
    return record;
  }

  async get(id: string): Promise<JobRecord | null> {
    return this.jobs.get(id) || null;
  }

  async claim(id: string): Promise<boolean> {
    const j = this.jobs.get(id);
    if (!j || j.status !== "queued") return false;
    j.status = "retrieving";
    j.startedAt = new Date();
    j.attempts++;
    return true;
  }

  async claimForScan(id: string): Promise<boolean> {
    const j = this.jobs.get(id);
    if (!j) return false;
    j.status = "scanning";
    return true;
  }

  async update(id: string, patch: JobPatch): Promise<void> {
    const j = this.jobs.get(id);
    if (!j) return;
    Object.assign(j, patch, { updatedAt: new Date() });
  }

  async requeue(id: string): Promise<boolean> {
    const j = this.jobs.get(id);
    if (!j) return false;
    j.status = "queued";
    return true;
  }

  async deleteExpired(): Promise<number> {
    return 0;
  }

  async saveFindings(): Promise<void> {}
  async getFindings(): Promise<{ findings: []; total: 0 }> {
    return { findings: [], total: 0 };
  }
  async getFinding(): Promise<null> {
    return null;
  }
  async saveFindingAiExplanation(): Promise<void> {}
  async createRemediation(): Promise<never> { throw new Error("not implemented"); }
  async getRemediation(): Promise<null> { return null; }
  async listRemediations(): Promise<[]> { return []; }
  async updateRemediation(): Promise<never> { throw new Error("not implemented"); }
  async transitionRemediation(): Promise<null> { return null; }
  async transition(id: string, from: readonly JobRecord["status"][], patch: Partial<JobRecord>): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job || !from.includes(job.status)) return false;
    Object.assign(job, patch, { updatedAt: new Date() });
    return true;
  }
  async reapStale(): Promise<number> { return 0; }
}

describe("runRetrieval pipeline", () => {
  let store: MockJobStore;
  let testTmpDir: string;
  let config: ServerConfig;

  beforeEach(async () => {
    store = new MockJobStore();
    testTmpDir = await mkdtemp(path.join(tmpdir(), "retrieval-test-"));
    config = {
      maxArchiveBytes: 10 * 1024 * 1024,
      maxUnpackedBytes: 20 * 1024 * 1024,
      maxFileCount: 50,
      maxRepoSizeKb: 100 * 1024,
      retrievalTimeoutMs: 5000,
      githubApiTimeoutMs: 2000,
      rateLimitMax: 10,
      rateLimitWindowSeconds: 3600,
      workerConcurrency: 1,
      jobTtlHours: 24,
      maxScansPerIpHourly: 3,
      maxScansPerIpDaily: 5,
      globalDailyScanCap: 20,
      maxConcurrentHeavyScans: 1,
      jobTimeoutMs: 900_000,
      scanDispatchBackend: "bullmq",
      githubRepository: "samarth-khera/VibeShieldAi",
      githubWorkflowRef: "main",
      appUrl: "http://localhost:3000",
    };
  });

  afterEach(async () => {
    await rm(testTmpDir, { recursive: true, force: true });
  });

  async function makeSampleTarball(): Promise<Buffer> {
    const staging = await mkdtemp(path.join(tmpdir(), "tar-make-"));
    const repoDir = path.join(staging, "repo-root-sha123");
    await (await import("node:fs/promises")).mkdir(repoDir, { recursive: true });
    await (await import("node:fs/promises")).writeFile(path.join(repoDir, "app.ts"), "export const x = 1;");
    const chunks: Buffer[] = [];
    const stream = tar.create({ gzip: true, cwd: staging }, ["repo-root-sha123"]);
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    await rm(staging, { recursive: true, force: true });
    return Buffer.concat(chunks);
  }

  it("completes retrieval successfully and marks ready_for_scan", async () => {
    const job = await store.create({
      owner: "acme",
      repo: "demo-app",
      repositoryUrl: "https://github.com/acme/demo-app",
      expiresAt: new Date(Date.now() + 86400000),
    });

    const tarBuffer = await makeSampleTarball();

    const mockFetch = async (url: string) => {
      if (url.includes("/commits/")) {
        return new Response("0123456789abcdef0123456789abcdef01234567", { status: 200 });
      }
      if (url.includes("/tarball/")) {
        return new Response(new Uint8Array(tarBuffer), {
          status: 200,
          headers: { "content-length": String(tarBuffer.length) },
        });
      }
      return new Response(
        JSON.stringify({
          full_name: "acme/demo-app",
          default_branch: "main",
          description: "A demo application",
          size: 120,
          stargazers_count: 5,
          language: "TypeScript",
          private: false,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const deps: RetrievalDeps = {
      store,
      config,
      fetchImpl: mockFetch as never,
      tmpRoot: testTmpDir,
    };

    const outcome = await runRetrieval(job.id, deps);
    expect(outcome).toBe("ready_for_scan");

    const updated = await store.get(job.id);
    expect(updated?.status).toBe("ready_for_scan");
    expect(updated?.fileCount).toBe(1);
    expect(updated?.commitSha).toBe("0123456789abcdef0123456789abcdef01234567");
    expect(updated?.defaultBranch).toBe("main");

    // Temp workspace should be cleaned up
    const remaining = await readdir(testTmpDir);
    expect(remaining.length).toBe(0);
  });

  it("handles 404 repository as invalid_repository", async () => {
    const job = await store.create({
      owner: "acme",
      repo: "nonexistent",
      repositoryUrl: "https://github.com/acme/nonexistent",
      expiresAt: new Date(Date.now() + 86400000),
    });

    const mockFetch = async () => new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });

    const deps: RetrievalDeps = {
      store,
      config,
      fetchImpl: mockFetch as never,
      tmpRoot: testTmpDir,
    };

    const outcome = await runRetrieval(job.id, deps);
    expect(outcome).toBe("failed");

    const updated = await store.get(job.id);
    expect(updated?.status).toBe("invalid_repository");
    expect(updated?.failureCategory).toBe("not_found_or_private");
  });
});
