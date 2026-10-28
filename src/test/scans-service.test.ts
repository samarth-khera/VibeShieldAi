import { describe, it, expect, beforeEach } from "vitest";
import { submitScan, getScan, retryScan, type ScanDeps } from "@/server/scans-service";
import type { ServerConfig } from "@/server/config";

import { InMemoryJobStore } from "./mock-store";

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
      maxScansPerIpHourly: 3,
      maxScansPerIpDaily: 5,
      globalDailyScanCap: 20,
      maxConcurrentHeavyScans: 1,
      jobTimeoutMs: 900_000,
      maxQueuedScans: 10,
      queueTimeoutMs: 1_800_000,
      warmWorkerEnabled: false,
      warmLeaseMs: 60_000,
      warmWorkerHealthyMs: 30_000,
      warmWorkerGraceMs: 10_000,
      scanDispatchBackend: "bullmq",
      githubRepository: "samarth-khera/VibeShieldAi",
      githubWorkflowRef: "main",
      appUrl: "http://localhost:3000",
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
