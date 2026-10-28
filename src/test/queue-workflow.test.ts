import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { spawn } from "node:child_process";
import path from "node:path";
import { getScan, retryScan, startScan, submitScan, type ScanDeps } from "@/server/scans-service";
import { getConfig, type ServerConfig } from "@/server/config";
import { verifyCallbackSignature } from "@/server/callback-auth";
import { InMemoryJobStore } from "./mock-store";

const ROOT = path.resolve(__dirname, "../..");

function depsFor(store: InMemoryJobStore, overrides: Partial<ServerConfig> = {}): ScanDeps & { enqueue: ReturnType<typeof vi.fn> } {
  return {
    store,
    config: {
      ...getConfig(),
      maxConcurrentHeavyScans: 2,
      maxScansPerIpHourly: 100,
      maxScansPerIpDaily: 100,
      globalDailyScanCap: 1000,
      jobTimeoutMs: 15 * 60_000,
      ...overrides,
    },
    enqueue: vi.fn().mockResolvedValue(undefined),
    rateLimit: vi.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
    workerOnline: vi.fn().mockResolvedValue(true),
    verifyTurnstile: vi.fn().mockResolvedValue({ success: true }),
  };
}

const submit = (deps: ScanDeps, i: number) =>
  submitScan(
    new Request("http://localhost/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-real-ip": `203.0.113.${i}` },
      body: JSON.stringify({ repositoryUrl: `https://github.com/octocat/repo-${i}` }),
    }),
    deps,
  );

describe("Bounded scan concurrency and explicit queue states", () => {
  it("admits exactly the configured number of concurrent scans and rejects the rest explicitly", async () => {
    const deps = depsFor(new InMemoryJobStore());
    const responses = await Promise.all(Array.from({ length: 10 }, (_, i) => submit(deps, i)));
    expect(responses.filter((r) => r.status === 202)).toHaveLength(2);
    const rejected = responses.filter((r) => r.status === 429);
    expect(rejected).toHaveLength(8);
    const body = await rejected[0].json();
    expect(body.error.code).toBe("concurrency_limit");
    expect(body.error.message).toMatch(/All 2 free-tier scan worker slots are busy, so this request was not queued/);
    expect(rejected[0].headers.get("Retry-After")).toBe("60");
    // Only admitted scans were dispatched; nothing was silently dropped after acceptance.
    expect(deps.enqueue).toHaveBeenCalledTimes(2);
  });

  it("a retry cannot bypass the cap, and a rejected retry leaves the job in its failed state", async () => {
    const store = new InMemoryJobStore();
    const deps = depsFor(store, { maxConcurrentHeavyScans: 1 });
    const first = await (await submit(deps, 1)).json();
    await store.update(first.data.id, { status: "failed" });
    await submit(deps, 2); // occupies the only slot

    const res = await retryScan(first.data.id, deps);
    expect(res.status).toBe(429);
    expect((await res.json()).error.code).toBe("concurrency_limit");
    expect((await store.get(first.data.id))?.status).toBe("failed");
    expect(deps.enqueue).toHaveBeenCalledTimes(2);
  });

  it("does not dispatch a duplicate workflow for a job that is already queued or running", async () => {
    const store = new InMemoryJobStore();
    const deps = depsFor(store);
    const { data } = await (await submit(deps, 1)).json();
    for (const status of ["queued", "retrieving", "scanning"] as const) {
      await store.update(data.id, { status });
      const res = await startScan(data.id, deps);
      expect(res.status).toBe(409);
    }
    expect(deps.enqueue).toHaveBeenCalledTimes(1);
  });

  it("re-dispatches a finished scan through the same slot reservation", async () => {
    const store = new InMemoryJobStore();
    const deps = depsFor(store);
    const { data } = await (await submit(deps, 1)).json();
    await store.update(data.id, { status: "completed" });
    const res = await startScan(data.id, deps);
    expect(res.status).toBe(202);
    expect((await res.json()).data.status).toBe("queued");
    expect(deps.enqueue).toHaveBeenCalledTimes(2);
  });

  it("fails a job whose worker stopped reporting and frees its slot for the next user", async () => {
    const store = new InMemoryJobStore();
    const deps = depsFor(store, { maxConcurrentHeavyScans: 1 });
    const { data } = await (await submit(deps, 1)).json();
    store.backdate(data.id, new Date(Date.now() - 16 * 60_000));

    const view = await (await getScan(data.id, deps)).json();
    expect(view.data.status).toBe("failed");
    expect(view.data.failure.category).toBe("worker_timeout");
    expect((await submit(deps, 2)).status).toBe(202);
  });

  it("marks a scan failed (not pending) when the workflow cannot be dispatched", async () => {
    const store = new InMemoryJobStore();
    const deps = depsFor(store);
    deps.enqueue.mockRejectedValueOnce(new Error("dispatch failed"));
    const res = await submit(deps, 1);
    expect(res.status).toBe(503);
    const [job] = await Promise.all([...(store as unknown as { jobs: Map<string, { status: string; failureCategory: string }> }).jobs.values()]);
    expect(job.status).toBe("failed");
    expect(job.failureCategory).toBe("queue_unavailable");
  });
});

describe("Scanner worker workflow definition", () => {
  const yml = readFileSync(path.join(ROOT, ".github/workflows/scanner-worker.yml"), "utf8");
  const installer = readFileSync(path.join(ROOT, "scripts/ci/install-scanners.sh"), "utf8");
  const requirements = readFileSync(path.join(ROOT, ".github/scanner-requirements.txt"), "utf8");
  const workflowLevel = yml.slice(0, yml.indexOf("\njobs:"));

  it("uses a per-job concurrency group so pending runs never replace each other", () => {
    const group = yml.match(/concurrency:\s*\n\s*group:\s*(.+)/)?.[1] ?? "";
    expect(group).toContain("inputs.job_id");
    expect(group).toContain("inputs.remediation_id");
    expect(yml).toMatch(/cancel-in-progress:\s*false/);
  });

  it("caches tools in a runner-owned directory with versioned keys and verified checksums", () => {
    expect(yml).not.toContain("/usr/local/bin");
    expect(yml).toContain("~/.vibeshield/bin");
    expect(yml).toMatch(/key: scanner-tools-v\d+-.*gitleaks\$\{\{ env.GITLEAKS_VERSION \}\}-osv\$\{\{ env.OSV_SCANNER_VERSION \}\}/);
    expect(installer).toContain("sha256sum --check");
    expect(installer).toMatch(/GITLEAKS_BINARY_SHA256="[0-9a-f]{64}"/);
    expect(installer).toMatch(/OSV_SCANNER_SHA256="[0-9a-f]{64}"/);
  });

  it("pins Semgrep consistently and uses the supported pip cache configuration", () => {
    const pinned = yml.match(/SEMGREP_VERSION:\s*([0-9.]+)/)?.[1];
    expect(requirements).toContain(`semgrep==${pinned}`);
    expect(yml).toMatch(/cache: pip\s*\n\s*cache-dependency-path: \.github\/scanner-requirements\.txt/);
  });

  it("has no OSV offline-database step that the online scan path would never use", () => {
    expect(yml).not.toContain("--download-offline-databases");
    expect(yml).not.toContain("osv-scanner/");
  });

  it("keeps the callback secret out of workflow-level env and dependency installation", () => {
    expect(workflowLevel).not.toContain("secrets.");
    expect(yml).toContain("npm ci --ignore-scripts");
    expect(yml).not.toMatch(/prisma generate/);
  });

  it("always reports setup failures and cancellations so jobs cannot stay pending", () => {
    expect(yml).toMatch(/if: failure\(\) \|\| cancelled\(\)\s*\n[\s\S]*?post-worker-status\.mjs failed/);
    expect(yml).toMatch(/post-worker-status\.mjs started/);
  });
});

describe("Dependency-free worker status reporter", () => {
  async function runReporter(args: string[], env: Record<string, string>) {
    const received: { body: string; signature: string | undefined }[] = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received.push({ body, signature: req.headers["x-vibeshield-signature"] as string | undefined });
        res.writeHead(200).end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      await new Promise<void>((resolve, reject) => {
        const child = spawn(process.execPath, [path.join(ROOT, "scripts/ci/post-worker-status.mjs"), ...args], {
          env: {
            NODE_ENV: "test",
            PATH: process.env.PATH ?? "",
            CALLBACK_SECRET: "s3cret",
            CALLBACK_URL: `http://127.0.0.1:${port}/cb`,
            GITHUB_RUN_ID: "42",
            GITHUB_REPOSITORY: "o/r",
            ...env,
          },
        });
        child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`exit ${code}`))));
      });
    } finally {
      server.close();
    }
    return received;
  }

  it("reports a signed scan failure the callback route accepts", async () => {
    const [msg] = await runReporter(["failed", "worker_failed", "setup broke"], { WORKER_MODE: "scan", JOB_ID: "j".repeat(32) });
    expect(verifyCallbackSignature(msg.body, msg.signature, "s3cret").valid).toBe(true);
    expect(JSON.parse(msg.body)).toMatchObject({ jobId: "j".repeat(32), status: "failed", failureCategory: "worker_failed", findings: [] });
  });

  it("reports a signed verification failure that can never claim resolution", async () => {
    const [msg] = await runReporter(["failed"], { WORKER_MODE: "verify", JOB_ID: "j".repeat(32), REMEDIATION_ID: "r-1" });
    expect(verifyCallbackSignature(msg.body, msg.signature, "s3cret").valid).toBe(true);
    const body = JSON.parse(msg.body);
    expect(body.rescanStatus).toBe("failed");
    expect(body.summary).toMatchObject({ targetResolved: false, resolvedFingerprints: [], reason: "worker_failed" });
  });

  it("sends a worker_started heartbeat in scan mode only", async () => {
    const [msg] = await runReporter(["started"], { WORKER_MODE: "scan", JOB_ID: "j".repeat(32) });
    expect(JSON.parse(msg.body)).toMatchObject({ type: "progress", phase: "worker_started" });
    expect(await runReporter(["started"], { WORKER_MODE: "verify", JOB_ID: "j".repeat(32) })).toHaveLength(0);
  });

  it("refuses to send signed payloads to a non-HTTPS remote callback", async () => {
    const received = await runReporter(["failed"], { WORKER_MODE: "scan", JOB_ID: "j".repeat(32), CALLBACK_URL: "http://example.com/cb" });
    expect(received).toHaveLength(0);
  });
});
