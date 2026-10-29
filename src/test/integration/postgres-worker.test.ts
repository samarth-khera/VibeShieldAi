/**
 * Warm-worker queue proofs against a real PostgreSQL server: atomic claims under contention, FIFO,
 * lease expiry/renewal, replay rejection, lease-bound callbacks and progressive result persistence.
 * Skipped unless VIBESHIELD_PG_TEST_URL points at a disposable, migrated database (tables are truncated).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { JobStore, QuotaConfig } from "@/server/job-store";
import { signCallbackPayload } from "@/server/callback-auth";
import type { ServerConfig } from "@/server/config";

const PG_URL = process.env.VIBESHIELD_PG_TEST_URL?.trim();
if (process.env.REQUIRE_POSTGRES === "1" && !PG_URL) {
  throw new Error("REQUIRE_POSTGRES=1 but VIBESHIELD_PG_TEST_URL is not set");
}
const CALLBACK_SECRET = "integration-callback-secret";
const WARM_SECRET = "integration-warm-secret";
const SHA = "b".repeat(40);

describe.skipIf(!PG_URL)("PostgreSQL warm-worker queue (live database)", () => {
  let prisma: PrismaClient;
  let store: JobStore;
  let config: ServerConfig;
  let handleScanCallback: (req: Request, id: string) => Promise<Response>;
  let handleWorkerClaim: (req: Request, deps: { store: JobStore; config: ServerConfig }) => Promise<Response>;

  const quota = (slots = 2): QuotaConfig => ({
    maxConcurrentHeavyScans: slots,
    maxQueuedScans: 50,
    maxScansPerIpHourly: 100,
    maxScansPerIpDaily: 100,
    globalDailyScanCap: 1000,
    jobTimeoutMs: 15 * 60_000,
    queueTimeoutMs: 30 * 60_000,
    warmLeaseMs: 60_000,
  });

  async function waitingJobs(n: number) {
    const ids: string[] = [];
    for (let i = 0; i < n; i++) {
      const r = await store.createWithQuota!(
        { owner: "octocat", repo: `r${i}`, repositoryUrl: `https://github.com/octocat/r${i}`, clientIpHash: `ip${i}`, expiresAt: new Date(Date.now() + 86400_000) },
        quota(),
      );
      if (!r.ok) throw new Error("setup");
      ids.push(r.job.id);
      await new Promise((res) => setTimeout(res, 5)); // distinct createdAt for FIFO checks
    }
    return ids;
  }

  const backdate = (id: string, minutes: number) =>
    prisma.$executeRawUnsafe(`UPDATE "ScanJob" SET "updatedAt" = now() - interval '${minutes} minutes' WHERE id = $1`, id);

  const callback = (id: string, body: Record<string, unknown>, secret = WARM_SECRET) => {
    const json = JSON.stringify(body);
    return handleScanCallback(
      new Request(`http://localhost/api/scans/${id}/callback`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-VibeShield-Signature": signCallbackPayload(json, secret) },
        body: json,
      }),
      id,
    );
  };

  const finding = (scanner: string, fp: string) => ({
    fingerprint: fp,
    scanner,
    ruleId: `${scanner}-rule`,
    category: scanner === "gitleaks" ? "Secrets" : "Code Analysis",
    severity: "high",
    title: `${scanner} finding`,
    description: "d",
    filePath: "a.txt",
    startLine: 1,
    endLine: 1,
    redactedEvidence: null,
  });

  beforeAll(async () => {
    process.env.DATABASE_URL = PG_URL;
    process.env.DATABASE_URL_UNPOOLED = PG_URL;
    process.env.SCAN_CALLBACK_SECRET = CALLBACK_SECRET;
    process.env.WARM_WORKER_SECRET = WARM_SECRET;
    process.env.WARM_WORKER_ENABLED = "true";
    const db = await import("@/server/db");
    prisma = db.prisma;
    store = db.prismaJobStore;
    config = { ...(await import("@/server/config")).getConfig(), ...quota() };
    handleScanCallback = (await import("@/server/scan-callbacks")).handleScanCallback;
    handleWorkerClaim = (await import("@/server/worker-api")).handleWorkerClaim;
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe('TRUNCATE "Remediation", "Finding", "ScanJob", "WorkerHeartbeat" CASCADE');
  });

  afterAll(async () => {
    await prisma?.$disconnect();
  });

  it("stores a remediation whose explanation exceeds the 500-character column instead of failing with P2000", async () => {
    // Production regression (2026-10-29): a 594-character npm explanation made prisma.remediation.create
    // throw P2000, so the eligible fix's preview returned HTTP 500 and nothing was saved.
    const [jobId] = await waitingJobs(1);
    const long = `${"multer 2.5.0 fixes all advisories. ".repeat(17)}end`;
    expect(long.length).toBeGreaterThan(500);
    const created = await store.createRemediation({
      id: randomUUID(),
      scanJobId: jobId,
      status: "preview",
      findingFingerprints: ["fp-a"],
      commitSha: "a".repeat(40),
      patchSummary: long,
      unifiedDiff: "",
      affectedFiles: ["backend/package-lock.json"],
      eligibility: "potentially_breaking",
      eligibilityReason: long,
      requiresRotation: false,
      warnings: [],
      approvedAt: null,
      rescanStatus: null,
      rescanSummary: null,
      branchName: null,
      pullRequestUrl: null,
    });
    expect(created.eligibilityReason).toHaveLength(500);
    expect(created.eligibilityReason.endsWith("…")).toBe(true);
    expect(created.patchSummary).toHaveLength(500);
    const updated = await store.updateRemediation(jobId, created.id, { eligibilityReason: long });
    expect(updated.eligibilityReason).toHaveLength(500);
  });

  it("racing claims from two warm workers and the Actions pump never exceed the cap or claim a job twice", async () => {
    await waitingJobs(6);
    const executors = [
      { kind: "warm" as const, workerId: "worker-a" },
      { kind: "warm" as const, workerId: "worker-b" },
      { kind: "github-actions" as const },
    ];
    const claims = await Promise.all(Array.from({ length: 21 }, (_, i) => store.claimNextScan!(executors[i % 3], quota(2))));
    const won = claims.filter((c) => c !== null);
    expect(won).toHaveLength(2);
    expect(new Set(won.map((c) => c!.job.id)).size).toBe(2);
    expect(await prisma.scanJob.count({ where: { startedAt: { not: null } } })).toBe(2);
    expect(await prisma.scanJob.count({ where: { status: "queued", startedAt: null } })).toBe(4);

    // Freeing one slot admits exactly one more, even under contention.
    await prisma.scanJob.update({ where: { id: won[0]!.job.id }, data: { status: "completed" } });
    const next = await Promise.all(Array.from({ length: 9 }, (_, i) => store.claimNextScan!(executors[i % 3], quota(2))));
    expect(next.filter(Boolean)).toHaveLength(1);
  });

  it("claims in submission order and reports queue positions", async () => {
    const ids = await waitingJobs(4);
    expect(await store.queuePosition!(ids[2])).toBe(3);
    const a = await store.claimNextScan!({ kind: "warm", workerId: "w" }, quota(4));
    const b = await store.claimNextScan!({ kind: "github-actions" }, quota(4));
    expect([a!.job.id, b!.job.id]).toEqual([ids[0], ids[1]]);
    expect(await store.queuePosition!(ids[2])).toBe(1);
    expect(await store.queuePosition!(ids[0])).toBeNull();
  });

  it("re-queues a lost warm lease (dropping its partial findings) and fails after the attempt limit", async () => {
    const [id] = await waitingJobs(1);
    for (let attempt = 1; attempt <= 3; attempt++) {
      const c = await store.claimNextScan!({ kind: "warm", workerId: "w" }, quota());
      expect(c?.job.id).toBe(id);
      await prisma.finding.create({ data: { ...finding("semgrep", `fp-${attempt}`), scanJobId: id } });
      await backdate(id, 2);
      await store.reapStale(new Date(), quota());
      const job = await prisma.scanJob.findUnique({ where: { id } });
      if (attempt < 3) {
        expect(job).toMatchObject({ status: "queued", startedAt: null, workflowRunId: null, attempts: attempt });
        expect(await prisma.finding.count({ where: { scanJobId: id } })).toBe(0);
      } else {
        expect(job).toMatchObject({ status: "failed", failureCategory: "worker_timeout" });
      }
    }
  });

  it("a renewed lease is not reaped", async () => {
    await waitingJobs(1);
    const c = await store.claimNextScan!({ kind: "warm", workerId: "w" }, quota());
    await backdate(c!.job.id, 2);
    expect(await store.renewLease!(c!.lease)).toBe(1);
    await store.reapStale(new Date(), quota());
    expect((await prisma.scanJob.findUnique({ where: { id: c!.job.id } }))?.startedAt).not.toBeNull();
  });

  it("rejects replayed or reordered worker requests and tracks health", async () => {
    const hb = (requestMs: number) => store.recordWorkerHeartbeat!({ workerId: "w", requestMs, capacity: 1, activeJobs: 0 });
    expect(await hb(1000)).toBe(true);
    expect(await hb(1000)).toBe(false);
    expect(await hb(999)).toBe(false);
    expect(await hb(1001)).toBe(true);
    expect(await store.warmWorkerHealthy!(new Date(), 30_000)).toBe(true);
    expect(await store.warmWorkerHealthy!(new Date(Date.now() + 60_000), 30_000)).toBe(false);
  });

  it("only the current lease can write results; a superseded run is rejected", async () => {
    const [id] = await waitingJobs(1);
    const first = await store.claimNextScan!({ kind: "warm", workerId: "w" }, quota());
    await backdate(id, 2);
    await store.reapStale(new Date(), quota());
    const second = await store.claimNextScan!({ kind: "warm", workerId: "w" }, quota());
    const result = (lease: string) => ({ type: "scanner_result", jobId: id, lease, scanner: "gitleaks", status: "completed", durationMs: 5, at: new Date().toISOString(), findings: [] });

    expect((await callback(id, result(first!.lease))).status).toBe(409);
    expect((await callback(id, result(second!.lease))).status).toBe(200);
    // The Actions secret without a lease cannot touch a warm-owned job either.
    expect((await callback(id, { ...result(second!.lease), lease: undefined }, CALLBACK_SECRET)).status).toBe(409);
  });

  it("persists each scanner's findings as it finishes, idempotently, and keeps IDs through the final result", async () => {
    await waitingJobs(1);
    const { job, lease } = (await store.claimNextScan!({ kind: "warm", workerId: "w" }, quota()))!;
    const id = job.id;
    const at = () => new Date().toISOString();
    await callback(id, { type: "progress", jobId: id, lease, phase: "scanning", at: at() });

    const gitleaks = { type: "scanner_result", jobId: id, lease, scanner: "gitleaks", status: "completed", durationMs: 40, at: at(), findings: [finding("gitleaks", "fp-g1")] };
    expect((await (await callback(id, gitleaks)).json()).data.accepted).toBe(true);
    let row = await prisma.scanJob.findUnique({ where: { id } });
    expect(row).toMatchObject({ status: "scanning", gitleaksStatus: "completed", semgrepStatus: "running", osvStatus: "running" });
    const progress = (row!.scanCoverage as { progress: { revision: number; firstFindingAt?: string } }).progress;
    expect(progress.revision).toBe(1);
    expect(progress.firstFindingAt).toBeTruthy();
    const partialId = (await prisma.finding.findFirst({ where: { scanJobId: id, fingerprint: "fp-g1" } }))!.id;

    await callback(id, gitleaks); // duplicate delivery
    expect(await prisma.finding.count({ where: { scanJobId: id } })).toBe(1);

    await callback(id, { ...gitleaks, scanner: "semgrep", findings: [finding("semgrep", "fp-s1")] });
    expect(await prisma.finding.count({ where: { scanJobId: id } })).toBe(2); // gitleaks rows untouched

    const final = await callback(id, {
      jobId: id,
      lease,
      status: "completed",
      commitSha: SHA,
      gitleaksStatus: "completed",
      semgrepStatus: "completed",
      osvStatus: "completed",
      findings: [finding("gitleaks", "fp-g1"), finding("semgrep", "fp-s1")],
      scanCoverage: { scannersRun: ["gitleaks", "semgrep", "osv-scanner"], lockfilesFound: [], limitations: [] },
    });
    expect(final.status).toBe(200);
    expect((await prisma.finding.findFirst({ where: { scanJobId: id, fingerprint: "fp-g1" } }))!.id).toBe(partialId);

    // Late or duplicate events can never reopen or change a finished job.
    await callback(id, { ...gitleaks, findings: [] });
    await callback(id, { type: "progress", jobId: id, lease, phase: "retrieving", at: at() });
    row = await prisma.scanJob.findUnique({ where: { id } });
    expect(row?.status).toBe("completed");
    expect(await prisma.finding.count({ where: { scanJobId: id } })).toBe(2);
  });

  it("assigns a verification to exactly one executor and reclaims a lost warm lease", async () => {
    const [scanId] = await waitingJobs(1);
    await prisma.scanJob.update({ where: { id: scanId }, data: { status: "completed", commitSha: SHA } });
    const rid = randomUUID();
    await prisma.remediation.create({
      data: {
        id: rid, scanJobId: scanId, status: "approved", approvedAt: new Date(), approvedOperations: { approvedBy: "u" },
        findingFingerprints: ["fp"], commitSha: SHA, patchSummary: "p", unifiedDiff: "--- a/x\n+++ b/x\n", affectedFiles: ["x"],
        eligibility: "safe", eligibilityReason: "r",
      },
    });
    expect((await store.beginRemediationVerification!(scanId, rid, quota())).ok).toBe(true);

    const [warm, gha] = await Promise.all([
      store.claimNextVerification!("w", quota()),
      store.assignVerification!(scanId, rid, "gha:x"),
    ]);
    expect(Boolean(warm) !== gha).toBe(true); // exactly one executor owns it

    if (warm) {
      await prisma.$executeRawUnsafe(`UPDATE "Remediation" SET "updatedAt" = now() - interval '2 minutes' WHERE id = $1`, rid);
      await store.reapStale(new Date(), quota());
      expect(await store.assignVerification!(scanId, rid, "gha:y")).toBe(true); // lost warm lease released
    }
  });

  it("serves signed claims end to end and rejects unsigned or replayed requests", async () => {
    const [id] = await waitingJobs(1);
    const claimReq = (body: Record<string, unknown>, secret = WARM_SECRET) => {
      const json = JSON.stringify(body);
      return new Request("http://localhost/api/internal/worker/claim", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-VibeShield-Signature": signCallbackPayload(json, secret) },
        body: json,
      });
    };
    const body = { workerId: "w1", requestMs: Date.now(), capacity: 1, activeJobs: 0, accept: ["scan"] };
    expect((await handleWorkerClaim(claimReq(body, "wrong"), { store, config })).status).toBe(401);
    const res = await handleWorkerClaim(claimReq(body), { store, config });
    const work = (await res.json()).data.work;
    expect(work).toMatchObject({ kind: "scan", jobId: id, repositoryUrl: "https://github.com/octocat/r0" });
    expect(work.lease).toMatch(/^warm:w1:/);
    expect((await handleWorkerClaim(claimReq(body), { store, config })).status).toBe(409); // replay
    expect((await handleWorkerClaim(claimReq(body), { store, config: { ...config, warmWorkerEnabled: false } })).status).toBe(404);
  });
});
