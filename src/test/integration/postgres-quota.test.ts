/**
 * Race-safety proof against a real PostgreSQL server (the in-memory store cannot prove the advisory
 * lock). Skipped unless VIBESHIELD_PG_TEST_URL points at a disposable, migrated database:
 *
 *   VIBESHIELD_PG_TEST_URL=postgresql://... npm run test:postgres
 *
 * Every table is truncated between tests, so never point this at a real deployment.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { JobStore, QuotaConfig } from "@/server/job-store";
import { signCallbackPayload } from "@/server/callback-auth";

const PG_URL = process.env.VIBESHIELD_PG_TEST_URL?.trim();
if (process.env.REQUIRE_POSTGRES === "1" && !PG_URL) {
  throw new Error("REQUIRE_POSTGRES=1 but VIBESHIELD_PG_TEST_URL is not set");
}
const SECRET = "integration-callback-secret";

describe.skipIf(!PG_URL)("PostgreSQL heavy-work slot reservation (live database)", () => {
  let prisma: PrismaClient;
  let store: JobStore;
  let callbackPost: (req: Request, props: { params: Promise<{ id: string }> }) => Promise<Response>;

  const quota = (slots: number): QuotaConfig => ({
    maxConcurrentHeavyScans: slots,
    maxScansPerIpHourly: 100,
    maxScansPerIpDaily: 100,
    globalDailyScanCap: 1000,
    maxQueuedScans: 50,
    jobTimeoutMs: 15 * 60_000,
    queueTimeoutMs: 30 * 60_000,
    warmLeaseMs: 60_000,
  });

  const newJob = (i: number) => ({
    owner: "octocat",
    repo: `repo-${i}`,
    repositoryUrl: `https://github.com/octocat/repo-${i}`,
    clientIpHash: `ip-${i}`,
    expiresAt: new Date(Date.now() + 86400_000),
  });

  beforeAll(async () => {
    process.env.DATABASE_URL = PG_URL;
    process.env.DATABASE_URL_UNPOOLED = PG_URL;
    process.env.SCAN_CALLBACK_SECRET = SECRET;
    const db = await import("@/server/db");
    prisma = db.prisma;
    store = db.prismaJobStore;
    callbackPost = (await import("@/app/api/scans/[id]/callback/route")).POST;
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe('TRUNCATE "Remediation", "Finding", "ScanJob" CASCADE');
  });

  afterAll(async () => {
    await prisma?.$disconnect();
  });

  it("bounds the waiting queue exactly under 12 simultaneous submissions", async () => {
    const results = await Promise.all(
      Array.from({ length: 12 }, (_, i) => store.createWithQuota!(newJob(i), { ...quota(2), maxQueuedScans: 5 })),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(5);
    const rejected = results.filter((r) => !r.ok);
    expect(rejected).toHaveLength(7);
    for (const r of rejected) if (!r.ok) expect(r.rateLimit.reason).toBe("queue_full");
    expect(await prisma.scanJob.count({ where: { status: "queued", startedAt: null } })).toBe(5);
  });

  it("counts remediation verifications and executing scans against one shared cap", async () => {
    const done = await store.createWithQuota!(newJob(100), quota(5));
    if (!done.ok) throw new Error("setup failed");
    await prisma.scanJob.update({ where: { id: done.job.id }, data: { status: "completed", commitSha: "a".repeat(40) } });
    const remediationIds: string[] = [];
    for (let i = 0; i < 5; i++) {
      const id = randomUUID();
      remediationIds.push(id);
      await prisma.remediation.create({
        data: {
          id,
          scanJobId: done.job.id,
          status: "approved",
          approvedAt: new Date(),
          findingFingerprints: [`fp-${i}`],
          commitSha: "a".repeat(40),
          patchSummary: "bump",
          unifiedDiff: "--- a/x\n+++ b/x\n",
          affectedFiles: ["x"],
          eligibility: "safe",
          eligibilityReason: "test",
        },
      });
    }
    for (let i = 0; i < 6; i++) await store.createWithQuota!(newJob(200 + i), quota(2));
    // One slot is taken by an executing scan; 5 verifications and 5 scan claims race for the last one.
    expect(await store.claimNextScan!({ kind: "github-actions" }, quota(2))).not.toBeNull();

    const outcomes = await Promise.all([
      ...remediationIds.map((id) => store.beginRemediationVerification!(done.job.id, id, quota(2)).then((r) => r.ok)),
      ...Array.from({ length: 5 }, (_, i) =>
        store.claimNextScan!(i % 2 ? { kind: "github-actions" } : { kind: "warm", workerId: `w${i}` }, quota(2)).then(Boolean),
      ),
    ]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    const verifying = await prisma.remediation.count({ where: { status: "applied" } });
    const executing = await prisma.scanJob.count({ where: { startedAt: { not: null }, status: "queued" } });
    expect(verifying + executing).toBe(2);
  });

  it("re-queues contended retries only while the waiting queue has room", async () => {
    const ids: string[] = [];
    for (let i = 0; i < 4; i++) {
      const r = await store.createWithQuota!(newJob(300 + i), quota(10));
      if (!r.ok) throw new Error("setup failed");
      await prisma.scanJob.update({ where: { id: r.job.id }, data: { status: "failed" } });
      ids.push(r.job.id);
    }
    const results = await Promise.all(ids.map((id) => store.requeueWithQuota!(id, ["failed"], 5, { ...quota(1), maxQueuedScans: 1 })));
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(await prisma.scanJob.count({ where: { status: "queued", startedAt: null } })).toBe(1);
    expect(await prisma.scanJob.count({ where: { status: "failed" } })).toBe(3);
  });

  it("fails executor-claimed work that stopped reporting and expired queue entries, freeing the slot", async () => {
    const a = await store.createWithQuota!(newJob(400), quota(1));
    const b = await store.createWithQuota!(newJob(401), quota(1));
    if (!a.ok || !b.ok) throw new Error("setup failed");
    const claimed = await store.claimNextScan!({ kind: "github-actions" }, quota(1));
    expect(claimed?.job.id).toBe(a.job.id);
    await prisma.$executeRawUnsafe(`UPDATE "ScanJob" SET "updatedAt" = now() - interval '20 minutes' WHERE id = $1`, a.job.id);
    await prisma.$executeRawUnsafe(`UPDATE "ScanJob" SET "updatedAt" = now() - interval '40 minutes' WHERE id = $1`, b.job.id);

    const next = await store.createWithQuota!(newJob(402), quota(1));
    expect(next.ok).toBe(true);
    expect(await prisma.scanJob.findUnique({ where: { id: a.job.id } })).toMatchObject({ status: "failed", failureCategory: "worker_timeout" });
    expect(await prisma.scanJob.findUnique({ where: { id: b.job.id } })).toMatchObject({ status: "failed", failureCategory: "queue_timeout" });
    expect(await store.claimNextScan!({ kind: "github-actions" }, quota(1))).not.toBeNull();
  });

  it("applies worker progress heartbeats forward-only and never reopens a finished job", async () => {
    const created = await store.createWithQuota!(newJob(500), quota(1));
    if (!created.ok) throw new Error("setup failed");
    const id = created.job.id;
    const post = (body: Record<string, unknown>) => {
      const json = JSON.stringify(body);
      return callbackPost(
        new Request(`http://localhost/api/scans/${id}/callback`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-VibeShield-Signature": signCallbackPayload(json, SECRET) },
          body: json,
        }),
        { params: Promise.resolve({ id }) },
      );
    };
    const progress = (phase: string) => post({ type: "progress", jobId: id, phase, at: new Date().toISOString() });

    await progress("worker_started");
    await progress("scanning");
    const late = await progress("retrieving"); // delivered out of order
    expect((await late.json()).data.accepted).toBe(false);
    let job = await prisma.scanJob.findUnique({ where: { id } });
    expect(job?.status).toBe("scanning");
    expect((job?.scanCoverage as { progress: Record<string, string> }).progress.worker_startedAt).toBeTruthy();

    const final = await post({ jobId: id, status: "completed", findings: [], scanCoverage: { scannersRun: [], lockfilesFound: [], limitations: [] } });
    expect(final.status).toBe(200);
    await progress("scanning");
    job = await prisma.scanJob.findUnique({ where: { id } });
    expect(job?.status).toBe("completed");
    // The final payload keeps the heartbeat timestamps recorded earlier.
    expect((job?.scanCoverage as { progress: Record<string, string> }).progress.scanningAt).toBeTruthy();

    const unsigned = await callbackPost(
      new Request(`http://localhost/api/scans/${id}/callback`, { method: "POST", body: JSON.stringify({ type: "progress" }) }),
      { params: Promise.resolve({ id }) },
    );
    expect(unsigned.status).toBe(401);
  });
});
