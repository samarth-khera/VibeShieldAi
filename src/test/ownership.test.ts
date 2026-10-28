import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  checkOwner,
  decodeGrant,
  encodeGrant,
  grantCookieForNewJob,
  isSameOriginMutation,
  ownerKeyFrom,
  type OwnershipConfig,
} from "@/server/auth/ownership";
import { attachOwnerGrant, attachViewer, requireJobOwner } from "@/server/auth/owner-gate";
import { signCallbackPayload } from "@/server/callback-auth";
import type { ServerConfig } from "@/server/config";
import { fetchRepoMetadata } from "@/server/github";
import { RetrievalError } from "@/server/errors";
import { handleApplyRemediation, handleApproveRemediation, handleDownloadPatch, handleVerificationResult } from "@/server/remediation/api";
import { APPROVAL_TTL_MS, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import { submitScan, type ScanDeps } from "@/server/scans-service";
import { InMemoryJobStore } from "@/test/mock-store";

const ORIGIN = "https://vs.example";
const COMMIT = "c".repeat(40);
const DIFF = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1,1 +1,1 @@\n-requests==2.19.0\n+requests==2.31.0\n";
const CALLBACK_SECRET = "test-callback-secret-0123456789abcdef";

let cfg: OwnershipConfig;
beforeEach(() => {
  cfg = { key: ownerKeyFrom({ SCAN_CALLBACK_SECRET: CALLBACK_SECRET }), appOrigin: ORIGIN, ttlSeconds: 7 * 86400 };
});

/** Cookie header for a browser that created `jobIds` (each via the real grant-issuing path). */
function browserOwning(...jobIds: string[]): string {
  let cookie = "";
  for (const id of jobIds) {
    const set = grantCookieForNewJob(new Request(`${ORIGIN}/api/scans`, { headers: cookie ? { cookie } : {} }), id, cfg)!;
    cookie = set.split(";")[0];
  }
  return cookie;
}
const post = (cookie?: string, headers: Record<string, string> = { "sec-fetch-site": "same-origin" }) =>
  new Request(`${ORIGIN}/api/x`, { method: "POST", headers: { ...headers, ...(cookie ? { cookie } : {}) } });

describe("owner grant", () => {
  it("is an HttpOnly, SameSite=Lax, Secure __Host- cookie that never appears in a URL", () => {
    const set = grantCookieForNewJob(new Request(`${ORIGIN}/api/scans`), "job-a", cfg)!;
    expect(set).toMatch(/^__Host-vibeshield_owner=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+; Path=\/; HttpOnly; SameSite=Lax; Max-Age=604800; Secure$/);
  });

  it("accumulates the browser's own jobs, keeps one session subject, caps at 30 and expires old entries", () => {
    const cookie = browserOwning("job-a", "job-b");
    const a = checkOwner(post(cookie), "job-a", cfg);
    const b = checkOwner(post(cookie), "job-b", cfg);
    expect(a.owner && b.owner && a.subject === b.subject).toBe(true);
    const many = browserOwning(...Array.from({ length: 35 }, (_, i) => `job-${i}`));
    expect(checkOwner(post(many), "job-0", cfg).owner).toBe(false);
    expect(checkOwner(post(many), "job-34", cfg).owner).toBe(true);
    const later = new Date(Date.now() + 8 * 86400_000);
    expect(checkOwner(post(cookie), "job-a", cfg, later)).toEqual({ owner: false, reason: "not_owner" });
  });

  it("rejects forged, tampered, re-signed and swapped grants", () => {
    const cookie = browserOwning("victim-job");
    const value = cookie.split("=")[1];
    const [payload, mac] = value.split(".");
    // Attacker edits the job list without the key.
    const forged = JSON.parse(Buffer.from(payload, "base64url").toString());
    forged.jobs.push(["someone-elses-job", Math.floor(Date.now() / 1000)]);
    const forgedValue = `${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${mac}`;
    expect(checkOwner(post(`__Host-vibeshield_owner=${forgedValue}`), "someone-elses-job", cfg).owner).toBe(false);
    // Signed with a different key.
    const otherKey = randomBytes(32);
    const other = encodeGrant({ sid: "A".repeat(22), jobs: [["victim-job", Math.floor(Date.now() / 1000)]] }, otherKey);
    expect(checkOwner(post(`__Host-vibeshield_owner=${other}`), "victim-job", cfg).owner).toBe(false);
    // Truncated / extra segments / garbage.
    for (const bad of [payload, `${value}.x`, "not-a-grant", ""]) {
      expect(decodeGrant(bad, cfg.key!, new Date(), cfg.ttlSeconds)).toBeNull();
    }
    // Without a key nothing is ever owned (fail closed).
    expect(checkOwner(post(cookie), "victim-job", { ...cfg, key: null })).toEqual({ owner: false, reason: "unavailable" });
  });

  it("derives a dedicated key, never the raw callback secret", () => {
    const k = ownerKeyFrom({ SCAN_CALLBACK_SECRET: CALLBACK_SECRET })!;
    expect(k.equals(Buffer.from(CALLBACK_SECRET))).toBe(false);
    expect(ownerKeyFrom({ OWNER_SESSION_SECRET: "x".repeat(40), SCAN_CALLBACK_SECRET: CALLBACK_SECRET })!.equals(k)).toBe(false);
    expect(ownerKeyFrom({})).toBeNull();
  });
});

describe("requireJobOwner (CSRF + ownership)", () => {
  it("1/5: user A cannot act on user B's job, even with a valid grant of their own", async () => {
    const userA = browserOwning("job-a");
    const r = requireJobOwner(post(userA), "job-b", cfg);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.response.status).toBe(403);
      expect((await r.response.json()).error.code).toBe("not_job_owner");
    }
    expect(requireJobOwner(post(browserOwning("job-b")), "job-b", cfg).ok).toBe(true);
  });

  it("2/10: a visitor with only the report URL / job ID is refused", () => {
    const r = requireJobOwner(post(undefined), "job-b", cfg);
    expect(r.ok).toBe(false);
  });

  it("4: refuses cross-site and header-less requests even with the owner's cookie", () => {
    const owner = browserOwning("job-b");
    const attempts: Record<string, string>[] = [{ "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }, { origin: "https://evil.example" }, {}];
    for (const headers of attempts) {
      const r = requireJobOwner(post(owner, headers), "job-b", cfg);
      expect(r.ok).toBe(false);
    }
    expect(isSameOriginMutation(post(owner, { origin: ORIGIN }), ORIGIN)).toBe(true);
  });

  it("returns 503 (not success) when ownership is not configured", async () => {
    const r = requireJobOwner(post(browserOwning("job-b")), "job-b", { ...cfg, key: null });
    expect(!r.ok && r.response.status).toBe(503);
  });
});

describe("scan submission and report access", () => {
  const scanConfig = {
    maxArchiveBytes: 1, githubApiTimeoutMs: 5000, jobTtlHours: 168, maxScansPerIpHourly: 10, maxScansPerIpDaily: 10,
    globalDailyScanCap: 100, maxConcurrentHeavyScans: 2, maxQueuedScans: 10, jobTimeoutMs: 900_000, queueTimeoutMs: 1_800_000,
    warmWorkerEnabled: false, warmLeaseMs: 60_000, warmWorkerHealthyMs: 30_000, warmWorkerGraceMs: 10_000, appUrl: ORIGIN,
  } as ServerConfig;

  it("11: a public scan needs no GitHub App; the creating response alone grants ownership", async () => {
    const store = new InMemoryJobStore();
    const deps: ScanDeps = {
      store,
      config: scanConfig,
      enqueue: async () => undefined,
      rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: async () => true,
      verifyRepo: async () => ({ ok: true }),
    };
    const req = new Request(`${ORIGIN}/api/scans`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // Client-supplied identity fields are ignored.
      body: JSON.stringify({ repositoryUrl: "https://github.com/acme/webapp", owner: "admin", sessionId: "x", approved: true }),
    });
    const res = await attachOwnerGrant(req, await submitScan(req, deps), cfg);
    expect(res.status).toBe(202);
    const id = (await res.json()).data.id;
    const cookie = res.headers.get("set-cookie")!.split(";")[0];
    expect(requireJobOwner(post(cookie), id, cfg).ok).toBe(true);

    // Non-202 responses never grant anything.
    const rejected = await attachOwnerGrant(req, Response.json({ error: { code: "x" } }, { status: 429 }), cfg);
    expect(rejected.headers.get("set-cookie")).toBeNull();
  });

  it("tells the report UI who owns the job (display only)", async () => {
    const res = () => Response.json({ data: { id: "job-b", status: "completed" } }, { status: 200 });
    const asOwner = await attachViewer(new Request(`${ORIGIN}/api/scans/job-b`, { headers: { cookie: browserOwning("job-b") } }), "job-b", res(), cfg);
    expect((await asOwner.json()).data.viewer).toEqual({ isOwner: true });
    const asVisitor = await attachViewer(new Request(`${ORIGIN}/api/scans/job-b`), "job-b", res(), cfg);
    expect((await asVisitor.json()).data.viewer).toEqual({ isOwner: false });
  });

  it("14: unknown repository visibility fails closed", async () => {
    const meta = (body: Record<string, unknown>) => async () =>
      new Response(JSON.stringify({ id: 1, full_name: "acme/webapp", default_branch: "main", size: 1, ...body }), { status: 200 });
    const signal = new AbortController().signal;
    const config = { maxRepoSizeKb: 10_000 } as ServerConfig;
    await expect(fetchRepoMetadata(meta({}), "acme", "webapp", config, signal)).rejects.toBeInstanceOf(RetrievalError);
    await expect(fetchRepoMetadata(meta({ private: true }), "acme", "webapp", config, signal)).rejects.toThrow();
    await expect(fetchRepoMetadata(meta({ private: false, visibility: "internal" }), "acme", "webapp", config, signal)).rejects.toThrow();
    await expect(fetchRepoMetadata(meta({ private: false, visibility: "public" }), "acme", "webapp", config, signal)).resolves.toMatchObject({ id: 1 });
  });
});

describe("approval binding (owner, job, commit, findings, exact diff)", () => {
  const OWNER = "owner-subject-a";
  const OTHER = "owner-subject-b";

  async function setup() {
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "acme", repo: "webapp", repositoryUrl: "https://github.com/acme/webapp", expiresAt: new Date(Date.now() + 3_600_000) });
    await store.update(job.id, { status: "completed", commitSha: COMMIT, defaultBranch: "main" });
    const rem = await store.createRemediation({
      id: "0f2b1c3d-aaaa-bbbb-cccc-000000000001",
      scanJobId: job.id,
      findingFingerprints: ["fp-1"],
      affectedFiles: ["requirements.txt"],
      commitSha: COMMIT,
      eligibility: "safe",
      eligibilityReason: "patch bump",
      requiresRotation: false,
      patchSummary: "Bump requests",
      unifiedDiff: DIFF,
      status: "preview",
      approvedAt: null,
      rescanStatus: null,
      branchName: null,
      pullRequestUrl: null,
    });
    const dispatched: string[] = [];
    const deps: RemediationDeps = {
      store,
      config: { scanCallbackSecret: CALLBACK_SECRET, maxConcurrentHeavyScans: 2 } as ServerConfig,
      dispatchVerification: async (_j, r) => {
        dispatched.push(r.id);
      },
    };
    const approve = (subject: string, body?: unknown) =>
      handleApproveRemediation(
        new Request(`${ORIGIN}/x`, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
        job.id,
        rem.id,
        deps,
        subject,
      );
    const apply = (subject: string) => handleApplyRemediation(job.id, rem.id, deps, subject);
    return { store, job, rem, deps, approve, apply, dispatched };
  }

  it("3/16: records server-derived identifiers only, ignores client-supplied identity, and is idempotent", async () => {
    const { approve, store, job, rem } = await setup();
    const first = await (await approve(OWNER, { approvedBy: "admin", ownerSubject: OTHER, githubUserId: 1 })).json();
    expect(first.data.status).toBe("approved");
    const stored = (await store.getRemediation(job.id, rem.id))!;
    expect(stored.approvedOperations).toMatchObject({
      approvedBy: "job_owner",
      ownerSubject: OWNER,
      githubUserId: null,
      scanJobId: job.id,
      remediationId: rem.id,
      commitSha: COMMIT,
      findingFingerprints: ["fp-1"],
      diffSha256: diffDigest(DIFF),
    });
    const again = await (await approve(OWNER)).json();
    expect(again.data.approvedAt).toBe(first.data.approvedAt);
  });

  it("6: a patch changed after approval invalidates the approval and requires re-approval", async () => {
    const { approve, apply, store, job, rem, dispatched } = await setup();
    await approve(OWNER);
    await store.updateRemediation(job.id, rem.id, { unifiedDiff: DIFF.replace("2.31.0", "9.9.9") });
    const res = await apply(OWNER);
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("approval_diff_changed");
    expect((await store.getRemediation(job.id, rem.id))!).toMatchObject({ status: "preview", approvedAt: null });
    expect(dispatched).toEqual([]);
  });

  it("7: a substituted commit or target finding invalidates the approval", async () => {
    const a = await setup();
    await a.approve(OWNER);
    await a.store.updateRemediation(a.job.id, a.rem.id, { findingFingerprints: ["fp-other"] });
    expect((await (await a.apply(OWNER)).json()).error.code).toBe("approval_target_mismatch");

    const b = await setup();
    await b.approve(OWNER);
    await b.store.update(b.job.id, { commitSha: "d".repeat(40) });
    await b.store.updateRemediation(b.job.id, b.rem.id, { commitSha: "d".repeat(40) });
    expect((await (await b.apply(OWNER)).json()).error.code).toBe("approval_target_mismatch");
    expect(b.dispatched).toEqual([]);
  });

  it("an approval from another session, or an expired one, is not accepted", async () => {
    const { approve, apply, store, job, rem } = await setup();
    await approve(OWNER);
    expect((await (await apply(OTHER)).json()).error.code).toBe("approval_session_mismatch");
    await approve(OWNER);
    const r = (await store.getRemediation(job.id, rem.id))!;
    const old = new Date(Date.now() - APPROVAL_TTL_MS - 60_000).toISOString();
    await store.updateRemediation(job.id, rem.id, { approvedOperations: { ...(r.approvedOperations as object), approvedAt: old } });
    expect((await (await apply(OWNER)).json()).error.code).toBe("approval_expired");
  });

  it("applies a valid approval once; a retry is idempotent", async () => {
    const { approve, apply, dispatched } = await setup();
    await approve(OWNER);
    expect((await apply(OWNER)).status).toBe(202);
    expect((await apply(OWNER)).status).toBe(202);
    expect(dispatched).toHaveLength(1);
  });

  it("8: a verification result signed for another job or remediation is rejected", async () => {
    const a = await setup();
    const b = await setup();
    await a.approve(OWNER);
    await a.apply(OWNER);
    const body = JSON.stringify({
      scanJobId: b.job.id,
      remediationId: b.rem.id,
      rescanStatus: "verified",
      summary: { targetResolved: true, originalFindingsCount: 1, postRescanFindingsCount: 0, newFindingsCount: 0, resolvedFingerprints: ["fp-1"], remainingFingerprints: [], regressions: [] },
    });
    const req = new Request(`${ORIGIN}/x`, { method: "POST", headers: { "x-vibeshield-signature": signCallbackPayload(body, CALLBACK_SECRET) }, body });
    const res = await handleVerificationResult(req, a.job.id, a.rem.id, a.deps);
    expect(res.status).toBe(400);
    expect((await a.store.getRemediation(a.job.id, a.rem.id))!.status).toBe("applied");
  });

  it("17: patch download stays available as the read-only fallback", async () => {
    const { deps, job, rem } = await setup();
    const res = await handleDownloadPatch(job.id, rem.id, deps);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(DIFF);
  });
});

describe("route wiring (direct API requests can't bypass the UI)", () => {
  const route = (p: string) => readFileSync(path.join(process.cwd(), "src/app/api/scans/[id]", p, "route.ts"), "utf8");
  const mutating = [
    "remediation/preview",
    "remediation/[remediationId]/approve",
    "remediation/[remediationId]/apply",
    "remediation/[remediationId]/pr",
    "retry",
    "scan",
    "findings/[findingId]/explain",
  ];

  it.each(mutating)("%s checks job ownership before calling its handler", (p) => {
    const src = route(p);
    const gate = src.indexOf("requireJobOwner(req, id)");
    const handler = src.search(/return (handle\w+|retryScan|startScan|explainScanFinding)\(/);
    expect(gate).toBeGreaterThan(-1);
    expect(handler).toBeGreaterThan(gate);
    expect(src).toMatch(/if \(!owner\.ok\) return owner\.response;/);
  });

  it.each(["retry", "scan", "remediation/[remediationId]/apply"])("13: %s refuses private jobs before queueing or dispatch", (p) => {
    const src = route(p);
    expect(src.indexOf("refusePrivateExecution(id)")).toBeGreaterThan(-1);
    expect(src.indexOf("refusePrivateExecution(id)")).toBeLessThan(src.search(/return (handle\w+|retryScan|startScan)\(/));
  });

  it("only the submit route issues ownership grants", () => {
    const submit = readFileSync(path.join(process.cwd(), "src/app/api/scans/route.ts"), "utf8");
    expect(submit).toContain("attachOwnerGrant(");
    for (const p of [...mutating, "", "findings", "remediation", "repository"]) {
      expect(route(p)).not.toContain("attachOwnerGrant(");
    }
  });
});
