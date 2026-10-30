/**
 * The production path after approval, with GitHub as the stateful fake and recorded npm data:
 * preview steps and safe classification, approval with publish consent, the worker's signed
 * progress and result callbacks, automatic publishing with the approving user's own authorization,
 * and the per-repository Safe Auto-Fix opt-in with its boundaries. No AI provider is involved.
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { getConfig, type GithubAppConfig, type ServerConfig } from "@/server/config";
import { signCallbackPayload } from "@/server/callback-auth";
import { disconnect, handleCallback, startConnect, type AuthDeps } from "@/server/auth/service";
import { InMemoryAuthStore } from "@/server/auth/store";
import {
  handleApplyRemediation,
  handleApproveRemediation,
  handleCreatePreview,
  handleListRemediations,
  handleSafeAutoFix,
  handleVerificationResult,
} from "@/server/remediation/api";
import { runSafeAutoFix } from "@/server/remediation/automation";
import { createPreview, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import { toPublicRemediation, type RemediationRecord } from "@/server/remediation/types";
import type { JobRecord } from "@/server/job-store";
import { InMemoryJobStore } from "@/test/mock-store";
import { FakeGitHubApp } from "@/test/fake-github";

const FIX = path.join(process.cwd(), "src/test/fixtures/npm-job-portal");
const read = (f: string) => readFileSync(path.join(FIX, f), "utf8");
const MANIFEST = read("original.package.json");
const LOCK = read("original.package-lock.json");
const ORIGIN = "https://vs.example";
const COOKIE = "__Host-vibeshield_session";
const OWNER = "owner-subject-automation";
const SECRET = "worker-callback-secret-for-tests-0123456789";
const RECORDED: Record<string, string> = {
  "https://registry.npmjs.org/multer/2.5.0": read("registry-multer-2.5.0.json"),
  "https://registry.npmjs.org/proxy-addr/2.0.8": read("registry-proxy-addr-2.0.8.json"),
  "https://registry.npmjs.org/proxy-addr": read("registry-proxy-addr.versions.json"),
  "https://registry.npmjs.org/brace-expansion": read("registry-brace-expansion.versions.json"),
  "https://registry.npmjs.org/brace-expansion/1.1.21": read("registry-brace-expansion-1.1.21.json"),
};
const registryFetch = async (url: string) => (RECORDED[url] ? new Response(RECORDED[url]) : new Response("{}", { status: 404 }));

const osv = (id: string, name: string, version: string, fixed: string) => ({
  fingerprint: `fp-${id}`,
  scanner: "osv-scanner",
  ruleId: id,
  category: "Dependencies",
  severity: "high",
  title: `${name} advisory ${id}`,
  description: "",
  filePath: "backend/package-lock.json",
  startLine: null,
  endLine: null,
  redactedEvidence: null,
  vulnerabilityId: id,
  remediation: null,
  packageInfo: { name, version, ecosystem: "npm", fixedVersion: fixed },
  metadata: { fixedVersion: fixed },
});
const FINDINGS = [osv("GHSA-jqcg-44mw-7w3h", "proxy-addr", "2.0.7", "2.0.8"), osv("GHSA-q7qp-rjg7-q26m", "multer", "2.0.2", "2.5.0")];

let gh: FakeGitHubApp;
let store: InMemoryAuthStore;
let auth: AuthDeps;
let jobs: InMemoryJobStore;
let job: JobRecord;
let base: string;
let dispatched: string[];
let deps: RemediationDeps;

beforeEach(async () => {
  gh = new FakeGitHubApp();
  base = gh.git.seed({ "backend/package.json": MANIFEST, "backend/package-lock.json": LOCK });
  gh.owner = { id: 9001, login: "acme", type: "User" };
  store = new InMemoryAuthStore();
  const app: GithubAppConfig = {
    clientId: gh.clientId,
    clientSecret: gh.clientSecret,
    slug: "vibeshield-ai-test",
    encryptionKey: randomBytes(32),
    callbackUrl: `${ORIGIN}/api/auth/github/callback`,
    setupUrl: `${ORIGIN}/api/auth/github/setup`,
    appOrigin: ORIGIN,
  };
  auth = { store, app, fetchImpl: gh.fetch };
  jobs = new InMemoryJobStore();
  job = await jobs.create({ owner: "acme", repo: "webapp", repositoryUrl: "https://github.com/acme/webapp", expiresAt: new Date(Date.now() + 3_600_000) });
  await jobs.update(job.id, { status: "completed", commitSha: base, defaultBranch: "main" });
  job = (await jobs.get(job.id))!;
  await jobs.saveFindings(job.id, FINDINGS as never);
  await store.setScanAccess({ scanJobId: job.id, githubRepoId: 4242, isPrivate: false, githubUserId: null });
  dispatched = [];
  deps = {
    store: jobs,
    auth,
    fetchImpl: gh.fetch,
    registryFetch,
    sourceFiles: { "backend/package.json": MANIFEST, "backend/package-lock.json": LOCK },
    config: { ...getConfig(), githubApiTimeoutMs: 5000, scanCallbackSecret: SECRET } as ServerConfig,
    // Production shape: verification is handed to the worker, which reports back via signed callbacks.
    dispatchVerification: async (_job, rem) => {
      dispatched.push(rem.id);
    },
  };
});

const cookieOf = (res: Response) => res.headers.get("set-cookie")?.match(new RegExp(`${COOKIE}=([^;]+)`))?.[0] ?? null;
async function connect(userId: number): Promise<string> {
  const start = await startConnect(new Request(`${ORIGIN}/api/auth/github/start?returnTo=%2F`), auth);
  const loc = new URL(start.headers.get("location")!);
  const code = gh.issueCode(userId, loc.searchParams.get("code_challenge")!);
  const cb = await handleCallback(
    new Request(`${ORIGIN}/api/auth/github/callback?code=${code}&state=${loc.searchParams.get("state")}`, { headers: { cookie: cookieOf(start)! } }),
    auth,
  );
  return cookieOf(cb)!;
}
const post = (url: string, cookie: string | null, body?: unknown) =>
  new Request(`${ORIGIN}${url}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, ...(cookie ? { cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
const findingId = async (name: string) => (await jobs.getFindings(job.id)).findings.find((f) => (f.packageInfo as { name: string }).name === name)!.id;
const preview = async (cookie: string, name: string) => {
  const res = await handleCreatePreview(post(`/api/scans/${job.id}/remediation/preview`, cookie, { findingId: await findingId(name) }), job.id, deps);
  expect(res.status).toBe(201);
  return (await res.json()).data as ReturnType<typeof toPublicRemediation>;
};
const approve = (cookie: string, remId: string, body?: unknown) =>
  handleApproveRemediation(post(`/api/scans/${job.id}/remediation/${remId}/approve`, cookie, body), job.id, remId, deps, OWNER);
/** The Actions worker's signed callbacks. */
const worker = (remId: string, payload: Record<string, unknown>, secret = SECRET) => {
  const raw = JSON.stringify({ scanJobId: job.id, remediationId: remId, ...payload });
  return handleVerificationResult(
    new Request(`${ORIGIN}/api/scans/${job.id}/remediation/${remId}/verification`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-vibeshield-signature": signCallbackPayload(raw, secret) },
      body: raw,
    }),
    job.id,
    remId,
    deps,
  );
};
const passed = (rem: RemediationRecord | ReturnType<typeof toPublicRemediation>) => ({
  rescanStatus: "verified",
  summary: {
    targetResolved: true,
    originalFindingsCount: 2,
    postRescanFindingsCount: 1,
    newFindingsCount: 0,
    resolvedFingerprints: rem.findingFingerprints,
    remainingFingerprints: [],
    regressions: [],
    scannerStatuses: { gitleaks: "completed", semgrep: "completed", osvScanner: "completed" },
    snapshot: { commitSha: base, fileCount: 2 },
  },
});
const stored = (remId: string) => jobs.getRemediation(job.id, remId);

describe("preview generation", () => {
  it("stores each step as it starts and classifies the proxy-addr patch-level transitive update as safe", async () => {
    const alice = await connect(1001);
    const states: string[] = [];
    const update = jobs.updateRemediation.bind(jobs);
    jobs.updateRemediation = async (j, r, patch) => {
      const g = (patch.approvedOperations as { generation?: { state: string; stage?: string } } | undefined)?.generation;
      if (g) states.push(`${g.state}:${g.stage}`);
      return update(j, r, patch);
    };
    const p = await preview(alice, "proxy-addr");
    expect(states).toEqual([
      "running:checking_repository",
      "running:checking_eligibility",
      "running:generating_remediation",
      "running:validating_dependency_changes",
      "running:generating_patch",
      "done:generating_patch",
    ]);
    expect(p.generation).toMatchObject({ state: "done", engine: "npm", repository: { canPublish: true, fullName: "acme/webapp", login: "alice" } });
    expect(p).toMatchObject({ eligibility: "safe", affectedFiles: ["backend/package-lock.json"], status: "preview" });
    expect(p.unifiedDiff).toContain('-      "version": "2.0.7"');
    // The stored diff and its hash are exactly what the user sees.
    expect(diffDigest((await stored(p.id))!.unifiedDiff)).toBe(diffDigest(p.unifiedDiff));
    // A direct dependency's minor upgrade is not "safe": it changes package.json.
    expect((await preview(alice, "multer")).eligibility).toBe("potentially_breaking");
  });

  it("a reload while generating shows the stored running step (and never a diff)", async () => {
    const id = (await createPreview(job.id, await findingId("proxy-addr"), deps)).id;
    const rec = (await stored(id))!;
    await jobs.updateRemediation(job.id, id, {
      unifiedDiff: "",
      approvedOperations: { generation: { ...(rec.approvedOperations as { generation: object }).generation, state: "running", stage: "validating_dependency_changes" } },
    });
    const list = (await (await handleListRemediations(job.id, deps)).json()).data as ReturnType<typeof toPublicRemediation>[];
    expect(list.find((r) => r.id === id)).toMatchObject({ unifiedDiff: "", generation: { state: "running", stage: "validating_dependency_changes" } });
  });
});

describe("approval with consent to publish, then the worker", () => {
  it("publishing consent needs a connected account that can write to the repository now", async () => {
    const alice = await connect(1001);
    const p = await preview(alice, "proxy-addr");
    gh.push.delete(1001);
    const refused = await approve(alice, p.id, { publish: true });
    expect(refused.status).toBe(409);
    expect((await refused.json()).error.code).toBe("publish_not_authorized");
    expect((await stored(p.id))!.status).toBe("preview");
  });

  it("verification failure prevents any commit or pull request", async () => {
    const alice = await connect(1001);
    const p = await preview(alice, "proxy-addr");
    expect((await approve(alice, p.id, { publish: true })).status).toBe(200);
    await handleApplyRemediation(job.id, p.id, deps, OWNER);
    const res = await worker(p.id, { ...passed(p), rescanStatus: "needs_review", summary: { ...passed(p).summary, targetResolved: false, regressions: ["x"] } });
    expect((await res.json()).data).toMatchObject({ accepted: true, status: "needs_review" });
    await handleListRemediations(job.id, deps); // the recovery pump must not publish it either
    expect(gh.git.commitBodies).toHaveLength(0);
    expect(gh.git.pulls).toHaveLength(0);
  });

  it("stores the worker's signed progress, then publishes automatically after it passes, reading GitHub back", async () => {
    const alice = await connect(1001);
    const p = await preview(alice, "proxy-addr");
    const approved = (await (await approve(alice, p.id, { publish: true })).json()).data;
    expect(approved).toMatchObject({ status: "approved", approvedBy: "job_owner", publishAfterVerification: { login: "alice" } });
    expect(((await stored(p.id))!.approvedOperations as { publish: object }).publish).toEqual({ githubUserId: 1001, login: "alice" });
    await handleApplyRemediation(job.id, p.id, deps, OWNER);
    expect(dispatched).toEqual([p.id]);

    // Progress events, signed like the result; unsigned ones are refused.
    expect((await worker(p.id, { progress: { stage: "applying_patch" } }, "wrong-secret")).status).toBe(401);
    for (const progress of [{ stage: "preparing_snapshot" }, { stage: "applying_patch" }, { stage: "scanning" }, { scanner: "gitleaks", status: "completed" }, { scanner: "osv-scanner", status: "completed" }]) {
      expect((await (await worker(p.id, { progress })).json()).data).toEqual({ accepted: true });
    }
    let pub = toPublicRemediation((await stored(p.id))!);
    expect(pub.verification?.progress).toMatchObject({ stage: "scanning", scanners: { gitleaks: "completed", semgrep: "running", osvScanner: "completed" } });
    await worker(p.id, { progress: { scanner: "semgrep", status: "completed" } });

    // The passed result: the branch, commit and PR are created with alice's own token, then read back.
    expect((await (await worker(p.id, passed(p))).json()).data).toMatchObject({ accepted: true, status: "verified" });
    pub = toPublicRemediation((await stored(p.id))!);
    expect(pub.pullRequest).toMatchObject({ status: "created", number: 1, prAuthor: "alice", commit: { authorLogin: "alice" }, baseBranch: "main" });
    const head = gh.git.refs.get(`heads/${pub.pullRequest!.branch}`)!;
    expect(gh.git.commits.get(head)!.parents).toEqual([base]);
    expect(gh.git.filesAt(head)["backend/package-lock.json"]).toBe(read("npm-update-proxy-addr.package-lock.json"));
    expect(gh.git.filesAt(head)["backend/package.json"]).toBe(MANIFEST);
    expect(gh.git.refs.get("heads/main")).toBe(base);
    expect(gh.git.calls.filter((c) => c.method !== "GET").every((c) => /^Bearer ghu_test_1001_/.test(c.auth ?? ""))).toBe(true);
    expect(store.events).toContainEqual(expect.objectContaining({ action: "pull_request", outcome: "created", detail: "auto-publish after approval #1" }));

    // Late or repeated worker callbacks and page polls never create another commit or PR.
    await worker(p.id, passed(p));
    await handleListRemediations(job.id, deps);
    expect(gh.git.commitBodies).toHaveLength(1);
    expect(gh.git.pulls).toHaveLength(1);
  });

  it("a disconnected account cannot be used to publish later", async () => {
    const alice = await connect(1001);
    const p = await preview(alice, "proxy-addr");
    await approve(alice, p.id, { publish: true });
    await handleApplyRemediation(job.id, p.id, deps, OWNER);
    await disconnect(post("/api/auth/github/disconnect", alice), auth);
    await worker(p.id, passed(p));
    expect(toPublicRemediation((await stored(p.id))!).pullRequest).toMatchObject({ status: "failed", code: "credential_invalid" });
    expect(gh.git.commitBodies).toHaveLength(0);
  });
});

describe("Safe Auto-Fix (per-repository opt-in)", () => {
  const safeCall = (cookie: string | null, body: unknown) => handleSafeAutoFix(post(`/api/scans/${job.id}/safe-autofix`, cookie, body), job.id, deps);

  it("is off by default: a completed scan is not processed", async () => {
    await connect(1001);
    expect(await runSafeAutoFix(job.id, deps)).toMatchObject({ considered: 0 });
    expect(await jobs.listRemediations(job.id)).toEqual([]);
  });

  it("needs explicit confirmation of the exact repository by a user who can write to it", async () => {
    const alice = await connect(1001);
    expect((await safeCall(alice, { action: "enable" })).status).toBe(400);
    expect((await safeCall(alice, { action: "enable", confirm: true, repositoryId: 5555 })).status).toBe(409);
    gh.push.add(1002);
    gh.push.delete(1002);
    const bob = await connect(1002); // read-only collaborator
    expect((await safeCall(bob, { action: "enable", confirm: true, repositoryId: 4242 })).status).toBe(403);
    expect((await safeCall(null, { action: "enable", confirm: true, repositoryId: 4242 })).status).toBe(401);
    const cross = await handleSafeAutoFix(
      new Request(`${ORIGIN}/x`, { method: "POST", headers: { "content-type": "application/json", origin: "https://evil.example", cookie: alice }, body: JSON.stringify({ action: "enable", confirm: true, repositoryId: 4242 }) }),
      job.id,
      deps,
    );
    expect(cross.status).toBe(403);
    expect(await store.getSafeAutoFix(4242)).toBeNull();
  });

  it("processes only server-classified safe fixes, leaves the rest for review, and publishes after the rescan passes", async () => {
    const alice = await connect(1001);
    const res = await safeCall(alice, { action: "enable", confirm: true, repositoryId: 4242 });
    expect((await res.json()).data).toMatchObject({ enabled: true, enabledBy: "alice", started: true });
    const list = await jobs.listRemediations(job.id);
    const proxy = list.find((r) => r.affectedFiles.length === 1)!;
    const multer = list.find((r) => r.affectedFiles.includes("backend/package.json"))!;
    expect(proxy).toMatchObject({ eligibility: "safe", status: "applied" });
    expect(toPublicRemediation(proxy)).toMatchObject({ approvedBy: "safe_autofix", publishAfterVerification: { login: "alice" } });
    // Potentially breaking: generated for review, never approved by the policy.
    expect(multer).toMatchObject({ eligibility: "potentially_breaking", status: "preview", approvedAt: null });
    expect(dispatched).toEqual([proxy.id]);

    await worker(proxy.id, passed(proxy));
    expect(toPublicRemediation((await stored(proxy.id))!).pullRequest).toMatchObject({ status: "created", prAuthor: "alice" });
    expect(store.events).toContainEqual(expect.objectContaining({ action: "pull_request", outcome: "created", detail: "safe auto-fix #1" }));
    // Running it again does not duplicate anything.
    await safeCall(alice, { action: "run" });
    expect((await jobs.listRemediations(job.id)).length).toBe(2);
    expect(gh.git.pulls).toHaveLength(1);
  });

  it("turning it off before verification finishes cancels the publication", async () => {
    const alice = await connect(1001);
    await safeCall(alice, { action: "enable", confirm: true, repositoryId: 4242 });
    const proxy = (await jobs.listRemediations(job.id)).find((r) => r.eligibility === "safe")!;
    expect((await (await safeCall(alice, { action: "disable" })).json()).data).toEqual({ enabled: false });
    await worker(proxy.id, passed(proxy));
    expect(toPublicRemediation((await stored(proxy.id))!).pullRequest).toMatchObject({ status: "failed", code: "publish_cancelled" });
    expect(gh.git.commitBodies).toHaveLength(0);
  });

  it("starts from the lowest fixed release, so an in-range fix is found even when other advisories need a parent upgrade", async () => {
    const alice = await connect(1001);
    // brace-expansion 1.1.12 (dev, via minimatch "^1.1.7"): one advisory is fixed in 1.1.18, another only in 5.x.
    await jobs.saveFindings(job.id, [
      osv("GHSA-qhr7-859c-m2p7", "brace-expansion", "1.1.12", "5.0.11"),
      osv("GHSA-rgw5-rvv9-x895", "brace-expansion", "1.1.12", "1.1.18"),
    ] as never);
    await safeCall(alice, { action: "enable", confirm: true, repositoryId: 4242 });
    const brace = (await jobs.listRemediations(job.id)).find((r) => r.patchSummary.startsWith("Update brace-expansion"))!;
    expect(brace).toMatchObject({ eligibility: "safe", status: "applied", findingFingerprints: ["fp-GHSA-rgw5-rvv9-x895"] });
    expect(brace.patchSummary).toContain("1.1.12 → 1.1.21");
  });

  it("the policy cannot approve a fix that is not classified safe", async () => {
    const alice = await connect(1001);
    await store.setSafeAutoFix({ githubRepoId: 4242, enabledByGithubUserId: 1001, enabledByLogin: "alice" });
    const multer = await preview(alice, "multer");
    const { approveRemediation } = await import("@/server/remediation/service");
    await expect(
      approveRemediation(job.id, multer.id, deps, { ownerSubject: "safe-autofix:1001", approvedBy: "safe_autofix", githubUserId: 1001, githubRepoId: 4242 }),
    ).rejects.toMatchObject({ code: "not_safe" });
  });
});
