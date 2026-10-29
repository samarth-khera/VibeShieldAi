/**
 * One remediation, traced through every stage with the same IDs and the same scanned commit:
 * npm lockfile preview → explicit approval (bound to session, GitHub user, repository ID, commit,
 * findings and diff hash) → isolated verification → stored PR progress → commit/branch/PR read
 * back from GitHub → duplicate retry. GitHub is the stateful fake; the npm data is recorded.
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getConfig, type GithubAppConfig } from "@/server/config";
import { handleCallback, startConnect, type AuthDeps } from "@/server/auth/service";
import { InMemoryAuthStore } from "@/server/auth/store";
import { handleApproveRemediation, handleCreatePullRequest } from "@/server/remediation/api";
import { applyAndVerify, createPreview, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import type { PullRequestState } from "@/server/remediation/github-pr";
import type { ScanEngineResult } from "@/server/scanners/types";
import type { JobRecord } from "@/server/job-store";
import { InMemoryJobStore } from "@/test/mock-store";
import { FakeGitHubApp } from "@/test/fake-github";

const FIX = path.join(process.cwd(), "src/test/fixtures/npm-job-portal");
const read = (f: string) => readFileSync(path.join(FIX, f), "utf8");
const MANIFEST = read("original.package.json");
const LOCK = read("original.package-lock.json");
const ORIGIN = "https://vs.example";
const COOKIE = "__Host-vibeshield_session";
const OWNER = "owner-subject-e2e";
const ADVISORIES: [string, string][] = [
  ["GHSA-3p4h-7m6x-2hcm", "2.2.0"],
  ["GHSA-535w-7cp7-47q4", "2.3.0"],
  ["GHSA-5528-5vmv-3xc2", "2.1.1"],
  ["GHSA-72gw-mp4g-v24j", "2.2.0"],
  ["GHSA-q7qp-rjg7-q26m", "2.5.0"],
  ["GHSA-qvfw-j98x-7q72", "2.3.0"],
  ["GHSA-v52c-386h-88mc", "2.1.0"],
  ["GHSA-wc9g-mqfw-jrwm", "2.3.0"],
  ["GHSA-xf7r-hgr6-v32p", "2.1.0"],
];
const multerFinding = ([id, fixed]: [string, string]) => ({
  fingerprint: `fp-${id}`,
  scanner: "osv-scanner",
  ruleId: id,
  category: "Dependencies",
  severity: "high",
  title: `multer advisory ${id}`,
  description: "",
  filePath: "backend/package-lock.json",
  startLine: null,
  endLine: null,
  redactedEvidence: null,
  vulnerabilityId: id,
  remediation: null,
  packageInfo: { name: "multer", version: "2.0.2", ecosystem: "npm", fixedVersion: fixed },
  metadata: { fixedVersion: fixed },
});
const registryFetch = async (url: string) =>
  url === "https://registry.npmjs.org/multer/2.5.0" ? new Response(read("registry-multer-2.5.0.json")) : new Response("{}", { status: 404 });

/** A scanner that reports the multer advisories only while the snapshot still locks multer 2.0.2. */
const scanEngine = async (dir: string): Promise<ScanEngineResult> => {
  const lock = JSON.parse(readFileSync(path.join(dir, "backend/package-lock.json"), "utf8"));
  const vulnerable = lock.packages["node_modules/multer"].version === "2.0.2";
  const findings = vulnerable ? ADVISORIES.map(multerFinding) : [];
  return {
    status: "completed",
    findings,
    counts: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
    gitleaksStatus: "completed",
    gitleaksDurationMs: 5,
    gitleaksError: null,
    semgrepStatus: "completed",
    semgrepDurationMs: 5,
    semgrepError: null,
    osvStatus: "completed",
    osvDurationMs: 5,
    osvError: null,
    scannerVersions: { gitleaks: "8", semgrep: "1", osvScanner: "2" },
    scanCoverage: { lockfilesFound: ["backend/package-lock.json"], scannersRun: ["gitleaks", "semgrep", "osv-scanner"], limitations: [] },
  } as ScanEngineResult;
};

let gh: FakeGitHubApp;
let auth: AuthDeps;
let store: InMemoryAuthStore;
let jobs: InMemoryJobStore;
let job: JobRecord;
let base: string;
let rdeps: RemediationDeps;
let prStates: PullRequestState[];

beforeEach(async () => {
  gh = new FakeGitHubApp();
  base = gh.git.seed({ "backend/package.json": MANIFEST, "backend/package-lock.json": LOCK, "README.md": "# job portal\n" });
  gh.admin.add(1002);
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
  await jobs.saveFindings(job.id, ADVISORIES.map(multerFinding) as never);
  await store.setScanAccess({ scanJobId: job.id, githubRepoId: 4242, isPrivate: false, githubUserId: null });
  rdeps = {
    store: jobs,
    auth,
    fetchImpl: gh.fetch,
    registryFetch,
    sourceFiles: { "backend/package.json": MANIFEST, "backend/package-lock.json": LOCK, "README.md": "# job portal\n" },
    scanEngine,
    config: { ...getConfig(), githubApiTimeoutMs: 5000 },
  };
  // Record every stored pull-request state, in order.
  prStates = [];
  const update = jobs.updateRemediation.bind(jobs);
  jobs.updateRemediation = async (jobId, remId, patch) => {
    const pr = (patch.approvedOperations as { pullRequest?: PullRequestState } | undefined)?.pullRequest;
    if (pr) prStates.push(pr);
    return update(jobId, remId, patch);
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
const post = (url: string, cookie: string, body: unknown = {}) =>
  new Request(`${ORIGIN}${url}`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, cookie }, body: JSON.stringify(body) });

/** Preview → approval (as `approver`) → verification, returning the verified remediation. */
async function verifiedFix(approverCookie: string) {
  const target = (await jobs.getFindings(job.id)).findings.find((f) => f.ruleId === "GHSA-q7qp-rjg7-q26m")!;
  const preview = await createPreview(job.id, target.id, rdeps);
  const approve = await handleApproveRemediation(post(`/api/scans/${job.id}/remediation/${preview.id}/approve`, approverCookie), job.id, preview.id, rdeps, OWNER);
  expect(approve.status).toBe(200);
  const verified = await applyAndVerify(job.id, preview.id, rdeps, { ownerSubject: OWNER });
  return { preview, verified };
}
const createPr = (remId: string, cookie: string, digest: string) =>
  handleCreatePullRequest(post(`/api/scans/${job.id}/remediation/${remId}/pr`, cookie, { approvedDiffSha256: digest }), job.id, remId, rdeps, OWNER);

describe("authorized repository, eligible npm fix: the whole workflow", () => {
  it("keeps one remediation ID, one commit and one diff from preview to a confirmed pull request", async () => {
    const alice = await connect(1001);
    const { preview, verified } = await verifiedFix(alice);
    const digest = diffDigest(preview.unifiedDiff);

    // Preview: both manifests, all nine advisories targeted, on the scanned commit.
    expect(preview).toMatchObject({ status: "preview", commitSha: base, affectedFiles: ["backend/package.json", "backend/package-lock.json"] });
    expect(preview.findingFingerprints).toHaveLength(9);
    // Approval bound to the session, GitHub user, repository ID, commit, findings and exact diff.
    const binding = (await jobs.getRemediation(job.id, preview.id))!.approvedOperations as Record<string, unknown>;
    expect(binding).toMatchObject({
      ownerSubject: OWNER,
      githubUserId: 1001,
      githubRepoId: 4242,
      scanJobId: job.id,
      remediationId: preview.id,
      commitSha: base,
      findingFingerprints: preview.findingFingerprints,
      diffSha256: digest,
    });
    // Verification: the same diff, every scanner completed, all targets resolved, no regressions.
    expect(verified).toMatchObject({ id: preview.id, status: "verified", rescanStatus: "verified", unifiedDiff: preview.unifiedDiff });
    expect(verified.rescanSummary).toMatchObject({ targetResolved: true, newFindingsCount: 0 });
    expect(verified.rescanSummary!.resolvedFingerprints).toHaveLength(9);

    const res = await createPr(preview.id, alice, digest);
    expect(res.status).toBe(201);
    const pr = (await res.json()).data.pullRequest as PullRequestState;

    // Progress was stored step by step, then replaced by the confirmed result.
    expect(prStates.filter((s) => s.status === "in_progress").map((s) => s.step)).toEqual([
      "checking_repository",
      "creating_commit",
      "pushing_branch",
      "creating_pull_request",
      "confirming",
    ]);
    expect(prStates.at(-1)).toMatchObject({ status: "created" });
    // GitHub state: a new branch whose only parent is the scanned commit, carrying exactly npm's files.
    expect(pr).toMatchObject({ status: "created", baseBranch: "main", prAuthor: "alice", commit: { authorName: "alice", authorLogin: "alice" } });
    const head = gh.git.refs.get(`heads/${pr.branch}`)!;
    expect(head).toBe(pr.headSha);
    expect(gh.git.commits.get(head)!.parents).toEqual([base]);
    const files = gh.git.filesAt(head);
    expect(files["backend/package.json"]).toBe(read("npm-expected.package.json"));
    expect(files["backend/package-lock.json"]).toBe(read("npm-expected.package-lock.json"));
    expect(files["README.md"]).toBe("# job portal\n");
    expect(gh.git.refs.get("heads/main")).toBe(base); // default branch untouched
    expect(gh.git.pulls[0]).toMatchObject({ head: pr.branch, base: "main", state: "open", user: "alice" });
    // Every write used alice's own user-to-server token.
    expect(gh.git.calls.filter((c) => c.method !== "GET").every((c) => /^Bearer ghu_test_1001_/.test(c.auth ?? ""))).toBe(true);

    // A retry returns the same branch and pull request; nothing new is written.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16_000);
    const again = await createPr(preview.id, alice, digest);
    vi.useRealTimers();
    expect((await again.json()).data.pullRequest).toMatchObject({ status: "exists", number: pr.number, branch: pr.branch, headSha: pr.headSha });
    expect(gh.git.commitBodies).toHaveLength(1);
    expect(gh.git.pulls).toHaveLength(1);
  });

  it("never reports a pull request that GitHub does not show back as created", async () => {
    const alice = await connect(1001);
    const { preview } = await verifiedFix(alice);
    gh.git.tamperReadBack = "pull";
    const res = await createPr(preview.id, alice, diffDigest(preview.unifiedDiff));
    const body = await res.json();
    expect(res.status).toBe(502);
    expect(body.error.code).toBe("not_confirmed");
    expect(body.data.pullRequest).toMatchObject({ status: "failed", code: "not_confirmed" });
    expect((await jobs.getRemediation(job.id, preview.id))!.pullRequestUrl).toBeNull();
  });

  it("refuses an approval made for another repository ID or by another GitHub account", async () => {
    const alice = await connect(1001);
    const { preview } = await verifiedFix(alice);
    const digest = diffDigest(preview.unifiedDiff);

    // Same owner browser, but a different GitHub account is connected now.
    gh.push.add(1002);
    const bob = await connect(1002);
    const asBob = await createPr(preview.id, bob, digest);
    expect(asBob.status).toBe(409);
    expect((await asBob.json()).error.code).toBe("approval_user_mismatch");

    // The approval names a different repository than the one GitHub reports now.
    const rem = (await jobs.getRemediation(job.id, preview.id))!;
    await jobs.updateRemediation(job.id, preview.id, { approvedOperations: { ...(rem.approvedOperations as object), githubRepoId: 9999 } });
    const moved = await createPr(preview.id, alice, digest);
    expect(moved.status).toBe(409);
    expect((await moved.json()).error.code).toBe("approval_target_mismatch");
    expect(gh.git.commitBodies).toHaveLength(0);
    expect(gh.git.pulls).toHaveLength(0);
  });

  it("an authorized repository does not make an ineligible finding fixable", async () => {
    // Job-portal's proxy-addr finding before transitive support: here, a lockfile that npm would rewrite.
    const alice = await connect(1001);
    await jobs.saveFindings(job.id, [
      { ...multerFinding(["GHSA-jqcg-44mw-7w3h", "2.0.8"]), fingerprint: "fp-proxy", packageInfo: { name: "proxy-addr", version: "2.0.7", ecosystem: "npm", fixedVersion: "2.0.8" } },
    ] as never);
    const proxy = (await jobs.getFindings(job.id)).findings.find((f) => f.fingerprint === "fp-proxy")!;
    // The registry is unreachable: the fix cannot be confirmed, so none is offered.
    const rem = await createPreview(job.id, proxy.id, { ...rdeps, registryFetch: async () => new Response("down", { status: 503 }) });
    expect(rem).toMatchObject({ eligibility: "unsuitable", unifiedDiff: "" });
    const approve = await handleApproveRemediation(post(`/api/scans/${job.id}/remediation/${rem.id}/approve`, alice), job.id, rem.id, rdeps, OWNER);
    expect(approve.status).toBe(400);
    expect((await approve.json()).error.code).toBe("unsuitable_for_autofix");
    const pr = await createPr(rem.id, alice, diffDigest(""));
    expect(pr.status).toBe(403);
    expect(gh.git.commitBodies).toHaveLength(0);
  });
});
