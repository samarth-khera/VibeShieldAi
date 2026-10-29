import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import type { GithubAppConfig, ServerConfig } from "@/server/config";
import { handleCallback, startConnect, type AuthDeps } from "@/server/auth/service";
import { InMemoryAuthStore } from "@/server/auth/store";
import { handleRepositoryAuthorization, repositoryAuthorizationState } from "@/server/auth/repository-authorization";
import { githubStatus } from "@/server/auth/status";
import { handleCreatePullRequest } from "@/server/remediation/api";
import { approveRemediation, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import type { JobRecord } from "@/server/job-store";
import { InMemoryJobStore } from "@/test/mock-store";
import { FakeGitHubApp } from "@/test/fake-github";

const ORIGIN = "https://vs.example";
const COOKIE = "__Host-vibeshield_session";
const OWNER = "owner-subject-1";
const REQS = "flask==2.0.0\nrequests==2.19.0\nnumpy==1.26.0\n";
const DIFF = "--- a/api/requirements.txt\n+++ b/api/requirements.txt\n@@ -1,3 +1,3 @@\n flask==2.0.0\n-requests==2.19.0\n+requests==2.31.0\n numpy==1.26.0\n";

let gh: FakeGitHubApp;
let store: InMemoryAuthStore;
let app: GithubAppConfig;
let now: Date;
let deps: AuthDeps;
let jobs: InMemoryJobStore;
let job: JobRecord;
let base: string;

beforeEach(async () => {
  gh = new FakeGitHubApp();
  base = gh.git.seed({ "api/requirements.txt": REQS });
  // A repository the user administers that is NOT yet selected in the existing installation, and
  // an app installation that holds "GitHub App installation repository access: write".
  gh.installation.repos = new Set();
  gh.installation.permissions = { ...gh.installation.permissions, installation_repositories: "write" };
  store = new InMemoryAuthStore();
  app = {
    clientId: gh.clientId,
    clientSecret: gh.clientSecret,
    slug: "vibeshield-ai-test",
    encryptionKey: randomBytes(32),
    callbackUrl: `${ORIGIN}/api/auth/github/callback`,
    setupUrl: `${ORIGIN}/api/auth/github/setup`,
    appOrigin: ORIGIN,
  };
  now = new Date("2026-10-30T12:00:00Z");
  deps = { store, app, fetchImpl: gh.fetch, now: () => now };
  jobs = new InMemoryJobStore();
  job = await jobs.create({ owner: "acme", repo: "webapp", repositoryUrl: "https://github.com/acme/webapp", expiresAt: new Date(Date.now() + 3_600_000) });
  await jobs.update(job.id, { status: "completed", commitSha: base, defaultBranch: "main" });
  job = (await jobs.get(job.id))!;
  await store.setScanAccess({ scanJobId: job.id, githubRepoId: 4242, isPrivate: false, githubUserId: null });
});

const cookieOf = (res: Response) => res.headers.get("set-cookie")?.match(new RegExp(`${COOKIE}=([^;]+)`))?.[0] ?? null;
const get = (path: string, cookie?: string | null) => new Request(`${ORIGIN}${path}`, { headers: cookie ? { cookie } : {} });

async function connect(userId: number): Promise<string> {
  const start = await startConnect(get(`/api/auth/github/start?returnTo=%2Freport%2F${job.id}`), deps);
  const loc = new URL(start.headers.get("location")!);
  const code = gh.issueCode(userId, loc.searchParams.get("code_challenge")!);
  const cb = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=${loc.searchParams.get("state")}`, cookieOf(start)), deps);
  return cookieOf(cb)!;
}

type Body = Record<string, unknown>;
/** Union of the prepare/confirm/cancel response fields the tests read. */
type Data = {
  state: string;
  message: string;
  added: boolean;
  cancelled: boolean;
  scannedCommit: string;
  request: { intent: string; expiresAt: string };
  repository: { id: number; fullName: string; canPush: boolean; canAdmin: boolean };
  installation: { id: number; account: string };
  links: { install: string; installationSettings: string | null };
};
async function call(cookie: string | null, body: Body, opts: { jobId?: string; subject?: string; origin?: string } = {}) {
  const jobId = opts.jobId ?? job.id;
  const req = new Request(`${ORIGIN}/api/scans/${jobId}/repository-authorization`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: opts.origin ?? ORIGIN, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  });
  const res = await handleRepositoryAuthorization(req, jobId, { auth: deps, jobs, recheckDelayMs: 0 }, opts.subject ?? OWNER);
  return { status: res.status, json: (await res.json()) as { data?: Data; error?: { code: string; message: string } } };
}
const prepare = (cookie: string | null, extra: Body = {}, opts?: Parameters<typeof call>[2]) => call(cookie, { action: "prepare", ...extra }, opts);
const confirm = (cookie: string | null, prepared: Data, override: Body = {}, opts?: Parameters<typeof call>[2]) =>
  call(cookie, { action: "confirm", intent: prepared.request.intent, repositoryId: prepared.repository.id, installationId: prepared.installation.id, ...override }, opts);
const events = (outcome?: string) => store.events.filter((e) => e.action === "repository_authorization" && (!outcome || e.outcome === outcome));

describe("in-product repository authorization", () => {
  it("adds exactly the scanned repository to the owner's installation only after explicit confirmation", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect(p.status).toBe(200);
    expect(p.json.data).toMatchObject({
      state: "authorization_required",
      repository: { id: 4242, fullName: "acme/webapp", defaultBranch: "main", ownerType: "Organization", canAdmin: true },
      installation: { id: 77, account: "acme", repositorySelection: "selected" },
      scannedCommit: base,
    });
    expect(p.json.data!.request.intent).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    // Preparing (opening the dialog) changes nothing on GitHub.
    expect(gh.repoAdds).toHaveLength(0);
    expect(gh.installation.repos.size).toBe(0);

    const c = await confirm(alice, p.json.data!);
    expect(c.status).toBe(200);
    expect(c.json.data).toMatchObject({ state: "authorized", added: true, repository: { id: 4242 }, installation: { id: 77 } });
    // One PUT, for the canonical repository ID, into the matched installation, with alice's own token.
    expect(gh.repoAdds).toEqual([{ userId: 1001, installationId: 77, repoId: 4242, status: 204 }]);
    expect([...gh.installation.repos]).toEqual([4242]);
    expect(events("requested")).toHaveLength(1);
    expect(events("added")[0]).toMatchObject({ githubLogin: "alice", scanJobId: job.id, repository: "acme/webapp", detail: expect.stringContaining("repo 4242 installation 77") });
    expect(JSON.stringify(store.events)).not.toMatch(/ghu_|ghr_|intent/);
  });

  it("is idempotent: a used request cannot be replayed and an authorized repository needs no new request", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect((await confirm(alice, p.json.data!)).status).toBe(200);
    const replay = await confirm(alice, p.json.data!);
    expect(replay.status).toBe(409);
    expect(replay.json.error!.code).toBe("authorization_request_invalid");
    expect(gh.repoAdds).toHaveLength(1);
    const again = await prepare(alice);
    expect(again.json.data).toMatchObject({ state: "authorized", request: null });
    expect(gh.repoAdds).toHaveLength(1);
  });

  it("does not add anything when the repository is already in the installation", async () => {
    gh.installation.repos.add(4242);
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect(p.json.data).toMatchObject({ state: "authorized", request: null });
    expect(gh.repoAdds).toHaveLength(0);
  });

  it("treats a repository added on GitHub between dialog and confirmation as already present", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    gh.installation.repos.add(4242); // e.g. via GitHub's own settings page meanwhile
    const c = await confirm(alice, p.json.data!);
    expect(c.json.data).toMatchObject({ state: "authorized", added: false });
    expect(gh.repoAdds).toHaveLength(0);
    expect(events("already_present")).toHaveLength(1);
  });

  it("handles concurrent confirmations without adding any other repository", async () => {
    const alice = await connect(1001);
    const [p1, p2] = [await prepare(alice), await prepare(alice)];
    const [c1, c2] = await Promise.all([confirm(alice, p1.json.data!), confirm(alice, p2.json.data!)]);
    expect([c1.status, c2.status]).toEqual([200, 200]);
    expect(gh.repoAdds.every((a) => a.repoId === 4242 && a.installationId === 77)).toBe(true);
    expect([...gh.installation.repos]).toEqual([4242]);
  });

  it("does not let a collaborator without admin access add the repository", async () => {
    gh.push.add(1002); // bob can push but is not an administrator
    const bob = await connect(1002);
    const p = await prepare(bob);
    expect(p.json.data).toMatchObject({ state: "admin_required", request: null, repository: { canPush: true, canAdmin: false } });
    expect(p.json.data!.message).toMatch(/administrator/);
    expect(gh.repoAdds).toHaveLength(0);
    // A forged or guessed request is not accepted either.
    const forged = await call(bob, { action: "confirm", intent: "A".repeat(43), repositoryId: 4242, installationId: 77 });
    expect(forged.json.error!.code).toBe("authorization_request_invalid");
    expect(gh.repoAdds).toHaveLength(0);
  });

  it("reports when GitHub requires an organization owner's approval, without claiming success", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    gh.addRepoStatus = 403;
    const c = await confirm(alice, p.json.data!);
    expect(c.status).toBe(403);
    expect(c.json.error!.code).toBe("organization_approval_required");
    expect(c.json.data).toMatchObject({ state: "authorization_required", links: { install: expect.stringContaining("/api/auth/github/install") } });
    expect(gh.installation.repos.size).toBe(0);
    expect(events("denied")[0].detail).toBe("github forbidden");
  });

  it("requires the one-time app permission before offering in-product authorization", async () => {
    delete gh.installation.permissions.installation_repositories;
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect(p.json.data).toMatchObject({
      state: "app_setup_required",
      request: null,
      links: { installationSettings: "https://github.com/organizations/acme/settings/installations/77" },
    });
    expect(gh.repoAdds).toHaveLength(0);
  });

  it("does not report success when GitHub does not list the repository afterwards", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    gh.addRepoStatus = 204; // GitHub answers 204 but the installation does not change
    const c = await confirm(alice, p.json.data!);
    expect(c.status).toBe(502);
    expect(c.json.error!.code).toBe("authorization_not_confirmed");
    expect(events("not_confirmed")).toHaveLength(1);
    expect(events("added")).toHaveLength(0);
  });

  it("sends users without an installation on the owner account to GitHub's own install flow", async () => {
    gh.installationUsers.delete(1001);
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect(p.json.data).toMatchObject({ state: "installation_required", installation: null, request: null });
    expect(p.json.data!.links.install).toBe(`/api/auth/github/install?returnTo=${encodeURIComponent(`/report/${job.id}`)}`);
  });

  it("matches the installation by the owner's account ID, never another account's installation", async () => {
    gh.otherInstallation = { id: 88, account: "mallory-org", accountId: 666, repos: new Set() };
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect(p.json.data!.installation.id).toBe(77);
    const c = await confirm(alice, p.json.data!, { installationId: 88 });
    expect(c.status).toBe(409);
    expect(c.json.error!.code).toBe("authorization_mismatch");
    expect(gh.repoAdds).toHaveLength(0);
  });

  it("rejects repository, installation, job, owner-session and GitHub-user substitution", async () => {
    const alice = await connect(1001);
    const other = await jobs.create({ owner: "acme", repo: "webapp", repositoryUrl: "https://github.com/acme/webapp", expiresAt: new Date(Date.now() + 3_600_000) });
    await jobs.update(other.id, { status: "completed", commitSha: base });
    const cases: [Body, Parameters<typeof call>[2]][] = [
      [{ repositoryId: 9999 }, {}],
      [{ installationId: 78 }, {}],
      [{}, { jobId: other.id }],
      [{}, { subject: "someone-else" }],
    ];
    for (const [override, opts] of cases) {
      const p = await prepare(alice);
      const c = await confirm(alice, p.json.data!, override, opts);
      expect(c.status).toBe(409);
      expect(c.json.error!.code).toBe("authorization_mismatch");
    }
    // Another browser (another GitHub user) cannot use alice's request: it is bound to her session.
    gh.push.add(1002);
    gh.admin.add(1002);
    const bob = await connect(1002);
    const p = await prepare(alice);
    const stolen = await confirm(bob, p.json.data!);
    expect(stolen.json.error!.code).toBe("authorization_request_invalid");
    expect(gh.repoAdds).toHaveLength(0);
    expect(events("rejected").length).toBeGreaterThanOrEqual(5);
  });

  it("refuses when the repository behind the scan changed (renamed, transferred or recreated)", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    gh.git.repoId = 5555;
    const c = await confirm(alice, p.json.data!);
    expect(c.json.error!.code).toBe("repository_changed");
    expect(gh.repoAdds).toHaveLength(0);
  });

  it("cancellation discards the request", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    const cancel = await call(alice, { action: "cancel", intent: p.json.data!.request.intent });
    expect(cancel.json.data).toEqual({ cancelled: true });
    expect((await confirm(alice, p.json.data!)).json.error!.code).toBe("authorization_request_invalid");
    expect(gh.repoAdds).toHaveLength(0);
    expect(events("cancelled")).toHaveLength(1);
  });

  it("requires a same-origin request, a connected GitHub user and a configured app", async () => {
    const alice = await connect(1001);
    expect((await prepare(alice, {}, { origin: "https://evil.example" })).json.error!.code).toBe("forbidden_origin");
    expect((await prepare(null)).status).toBe(401);
    deps.app = undefined;
    expect((await prepare(alice)).status).toBe(503);
  });

  it("refreshes an expired token, and treats a revoked authorization as disconnected", async () => {
    const alice = await connect(1001);
    now = new Date(now.getTime() + 9 * 3600_000); // past the 8-hour user token
    const p = await prepare(alice);
    expect(p.json.data!.state).toBe("authorization_required");
    expect(gh.oauthCalls.some((c) => c.grant_type === "refresh_token")).toBe(true);
    gh.tokens.clear(); // the user revoked the app on GitHub
    const c = await confirm(alice, p.json.data!);
    expect(c.status).toBe(401);
    expect(c.json.error!.code).toBe("authorization_revoked");
    expect(store.accounts.size).toBe(0);
    expect(gh.repoAdds).toHaveLength(0);
  });

  it("the status view never shows authorization before GitHub confirms it", async () => {
    const alice = await connect(1001);
    const req = get(`/api/auth/github/status?jobId=${job.id}`, alice);
    const before = await githubStatus(req, deps, job);
    expect(before.repository).toMatchObject({ readyToWrite: false, reason: "not_installed", id: 4242, authorization: { state: "authorization_required", installationId: 77 } });
    const p = await prepare(alice);
    await confirm(alice, p.json.data!);
    const after = await githubStatus(req, deps, job);
    expect(after.repository).toMatchObject({ readyToWrite: true, authorization: { state: "authorized" } });
  });
});

describe("authorization states", () => {
  const base = { status: "ok" as const, repoId: 1, canRead: true, canPush: true, canAdmin: true, installed: false, appCanWrite: false };
  const inst = { id: 7, accountLogin: "acme", repositorySelection: "selected" as const, canAddRepositories: true, appCanWrite: true };
  it.each([
    [{ ...base, installed: true, appCanWrite: true }, "authorized"],
    [{ ...base, installed: true, appCanWrite: false }, "app_lacks_permission"],
    [{ ...base, installed: true, appCanWrite: true, canPush: false }, "no_push_permission"],
    [{ ...base, ownerInstallation: inst }, "authorization_required"],
    [{ ...base, ownerInstallation: { ...inst, canAddRepositories: false } }, "app_setup_required"],
    [{ ...base, canAdmin: false, ownerInstallation: inst }, "admin_required"],
    [{ ...base, canAdmin: false, canPush: false, ownerInstallation: inst }, "no_push_permission"],
    [{ ...base }, "installation_required"],
  ])("%# → %s", (access, state) => {
    expect(repositoryAuthorizationState(access)).toBe(state);
  });
});

describe("pull request after in-product authorization", () => {
  it("commits with the user's own authorization and records GitHub's attribution, never a client-supplied author", async () => {
    const alice = await connect(1001);
    const p = await prepare(alice);
    expect((await confirm(alice, p.json.data!)).json.data!.state).toBe("authorized");

    const rem = await jobs.createRemediation({
      id: "0f2b1c3d-aaaa-bbbb-cccc-000000000009",
      scanJobId: job.id,
      findingFingerprints: ["fp"],
      affectedFiles: ["api/requirements.txt"],
      commitSha: base,
      eligibility: "safe",
      eligibilityReason: "Patch-level dependency bump",
      requiresRotation: false,
      patchSummary: "Bump requests",
      unifiedDiff: DIFF,
      status: "preview",
      approvedAt: null,
      rescanStatus: null,
      branchName: null,
      pullRequestUrl: null,
    });
    const rdeps: RemediationDeps = { store: jobs, fetchImpl: gh.fetch, config: { githubApiTimeoutMs: 5000 } as ServerConfig, auth: deps };
    await approveRemediation(job.id, rem.id, rdeps, { ownerSubject: OWNER });
    await jobs.updateRemediation(job.id, rem.id, { status: "verified", rescanStatus: "verified" });
    const prReq = (body: Body) =>
      new Request(`${ORIGIN}/api/scans/${job.id}/remediation/${rem.id}/pr`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, cookie: alice },
        body: JSON.stringify(body),
      });
    // A client-supplied author or committer is refused outright; nothing is written.
    const spoofed = await handleCreatePullRequest(
      prReq({ approvedDiffSha256: diffDigest(DIFF), author: { name: "Linus Torvalds", email: "torvalds@example.com" } }),
      job.id,
      rem.id,
      rdeps,
      OWNER,
    );
    expect(spoofed.status).toBe(400);
    expect(gh.git.commitBodies).toHaveLength(0);
    const res = await handleCreatePullRequest(prReq({ approvedDiffSha256: diffDigest(DIFF) }), job.id, rem.id, rdeps, OWNER);
    expect(res.status).toBe(201);
    const pr = (await res.json()).data.pullRequest;
    expect(pr).toMatchObject({
      status: "created",
      url: "https://github.com/acme/webapp/pull/1",
      openedBy: { login: "alice" },
      commit: { authorName: "alice", authorEmailIsNoreply: true, verified: true, url: expect.stringContaining(pr.headSha) },
    });
    expect(JSON.stringify(pr)).not.toMatch(/@users\.noreply/); // no email address is stored
    // Nothing about authorship is sent to GitHub; GitHub attributes the commit to the token's user.
    expect(gh.git.commitBodies).toHaveLength(1);
    expect(Object.keys(gh.git.commitBodies[0]).sort()).toEqual(["message", "parents", "tree"]);
    expect(gh.git.pulls[0].body).toMatch(/on behalf of @alice/);
    expect(gh.git.refs.get("heads/main")).toBe(base);
  });
});
