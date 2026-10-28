import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { GithubAppConfig, ServerConfig } from "@/server/config";
import { decryptSecret, encryptSecret, parseEncryptionKey } from "@/server/auth/crypto";
import {
  disconnect,
  getUserToken,
  handleCallback,
  handleSetup,
  safeReturnTo,
  startConnect,
  startInstall,
  type AuthDeps,
} from "@/server/auth/service";
import { InMemoryAuthStore } from "@/server/auth/store";
import { authorizeRepository, checkJobAccess } from "@/server/auth/repository-access";
import { githubStatus } from "@/server/auth/status";
import { resolveRepositoryForScan } from "@/server/auth/scan-gate";
import { repositoryUrlForWorker, resolvePrivateSource } from "@/server/auth/private-source";
import { handleCreatePullRequest, handleDownloadPatch } from "@/server/remediation/api";
import { approveRemediation, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import { submitScan, type ScanDeps } from "@/server/scans-service";
import { InMemoryJobStore } from "@/test/mock-store";
import { FakeGitHubApp } from "@/test/fake-github";

const ORIGIN = "https://vs.example";
const COOKIE = "__Host-vibeshield_session";
const REQS = "flask==2.0.0\nrequests==2.19.0\nnumpy==1.26.0\n";
const DIFF = "--- a/api/requirements.txt\n+++ b/api/requirements.txt\n@@ -2,1 +2,1 @@\n-requests==2.19.0\n+requests==2.31.0\n";

let gh: FakeGitHubApp;
let store: InMemoryAuthStore;
let app: GithubAppConfig;
let now: Date;
let deps: AuthDeps;
let base: string;

beforeEach(() => {
  gh = new FakeGitHubApp();
  base = gh.git.seed({ "api/requirements.txt": REQS, "README.md": "# app\n" });
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
  now = new Date("2026-10-28T12:00:00Z");
  deps = { store, app, fetchImpl: gh.fetch, now: () => now };
});

const cookieOf = (res: Response) => {
  const c = res.headers.get("set-cookie");
  const m = c?.match(new RegExp(`${COOKIE}=([^;]+)`));
  return m ? `${COOKIE}=${m[1]}` : null;
};
const get = (path: string, cookie?: string | null) => new Request(`${ORIGIN}${path}`, { headers: cookie ? { cookie } : {} });

/** Drives the real redirect flow: start → GitHub consent (modelled) → callback. Returns the session cookie. */
async function connect(userId: number, returnTo = "/report/job1"): Promise<string> {
  const start = await startConnect(get(`/api/auth/github/start?returnTo=${encodeURIComponent(returnTo)}`), deps);
  const loc = new URL(start.headers.get("location")!);
  const code = gh.issueCode(userId, loc.searchParams.get("code_challenge")!);
  const cb = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=${loc.searchParams.get("state")}`, cookieOf(start)), deps);
  expect(cb.headers.get("location")).toContain("github=connected");
  return cookieOf(cb)!;
}

describe("token encryption", () => {
  it("round-trips, detects tampering and rejects malformed keys", () => {
    const key = randomBytes(32);
    const enc = encryptSecret("ghu_secret", key);
    expect(enc).not.toContain("ghu_secret");
    expect(decryptSecret(enc, key)).toBe("ghu_secret");
    const parts = enc.split(".");
    parts[3] = Buffer.from("tampered").toString("base64url");
    expect(() => decryptSecret(parts.join("."), key)).toThrow();
    expect(() => decryptSecret(enc, randomBytes(32))).toThrow();
    expect(parseEncryptionKey("too-short")).toBeNull();
    expect(parseEncryptionKey(key.toString("base64"))?.equals(key)).toBe(true);
    expect(parseEncryptionKey(key.toString("hex"))?.equals(key)).toBe(true);
  });
});

describe("authorization initiation and callback", () => {
  it("redirects to GitHub with PKCE and a hashed single-use state, using a Secure HttpOnly SameSite cookie", async () => {
    const res = await startConnect(get("/api/auth/github/start?returnTo=%2Freport%2Fjob1"), deps);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(loc.searchParams.get("client_id")).toBe(gh.clientId);
    expect(loc.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/api/auth/github/callback`);
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
    const state = loc.searchParams.get("state")!;
    expect(state.length).toBeGreaterThanOrEqual(40);
    expect(store.states.has(state)).toBe(false); // only the hash is stored
    const cookie = res.headers.get("set-cookie")!;
    expect(cookie).toMatch(/^__Host-vibeshield_session=[A-Za-z0-9_-]+; Path=\/; HttpOnly; SameSite=Lax; Max-Age=\d+; Secure$/);
  });

  it("refuses open redirects in returnTo", () => {
    for (const bad of ["//evil.example", "https://evil.example", "/\\evil", "/report/x/../../admin", "javascript:alert(1)"]) {
      expect(safeReturnTo(bad)).toBe("/");
    }
    expect(safeReturnTo("/report/abc_DEF-1?finding=f1&mode=autofix")).toBe("/report/abc_DEF-1?finding=f1&mode=autofix");
  });

  it("stores only encrypted tokens, rotates the session, audits, and returns to the report", async () => {
    const cookie = await connect(1001);
    const acct = [...store.accounts.values()][0];
    expect(acct).toMatchObject({ githubUserId: 1001, login: "alice" });
    expect(acct.accessTokenEnc).not.toMatch(/ghu_/);
    expect(acct.refreshTokenEnc).not.toMatch(/ghr_/);
    expect(decryptSecret(acct.accessTokenEnc, app.encryptionKey)).toMatch(/^ghu_test_1001_/);
    // Pre-authentication session revoked; only the rotated one is linked.
    const sessions = [...store.sessions.values()];
    expect(sessions.filter((s) => s.revokedAt)).toHaveLength(1);
    expect(sessions.filter((s) => s.accountId === acct.id)).toHaveLength(1);
    expect(cookie).toMatch(/^__Host-vibeshield_session=/);
    expect(store.events).toContainEqual(expect.objectContaining({ action: "github_connect", outcome: "success", githubLogin: "alice" }));
    expect(JSON.stringify(store.events)).not.toMatch(/ghu_|ghr_|code-/);
  });

  it("rejects missing, unknown, expired and replayed state without exchanging the code", async () => {
    const start = await startConnect(get("/api/auth/github/start"), deps);
    const cookie = cookieOf(start);
    const loc = new URL(start.headers.get("location")!);
    const state = loc.searchParams.get("state")!;
    const code = gh.issueCode(1001, loc.searchParams.get("code_challenge")!);

    const missing = await handleCallback(get(`/api/auth/github/callback?code=${code}`, cookie), deps);
    expect(missing.headers.get("location")).toContain("reason=state_invalid");
    const unknown = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=forged-state-value-xxxxxxxxxxxxxxxx`, cookie), deps);
    expect(unknown.headers.get("location")).toContain("reason=state_invalid");

    now = new Date(now.getTime() + 11 * 60_000); // past the 10-minute state lifetime
    const expired = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=${state}`, cookie), deps);
    expect(expired.headers.get("location")).toContain("reason=state_invalid");
    expect(gh.oauthCalls).toHaveLength(0);

    now = new Date("2026-10-28T12:00:00Z");
    const fresh = await startConnect(get("/api/auth/github/start"), deps);
    const fl = new URL(fresh.headers.get("location")!);
    const c2 = gh.issueCode(1001, fl.searchParams.get("code_challenge")!);
    const url = `/api/auth/github/callback?code=${c2}&state=${fl.searchParams.get("state")}`;
    expect((await handleCallback(get(url, cookieOf(fresh)), deps)).headers.get("location")).toContain("github=connected");
    const replay = await handleCallback(get(url, cookieOf(fresh)), deps);
    expect(replay.headers.get("location")).toContain("reason=state_invalid");
    expect(gh.oauthCalls).toHaveLength(1);
  });

  it("blocks CSRF/session swapping: a state started in one browser can't complete in another", async () => {
    // The attacker starts a flow in their own browser and sends the victim the callback link.
    const attacker = await startConnect(get("/api/auth/github/start"), deps);
    const loc = new URL(attacker.headers.get("location")!);
    const code = gh.issueCode(1003, loc.searchParams.get("code_challenge")!);
    const victim = await startConnect(get("/api/auth/github/start"), deps); // victim has their own session
    const res = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=${loc.searchParams.get("state")}`, cookieOf(victim)), deps);
    expect(res.headers.get("location")).toContain("reason=state_invalid");
    expect(store.accounts.size).toBe(0);
    expect(gh.oauthCalls).toHaveLength(0);
    // And with no session cookie at all.
    const none = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=${loc.searchParams.get("state")}`), deps);
    expect(none.headers.get("location")).toContain("reason=state_invalid");
  });

  it("rejects a code whose PKCE verifier does not match, and handles a declined consent", async () => {
    const start = await startConnect(get("/api/auth/github/start?returnTo=%2Freport%2Fjob1"), deps);
    const loc = new URL(start.headers.get("location")!);
    const code = gh.issueCode(1001, "a-different-challenge");
    const res = await handleCallback(get(`/api/auth/github/callback?code=${code}&state=${loc.searchParams.get("state")}`, cookieOf(start)), deps);
    expect(res.headers.get("location")).toContain("reason=bad_verification_code");
    expect(store.accounts.size).toBe(0);

    const s2 = await startConnect(get("/api/auth/github/start?returnTo=%2Freport%2Fjob1"), deps);
    const l2 = new URL(s2.headers.get("location")!);
    const declined = await handleCallback(get(`/api/auth/github/callback?error=access_denied&state=${l2.searchParams.get("state")}`, cookieOf(s2)), deps);
    expect(declined.headers.get("location")).toBe("/report/job1?github=cancelled");
  });

  it("reports not_configured without touching storage when the app is not set up", async () => {
    const off = { ...deps, app: undefined };
    expect((await startConnect(get("/api/auth/github/start"), off)).headers.get("location")).toBe("/?github=not_configured");
    expect(store.sessions.size).toBe(0);
    const status = await githubStatus(get("/api/auth/github/status"), off, null);
    expect(status).toMatchObject({ configured: false, unavailableReason: "not_configured", connected: false });
  });
});

describe("installation flow", () => {
  it("requires a connected session, then sends the user to GitHub's installation page with state", async () => {
    const anon = await startInstall(get("/api/auth/github/install?returnTo=%2Freport%2Fjob1"), deps);
    expect(anon.headers.get("location")).toBe("/report/job1?github=connect_first");
    const cookie = await connect(1001);
    const res = await startInstall(get("/api/auth/github/install?returnTo=%2Freport%2Fjob1", cookie), deps);
    const loc = new URL(res.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe("https://github.com/apps/vibeshield-ai-test/installations/new");
    expect(loc.searchParams.get("state")).toBeTruthy();
  });

  it("never trusts installation_id from the URL: it must be one GitHub lists for the user's token", async () => {
    const cookie = await connect(1001);
    const begin = async () =>
      new URL((await startInstall(get("/api/auth/github/install?returnTo=%2Freport%2Fjob1", cookie), deps)).headers.get("location")!).searchParams.get("state")!;
    const forged = await handleSetup(get(`/api/auth/github/setup?installation_id=999&setup_action=install&state=${await begin()}`, cookie), deps);
    expect(forged.headers.get("location")).toBe("/report/job1?github=installation_not_verified");
    const state = await begin();
    const ok = await handleSetup(get(`/api/auth/github/setup?installation_id=77&setup_action=install&state=${state}`, cookie), deps);
    expect(ok.headers.get("location")).toBe("/report/job1?github=installed");
    const replay = await handleSetup(get(`/api/auth/github/setup?installation_id=77&setup_action=install&state=${state}`, cookie), deps);
    expect(replay.headers.get("location")).toContain("reason=state_invalid");
    const requested = await handleSetup(get(`/api/auth/github/setup?setup_action=request&state=${await begin()}`, cookie), deps);
    expect(requested.headers.get("location")).toBe("/report/job1?github=install_requested");
  });
});

describe("token lifecycle", () => {
  it("refreshes an expired user token, and treats a rejected refresh as expired authorization", async () => {
    const cookie = await connect(1001);
    const acct = [...store.accounts.values()][0];
    now = new Date(now.getTime() + 9 * 3600_000); // past the 8-hour access-token lifetime
    const t = await getUserToken(acct, deps);
    expect("token" in t && gh.tokens.get(t.token)).toBe(1001);
    expect(gh.oauthCalls.at(-1)).toMatchObject({ grant_type: "refresh_token" });

    // GitHub refresh tokens are single use: replaying the old one fails, and the stale record is not reused.
    now = new Date(now.getTime() + 9 * 3600_000);
    gh.refreshTokens.clear();
    const fresh = [...store.accounts.values()][0];
    expect(await getUserToken(fresh, deps)).toEqual({ error: "authorization_expired" });
    expect(store.accounts.size).toBe(0);
    expect(store.events).toContainEqual(expect.objectContaining({ action: "github_authorization_lost", outcome: "refresh_rejected" }));
    const status = await githubStatus(get("/api/auth/github/status", cookie), deps, null);
    expect(status.connected).toBe(false);
  });

  it("uses the token another request just refreshed instead of discarding the account", async () => {
    await connect(1001);
    const stale = [...store.accounts.values()][0];
    now = new Date(now.getTime() + 9 * 3600_000);
    const first = await getUserToken(stale, deps); // refreshes and stores new tokens
    const second = await getUserToken(stale, deps); // same stale snapshot: its refresh token is now spent
    expect("token" in first && "token" in second).toBe(true);
    expect(store.accounts.size).toBe(1);
  });

  it("asks to reconnect (not a 500) after the encryption key is rotated", async () => {
    const cookie = await connect(1001);
    deps.app = { ...app, encryptionKey: randomBytes(32) };
    const r = await authorizeRepository(get("/x", cookie), deps, { owner: "acme", repo: "webapp" }, null, "write");
    expect(r).toMatchObject({ ok: false, code: "authorization_expired" });
    expect(store.accounts.size).toBe(0);
  });

  it("detects a token revoked on GitHub and forgets it", async () => {
    const cookie = await connect(1001);
    gh.tokens.clear(); // user revoked the app in GitHub settings
    const r = await authorizeRepository(get("/x", cookie), deps, { owner: "acme", repo: "webapp" }, null, "write");
    expect(r).toMatchObject({ ok: false, code: "authorization_revoked" });
    expect(store.accounts.size).toBe(0);
  });

  it("disconnect revokes the grant at GitHub, deletes tokens, refuses cross-site requests, and audits", async () => {
    const cookie = await connect(1001);
    const xsite = await disconnect(new Request(`${ORIGIN}/api/auth/github/disconnect`, { method: "POST", headers: { cookie, origin: "https://evil.example" } }), deps);
    expect(xsite.status).toBe(403);
    expect(store.accounts.size).toBe(1);
    const res = await disconnect(new Request(`${ORIGIN}/api/auth/github/disconnect`, { method: "POST", headers: { cookie, origin: ORIGIN } }), deps);
    expect(await res.json()).toEqual({ data: { connected: false, revokedAtGitHub: true } });
    expect(gh.revoked).toHaveLength(1);
    expect(gh.tokens.size).toBe(0);
    expect(store.accounts.size).toBe(0);
    expect(store.events).toContainEqual(expect.objectContaining({ action: "github_disconnect", outcome: "revoked", githubLogin: "alice" }));
  });
});

describe("repository authorization (live, per request)", () => {
  const job = { id: "job1", owner: "acme", repo: "webapp" };
  const access = { scanJobId: "job1", githubRepoId: 4242, isPrivate: false, githubUserId: null };

  it("confirms read and write for a user who can push to an installed repository", async () => {
    const cookie = await connect(1001);
    const r = await authorizeRepository(get("/x", cookie), deps, job, access, "write");
    expect(r.ok).toBe(true);
    const status = await githubStatus(get("/x", cookie), deps, job);
    expect(status.repository).toMatchObject({ canRead: true, canPush: true, installed: true, appCanWrite: true, readyToWrite: true });
  });

  it("distinguishes not connected, no push permission, not installed, repository removed and missing app permission", async () => {
    expect(await authorizeRepository(get("/x"), deps, job, access, "write")).toMatchObject({ ok: false, code: "not_connected" });

    const bob = await connect(1002);
    expect(await authorizeRepository(get("/x", bob), deps, job, access, "write")).toMatchObject({ ok: false, code: "no_push_permission" });
    expect((await authorizeRepository(get("/x", bob), deps, job, access, "read")).ok).toBe(true);

    const alice = await connect(1001);
    gh.installation.repos.clear(); // repository removed from the installation on GitHub
    expect(await authorizeRepository(get("/x", alice), deps, job, access, "write")).toMatchObject({ ok: false, code: "not_installed" });
    gh.installation.repos.add(4242);
    gh.installation.permissions.contents = "read";
    expect(await authorizeRepository(get("/x", alice), deps, job, access, "write")).toMatchObject({ ok: false, code: "app_lacks_permission" });
    gh.installation.permissions.contents = "write";
    gh.installationUsers.clear(); // installation removed
    expect(await authorizeRepository(get("/x", alice), deps, job, access, "write")).toMatchObject({ ok: false, code: "not_installed" });
  });

  it("rejects a repository whose immutable ID differs from the scan's (recreated or substituted)", async () => {
    const cookie = await connect(1001);
    const r = await authorizeRepository(get("/x", cookie), deps, job, { ...access, githubRepoId: 1 }, "write");
    expect(r).toMatchObject({ ok: false, code: "repository_changed" });
  });
});

describe("pull request endpoint", () => {
  const config = { githubApiTimeoutMs: 5000 } as ServerConfig;

  async function setup(status: "verified" | "needs_review" | "approved" = "verified") {
    const jobs = new InMemoryJobStore();
    const job = await jobs.create({ owner: "acme", repo: "webapp", repositoryUrl: "https://github.com/acme/webapp", expiresAt: new Date(Date.now() + 3_600_000) });
    await jobs.update(job.id, { status: "completed", commitSha: base, defaultBranch: "main" });
    await store.setScanAccess({ scanJobId: job.id, githubRepoId: 4242, isPrivate: false, githubUserId: null });
    const rem = await jobs.createRemediation({
      id: "0f2b1c3d-aaaa-bbbb-cccc-000000000002",
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
    const rdeps: RemediationDeps = { store: jobs, fetchImpl: gh.fetch, config, auth: deps };
    await approveRemediation(job.id, rem.id, rdeps);
    if (status !== "approved") await jobs.updateRemediation(job.id, rem.id, { status, rescanStatus: status });
    return { jobs, job, rem, rdeps };
  }
  const prRequest = (jobId: string, remId: string, cookie: string | null, digest = diffDigest(DIFF), origin = ORIGIN) =>
    new Request(`${ORIGIN}/api/scans/${jobId}/remediation/${remId}/pr`, {
      method: "POST",
      headers: { "content-type": "application/json", origin, ...(cookie ? { cookie } : {}) },
      body: JSON.stringify({ approvedDiffSha256: digest }),
    });

  it("opens the PR with the requesting user's own token only, idempotently, and audits it", async () => {
    const { job, rem, rdeps } = await setup();
    const cookie = await connect(1001);
    const res = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, rdeps);
    expect(res.status).toBe(201);
    const body = (await res.json()).data;
    expect(body.pullRequest).toMatchObject({ status: "created", number: 1, openedBy: { githubUserId: 1001, login: "alice" } });
    expect(body.remediation.pullRequestUrl).toBe("https://github.com/acme/webapp/pull/1");
    const head = gh.git.refs.get(`heads/${body.pullRequest.branch}`)!;
    expect(gh.git.commits.get(head)!.parents).toEqual([base]);
    expect(gh.git.refs.get("heads/main")).toBe(base);
    // Every write went out with alice's user-to-server token; nothing else.
    const writes = gh.git.calls.filter((c) => c.method !== "GET");
    expect(writes.length).toBeGreaterThan(0);
    expect(writes.every((c) => /^Bearer ghu_test_1001_/.test(c.auth ?? ""))).toBe(true);
    expect(store.events).toContainEqual(expect.objectContaining({ action: "pull_request", outcome: "created", githubLogin: "alice", detail: "#1" }));

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16_000);
    const again = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, rdeps);
    vi.useRealTimers();
    expect((await again.json()).data.pullRequest).toMatchObject({ status: "exists", number: 1 });
    expect(gh.git.pulls).toHaveLength(1);
  });

  it("never lets one user's authorization serve another session", async () => {
    const { job, rem, rdeps } = await setup();
    await connect(1001); // alice is connected in her own browser
    const anonymous = await handleCreatePullRequest(prRequest(job.id, rem.id, null), job.id, rem.id, rdeps);
    expect(anonymous.status).toBe(401);
    expect((await anonymous.json()).error.code).toBe("not_connected");
    const mallory = await connect(1003);
    const res = await handleCreatePullRequest(prRequest(job.id, rem.id, mallory), job.id, rem.id, rdeps);
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("repository_not_found");
    expect(gh.git.pulls).toHaveLength(0);
  });

  it("denies a user without write access and records the denial", async () => {
    const { job, rem, rdeps } = await setup();
    const bob = await connect(1002);
    const res = await handleCreatePullRequest(prRequest(job.id, rem.id, bob), job.id, rem.id, rdeps);
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("no_push_permission");
    expect(store.events).toContainEqual(expect.objectContaining({ action: "pull_request", outcome: "denied", detail: "no_push_permission" }));
  });

  it("enforces approval, verification and the exact approved diff", async () => {
    const cookie = await connect(1001);
    for (const status of ["approved", "needs_review"] as const) {
      const { job, rem, rdeps } = await setup(status);
      const res = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, rdeps);
      expect(res.status).toBe(409);
      expect((await res.json()).error.code).toBe("not_verified");
    }
    const { job, rem, rdeps, jobs } = await setup();
    const wrong = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie, "0".repeat(64)), job.id, rem.id, rdeps);
    expect((await wrong.json()).error.code).toBe("diff_confirmation_mismatch");
    await jobs.updateRemediation(job.id, rem.id, { unifiedDiff: DIFF.replace("2.31.0", "9.9.9") });
    const swapped = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie, diffDigest(DIFF.replace("2.31.0", "9.9.9"))), job.id, rem.id, rdeps);
    expect((await swapped.json()).error.code).toBe("patch_mismatch");
    const unapproved = await setup("approved");
    await unapproved.jobs.updateRemediation(unapproved.job.id, unapproved.rem.id, { approvedAt: null, status: "verified", rescanStatus: "verified" });
    const r = await handleCreatePullRequest(prRequest(unapproved.job.id, unapproved.rem.id, cookie), unapproved.job.id, unapproved.rem.id, unapproved.rdeps);
    expect((await r.json()).error.code).toBe("approval_required");
    expect(gh.git.pulls).toHaveLength(0);
  });

  it("rejects a repository substituted after the scan and a commit that does not belong to the job", async () => {
    const cookie = await connect(1001);
    const { job, rem, rdeps, jobs } = await setup();
    gh.git.repoId = 5555; // repository deleted and recreated under the same name
    gh.installation.repos.add(5555);
    const res = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, rdeps);
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("repository_changed");
    gh.git.repoId = 4242;
    await jobs.update(job.id, { commitSha: "e".repeat(40) });
    const moved = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, rdeps);
    expect((await moved.json()).error.code).toBe("commit_mismatch");
    expect(gh.git.pulls).toHaveLength(0);
  });

  it("refuses cross-site requests and answers not_configured, keeping the patch download, when the app is absent", async () => {
    const { job, rem, rdeps } = await setup();
    const cookie = await connect(1001);
    const xsite = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie, diffDigest(DIFF), "https://evil.example"), job.id, rem.id, rdeps);
    expect(xsite.status).toBe(403);
    const off = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, { ...rdeps, auth: { ...deps, app: undefined } });
    expect(off.status).toBe(503);
    expect((await off.json()).error.code).toBe("not_configured");
    const patch = await handleDownloadPatch(job.id, rem.id, rdeps);
    expect(patch.status).toBe(200);
    expect(await patch.text()).toBe(DIFF);
  });

  it("rejects after disconnect", async () => {
    const { job, rem, rdeps } = await setup();
    const cookie = await connect(1001);
    await disconnect(new Request(`${ORIGIN}/api/auth/github/disconnect`, { method: "POST", headers: { cookie, origin: ORIGIN } }), deps);
    const res = await handleCreatePullRequest(prRequest(job.id, rem.id, cookie), job.id, rem.id, rdeps);
    expect(res.status).toBe(401);
    expect(gh.git.pulls).toHaveLength(0);
  });
});

describe("private repositories", () => {
  const scanConfig = {
    maxArchiveBytes: 50 * 1024 * 1024,
    githubApiTimeoutMs: 5000,
    jobTtlHours: 24,
    maxScansPerIpHourly: 10,
    maxScansPerIpDaily: 10,
    globalDailyScanCap: 100,
    maxConcurrentHeavyScans: 2,
    maxQueuedScans: 10,
    jobTimeoutMs: 900_000,
    queueTimeoutMs: 1_800_000,
    warmWorkerEnabled: false,
    warmLeaseMs: 60_000,
    warmWorkerHealthyMs: 30_000,
    warmWorkerGraceMs: 10_000,
    appUrl: ORIGIN,
  } as ServerConfig;

  const publicCheck = async () =>
    gh.isPrivate ? { ok: false, code: "not_found_or_private", error: "nf" } : { ok: true, repoId: 4242 };

  function scanDeps(order: string[] = []) {
    const jobs = new InMemoryJobStore();
    const create = jobs.create.bind(jobs);
    jobs.create = async (d) => {
      order.push("job");
      return create(d);
    };
    const enqueued: string[] = [];
    const d: ScanDeps = {
      store: jobs,
      config: scanConfig,
      enqueue: async (id, _a, url) => {
        enqueued.push(await repositoryUrlForWorker(id, url ?? "", deps));
      },
      rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: async () => true,
      resolveRepository: (req, o, r) => resolveRepositoryForScan(req, o, r, deps, publicCheck),
      recordScanAccess: async (rec) => {
        order.push(rec.isPrivate ? "private-access" : "public-access");
        await store.setScanAccess(rec);
      },
    };
    return { d, jobs, enqueued };
  }
  const submit = (d: ScanDeps, cookie?: string) =>
    submitScan(
      new Request(`${ORIGIN}/api/scans`, {
        method: "POST",
        headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
        body: JSON.stringify({ repositoryUrl: "https://github.com/acme/webapp" }),
      }),
      d,
    );

  it("scans a public repository without any GitHub connection and records its immutable ID", async () => {
    const { d, enqueued } = scanDeps();
    const res = await submit(d);
    expect(res.status).toBe(202);
    const id = (await res.json()).data.id;
    expect(await store.getScanAccess(id)).toMatchObject({ githubRepoId: 4242, isPrivate: false, githubUserId: null });
    expect(enqueued).toEqual(["https://github.com/acme/webapp"]);
  });

  it("requires authorization for a private repository and never reveals whether it exists", async () => {
    gh.isPrivate = true;
    const { d } = scanDeps();
    const anon = await submit(d);
    expect(anon.status).toBe(403);
    expect((await anon.json()).error.code).toBe("authorization_required");
    const mallory = await connect(1003);
    const denied = await submit(d, mallory);
    expect(denied.status).toBe(400);
    expect((await denied.json()).error.code).toBe("not_found_or_private");
  });

  it("scans a private repository for an authorized user, writing the access record before the job, and hides it from others", async () => {
    gh.isPrivate = true;
    const order: string[] = [];
    const { d, jobs, enqueued } = scanDeps(order);
    const alice = await connect(1001);
    const res = await submit(d, alice);
    expect(res.status).toBe(202);
    const id = (await res.json()).data.id;
    expect(order).toEqual(["private-access", "job"]);
    expect(await store.getScanAccess(id)).toMatchObject({ isPrivate: true, githubUserId: 1001, githubRepoId: 4242 });
    // The workflow/claim value is a placeholder: the private name never reaches public workflow inputs.
    expect(enqueued).toEqual(["private"]);

    const job = (await jobs.get(id))!;
    expect((await checkJobAccess(get("/x", alice), deps, job)).denied).toBeNull();
    const bob = await connect(1002); // bob can read the repo on GitHub, but did not authorize this scan
    expect((await checkJobAccess(get("/x", bob), deps, job)).denied?.status).toBe(404);
    expect((await checkJobAccess(get("/x"), deps, job)).denied?.status).toBe(404);
    // Live operations re-check access with GitHub: removed from the installation means denied.
    gh.installation.repos.clear();
    const live = await checkJobAccess(get("/x", alice), deps, job, { live: true });
    expect(live.denied).not.toBeNull();
  });

  it("gives workers a short-lived archive URL, never the user's token, and fails closed when access is lost", async () => {
    gh.isPrivate = true;
    await connect(1001);
    const job = { id: "jobp", owner: "acme", repo: "webapp", commitSha: base };
    const rec = { scanJobId: "jobp", githubRepoId: 4242, isPrivate: true, githubUserId: 1001 };
    const src = await resolvePrivateSource(job, rec, "verify", deps, scanConfig);
    expect(src).toMatchObject({ commitSha: base, defaultBranch: "main" });
    expect((src as { archiveUrl: string }).archiveUrl).toMatch(/^https:\/\/codeload\.github\.com\//);
    expect(JSON.stringify(src)).not.toMatch(/ghu_|ghr_/);
    const scan = await resolvePrivateSource(job, rec, "scan", deps, scanConfig);
    expect(scan).toMatchObject({ commitSha: base });

    gh.read.delete(1001);
    expect(await resolvePrivateSource(job, rec, "scan", deps, scanConfig)).toEqual({ code: "access_lost" });
    gh.read.add(1001);
    gh.git.repoId = 9;
    gh.installation.repos.add(9);
    expect(await resolvePrivateSource(job, rec, "scan", deps, scanConfig)).toEqual({ code: "repository_changed" });
    expect(await resolvePrivateSource(job, { ...rec, isPrivate: false }, "scan", deps, scanConfig)).toEqual({ code: "not_private" });
  });
});
