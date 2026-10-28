import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createRemediationPullRequest, remediationBranchName } from "@/server/remediation/github-pr";
import { applyDiffStrict, DiffApplyError } from "@/server/remediation/strict-apply";
import { handleCreatePullRequest } from "@/server/remediation/api";
import { approveRemediation, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import type { ServerConfig } from "@/server/config";
import { InMemoryJobStore } from "@/test/mock-store";

/**
 * A small content-addressed model of GitHub's Git Data + Pulls API: enough to prove that the PR
 * branch holds exactly the patched files on top of the scanned commit, and that retries converge.
 */
type Entry = { path: string; mode: string; type: "blob" | "tree"; sha: string };
class FakeGitHub {
  blobs = new Map<string, string>();
  trees = new Map<string, Entry[]>();
  commits = new Map<string, { tree: string; parents: string[]; message: string }>();
  refs = new Map<string, string>();
  pulls: { number: number; head: string; base: string; title: string; body: string; state: string; merged_at: null }[] = [];
  calls: { method: string; path: string }[] = [];
  repo = { full_name: "acme/webapp", default_branch: "main", archived: false, permissions: { push: true } };
  mode: "ok" | "unauthorized" | "deny_writes" | "rate_limited" | "offline" | "missing_repo" = "ok";

  private sha(kind: string, data: unknown) {
    return createHash("sha1").update(kind + JSON.stringify(data)).digest("hex");
  }
  blob(content: string) {
    const sha = this.sha("blob", content);
    this.blobs.set(sha, content);
    return sha;
  }
  tree(entries: Entry[]) {
    const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));
    const sha = this.sha("tree", sorted);
    this.trees.set(sha, sorted);
    return sha;
  }
  /** Builds nested trees from a flat path → entry map. */
  build(flat: Map<string, { mode: string; sha: string }>): string {
    const here: Entry[] = [];
    const dirs = new Map<string, Map<string, { mode: string; sha: string }>>();
    for (const [p, e] of flat) {
      const [head, ...rest] = p.split("/");
      if (rest.length === 0) here.push({ path: head, mode: e.mode, type: "blob", sha: e.sha });
      else {
        if (!dirs.has(head)) dirs.set(head, new Map());
        dirs.get(head)!.set(rest.join("/"), e);
      }
    }
    for (const [name, sub] of dirs) here.push({ path: name, mode: "040000", type: "tree", sha: this.build(sub) });
    return this.tree(here);
  }
  flatten(treeSha: string, prefix = ""): Map<string, { mode: string; sha: string }> {
    const out = new Map<string, { mode: string; sha: string }>();
    for (const e of this.trees.get(treeSha) ?? []) {
      if (e.type === "tree") for (const [p, v] of this.flatten(e.sha, `${prefix}${e.path}/`)) out.set(p, v);
      else out.set(`${prefix}${e.path}`, { mode: e.mode, sha: e.sha });
    }
    return out;
  }
  seed(files: Record<string, string | { content: string; mode: string }>): string {
    const flat = new Map<string, { mode: string; sha: string }>();
    for (const [p, v] of Object.entries(files)) {
      const { content, mode } = typeof v === "string" ? { content: v, mode: "100644" } : v;
      flat.set(p, { mode, sha: this.blob(content) });
    }
    const tree = this.build(flat);
    const sha = this.sha("commit", { tree, parents: [] });
    this.commits.set(sha, { tree, parents: [], message: "init" });
    this.refs.set("heads/main", sha);
    return sha;
  }
  filesAt(commitSha: string): Record<string, string> {
    const c = this.commits.get(commitSha)!;
    return Object.fromEntries([...this.flatten(c.tree)].map(([p, e]) => [p, this.blobs.get(e.sha)!]));
  }

  fetch = async (url: string, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    const path = url.replace("https://api.github.com/repos/acme/webapp", "");
    this.calls.push({ method, path });
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    if (this.mode === "offline") throw new TypeError("fetch failed");
    if (this.mode === "unauthorized") return json(401, { message: "Bad credentials" });
    if (this.mode === "rate_limited") return json(403, { message: "API rate limit exceeded" }, { "x-ratelimit-remaining": "0" });
    if (this.mode === "missing_repo") return json(404, { message: "Not Found" });
    if (this.mode === "deny_writes" && method !== "GET") return json(403, { message: "Resource not accessible by personal access token" });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;

    if (method === "GET" && path === "") return json(200, this.repo);
    let m: RegExpMatchArray | null;
    if (method === "GET" && (m = path.match(/^\/git\/commits\/([0-9a-f]+)$/))) {
      const c = this.commits.get(m[1]);
      return c ? json(200, { sha: m[1], tree: { sha: c.tree }, parents: c.parents.map((sha) => ({ sha })) }) : json(404, {});
    }
    if (method === "GET" && (m = path.match(/^\/git\/trees\/([0-9a-f]+)$/))) {
      const t = this.trees.get(m[1]);
      return t ? json(200, { sha: m[1], tree: t }) : json(404, {});
    }
    if (method === "GET" && (m = path.match(/^\/git\/blobs\/([0-9a-f]+)$/))) {
      const b = this.blobs.get(m[1]);
      return b === undefined ? json(404, {}) : json(200, { encoding: "base64", content: Buffer.from(b).toString("base64") });
    }
    if (method === "POST" && path === "/git/trees") {
      const flat = this.flatten(body.base_tree);
      for (const e of body.tree) flat.set(e.path, { mode: e.mode, sha: this.blob(e.content) });
      return json(201, { sha: this.build(flat) });
    }
    if (method === "POST" && path === "/git/commits") {
      const sha = this.sha("commit", { ...body, n: this.commits.size });
      this.commits.set(sha, { tree: body.tree, parents: body.parents, message: body.message });
      return json(201, { sha });
    }
    if (method === "GET" && (m = path.match(/^\/git\/ref\/heads\/(.+)$/))) {
      const sha = this.refs.get(`heads/${m[1]}`);
      return sha ? json(200, { object: { sha } }) : json(404, { message: "Not Found" });
    }
    if (method === "POST" && path === "/git/refs") {
      const name = body.ref.replace(/^refs\//, "");
      if (this.refs.has(name)) return json(422, { message: "Reference already exists" });
      this.refs.set(name, body.sha);
      return json(201, { ref: body.ref });
    }
    if (method === "GET" && path.startsWith("/pulls?")) {
      const head = decodeURIComponent(new URL(`https://x${path}`).searchParams.get("head")!).split(":")[1];
      return json(
        200,
        this.pulls.filter((p) => p.head === head).map((p) => ({ ...p, html_url: `https://github.com/acme/webapp/pull/${p.number}`, base: { ref: p.base } })),
      );
    }
    if (method === "POST" && path === "/pulls") {
      if (this.pulls.some((p) => p.head === body.head && p.state === "open")) {
        return json(422, { message: "A pull request already exists" });
      }
      const number = this.pulls.length + 1;
      this.pulls.push({ number, head: body.head, base: body.base, title: body.title, body: body.body, state: "open", merged_at: null });
      return json(201, { number, html_url: `https://github.com/acme/webapp/pull/${number}` });
    }
    return json(404, { message: `unhandled ${method} ${path}` });
  };
}

const REQS = "flask==2.0.0\nrequests==2.19.0\nnumpy==1.26.0\n";
const DIFF = "--- a/api/requirements.txt\n+++ b/api/requirements.txt\n@@ -2,1 +2,1 @@\n-requests==2.19.0\n+requests==2.31.0\n";

let gh: FakeGitHub;
let base: string;
const params = () => ({
  owner: "acme",
  repo: "webapp",
  commitSha: base,
  scanJobId: "job12345678abcdef",
  remediationId: "0f2b1c3d-aaaa-bbbb-cccc-000000000001",
  unifiedDiff: DIFF,
  title: "[VibeShield AI] Bump requests",
  body: "Fixes GHSA-x",
  token: "test-write-token",
  allowedRepositories: ["acme/webapp"],
  fetchImpl: gh.fetch,
});

beforeEach(() => {
  gh = new FakeGitHub();
  base = gh.seed({ "README.md": "# app\n", "api/requirements.txt": REQS, "api/app.py": "print('hi')\n" });
});

describe("strict diff application", () => {
  it("applies an exact hunk and refuses a mismatched removed line", () => {
    const out = applyDiffStrict(new Map([["api/requirements.txt", REQS]]), DIFF);
    expect(out.get("api/requirements.txt")).toBe(REQS.replace("2.19.0", "2.31.0"));
    expect(() => applyDiffStrict(new Map([["api/requirements.txt", REQS.replace("2.19.0", "2.20.0")]]), DIFF)).toThrow(DiffApplyError);
  });
  it("rejects renames, creations and truncated hunks", () => {
    expect(() => applyDiffStrict(new Map(), "--- a/x\n+++ b/y\n@@ -1,1 +1,1 @@\n-a\n+b\n")).toThrow(/in-place/);
    expect(() => applyDiffStrict(new Map(), "--- /dev/null\n+++ b/y\n@@ -0,0 +1,1 @@\n+b\n")).toThrow(DiffApplyError);
    expect(() => applyDiffStrict(new Map([["x", "a\nb\n"]]), "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-a\n+c\n")).toThrow(/length/);
  });
  it("treats header-looking content inside a hunk as content", () => {
    const diff = "--- a/notes.md\n+++ b/notes.md\n@@ -1,1 +1,1 @@\n--- old\n+++ new\n";
    expect(applyDiffStrict(new Map([["notes.md", "-- old\n"]]), diff).get("notes.md")).toBe("++ new\n");
  });
});

describe("createRemediationPullRequest against a modelled GitHub", () => {
  it("commits exactly the patched file on a new branch whose only parent is the scanned commit", async () => {
    const result = await createRemediationPullRequest(params());
    expect(result.status).toBe("created");
    expect(result.number).toBe(1);
    expect(result.url).toBe("https://github.com/acme/webapp/pull/1");
    expect(result.branch).toBe(remediationBranchName("job12345678abcdef", "0f2b1c3d-aaaa-bbbb-cccc-000000000001"));
    expect(result.baseBranch).toBe("main");

    const head = gh.refs.get(`heads/${result.branch}`)!;
    expect(head).toBe(result.headSha);
    expect(gh.commits.get(head)!.parents).toEqual([base]);
    const before = gh.filesAt(base);
    const after = gh.filesAt(head);
    expect(after["api/requirements.txt"]).toBe(REQS.replace("requests==2.19.0", "requests==2.31.0"));
    // Nothing else changed, and the default branch still points at the scanned commit.
    expect({ ...after, "api/requirements.txt": before["api/requirements.txt"] }).toEqual(before);
    expect(gh.refs.get("heads/main")).toBe(base);
    expect(gh.pulls[0]).toMatchObject({ head: result.branch, base: "main", state: "open" });
  });

  it("is idempotent: a retry and a concurrent double click converge on one branch, commit and PR", async () => {
    const [a, b] = await Promise.all([createRemediationPullRequest(params()), createRemediationPullRequest(params())]);
    const c = await createRemediationPullRequest(params());
    expect(gh.pulls).toHaveLength(1);
    expect([a.status, b.status].sort()).toEqual(["created", "exists"]);
    expect(new Set([a.number, b.number, c.number])).toEqual(new Set([1]));
    expect(c.status).toBe("exists");
    expect(c.state).toBe("open");
    expect(new Set([a.headSha, b.headSha, c.headSha]).size).toBe(1);
    expect([...gh.refs.keys()].filter((r) => r.startsWith("heads/vibeshield/"))).toHaveLength(1);
  });

  it("reports an existing closed PR instead of opening a duplicate", async () => {
    await createRemediationPullRequest(params());
    gh.pulls[0].state = "closed";
    const again = await createRemediationPullRequest(params());
    expect(again).toMatchObject({ status: "exists", state: "closed", number: 1 });
    expect(gh.pulls).toHaveLength(1);
  });

  it("never reuses a branch that holds different content", async () => {
    const branch = remediationBranchName("job12345678abcdef", "0f2b1c3d-aaaa-bbbb-cccc-000000000001");
    gh.refs.set(`heads/${branch}`, base); // someone else's content at our branch name
    const result = await createRemediationPullRequest(params());
    expect(result).toMatchObject({ status: "failed", code: "branch_conflict" });
    expect(gh.refs.get(`heads/${branch}`)).toBe(base);
    expect(gh.pulls).toHaveLength(0);
  });

  it("fails closed when the patch no longer matches the scanned files", async () => {
    base = gh.seed({ "api/requirements.txt": REQS.replace("2.19.0", "2.20.0") });
    const result = await createRemediationPullRequest(params());
    expect(result).toMatchObject({ status: "failed", code: "patch_conflict" });
    expect(gh.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("refuses to write through a symlink", async () => {
    base = gh.seed({ "api/requirements.txt": { content: "../../etc/passwd", mode: "120000" } });
    const result = await createRemediationPullRequest(params());
    expect(result).toMatchObject({ status: "failed", code: "unsafe_target" });
    expect(gh.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("refuses repositories outside the allowlist without calling GitHub", async () => {
    const result = await createRemediationPullRequest({ ...params(), allowedRepositories: ["acme/other"] });
    expect(result).toMatchObject({ status: "failed", code: "repository_not_allowed" });
    expect(gh.calls).toHaveLength(0);
  });

  it("refuses a repository that was renamed or transferred since the scan", async () => {
    gh.repo.full_name = "someone-else/webapp";
    expect(await createRemediationPullRequest(params())).toMatchObject({ status: "failed", code: "repository_mismatch" });
  });

  it.each([
    ["unauthorized", "credential_invalid"],
    ["deny_writes", "access_denied"],
    ["rate_limited", "rate_limited"],
    ["offline", "network_error"],
    ["missing_repo", "repository_not_found"],
  ] as const)("maps GitHub %s to %s and never reports success", async (mode, code) => {
    gh.mode = mode;
    const result = await createRemediationPullRequest(params());
    expect(result.status).toBe("failed");
    expect(result.code).toBe(code);
    expect(result.url).toBeUndefined();
    expect(result.message).not.toContain("test-write-token");
    expect(gh.pulls).toHaveLength(0);
  });

  it("reports an unknown scanned commit", async () => {
    expect(await createRemediationPullRequest({ ...params(), commitSha: "f".repeat(40) })).toMatchObject({
      status: "failed",
      code: "commit_not_found",
    });
  });
});

describe("PR endpoint gates", () => {
  const config = (over: Partial<ServerConfig> = {}) =>
    ({ githubWriteToken: "test-write-token", pullRequestRepositories: ["acme/webapp"], githubApiTimeoutMs: 5000, ...over }) as ServerConfig;

  async function setup(status: "verified" | "needs_review" | "approved" = "verified") {
    const COMMIT = base;
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "acme", repo: "webapp", repositoryUrl: "https://github.com/acme/webapp", expiresAt: new Date(Date.now() + 3_600_000) });
    await store.update(job.id, { status: "completed", commitSha: COMMIT, defaultBranch: "main" });
    const rem = await store.createRemediation({
      id: "0f2b1c3d-aaaa-bbbb-cccc-000000000002",
      scanJobId: job.id,
      findingFingerprints: ["fp"],
      affectedFiles: ["api/requirements.txt"],
      commitSha: COMMIT,
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
    const deps: RemediationDeps = { store, fetchImpl: gh.fetch, config: config() };
    await approveRemediation(job.id, rem.id, deps);
    if (status !== "approved") await store.updateRemediation(job.id, rem.id, { status, rescanStatus: status === "verified" ? "verified" : "needs_review" });
    return { store, job, rem, deps };
  }

  it("records the approved diff digest", async () => {
    const { store, job, rem } = await setup("approved");
    const r = await store.getRemediation(job.id, rem.id);
    expect((r!.approvedOperations as { diffSha256: string }).diffSha256).toBe(diffDigest(DIFF));
  });

  it("rejects unverified and needs-review fixes before touching GitHub", async () => {
    for (const status of ["approved", "needs_review"] as const) {
      const { job, rem, deps } = await setup(status);
      const res = await handleCreatePullRequest(job.id, rem.id, deps);
      expect(res.status).toBe(409);
      expect((await res.json()).error.code).toBe("not_verified");
    }
    expect(gh.calls).toHaveLength(0);
  });

  it("rejects a patch that differs from the approved one", async () => {
    const { store, job, rem, deps } = await setup();
    await store.updateRemediation(job.id, rem.id, { unifiedDiff: DIFF.replace("2.31.0", "9.9.9") });
    const res = await handleCreatePullRequest(job.id, rem.id, deps);
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe("patch_mismatch");
    expect(gh.calls).toHaveLength(0);
  });

  it("opens the PR through the endpoint, persists it, and reports the same PR on retry", async () => {
    const { job, rem, deps } = await setup();
    vi.useFakeTimers({ toFake: ["Date"] });
    const first = await handleCreatePullRequest(job.id, rem.id, deps);
    expect(first.status).toBe(201);
    const a = (await first.json()).data;
    expect(a.pullRequest).toMatchObject({ status: "created", number: 1 });
    expect(a.remediation.pullRequestUrl).toBe("https://github.com/acme/webapp/pull/1");
    expect(a.remediation.pullRequest).toMatchObject({ availability: "enabled", status: "created" });
    expect(gh.pulls[0].body).toContain("Patch applied to the scanned commit");
    expect(gh.pulls[0].body).toContain(base);

    // Inside the recheck window the stored outcome is returned without calling GitHub again.
    const callsBefore = gh.calls.length;
    const cachedRes = await handleCreatePullRequest(job.id, rem.id, deps);
    expect((await cachedRes.json()).data.pullRequest).toMatchObject({ status: "created", number: 1 });
    expect(gh.calls.length).toBe(callsBefore);

    vi.setSystemTime(Date.now() + 16_000);
    const second = await handleCreatePullRequest(job.id, rem.id, deps);
    vi.useRealTimers();
    expect(second.status).toBe(200);
    expect((await second.json()).data.pullRequest).toMatchObject({ status: "exists", number: 1 });
    expect(gh.pulls).toHaveLength(1);
  });

  it("returns 503 not_configured with the truthful state when no write credential exists", async () => {
    const { job, rem, deps } = await setup();
    const res = await handleCreatePullRequest(job.id, rem.id, { ...deps, config: config({ githubWriteToken: undefined }) });
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error.code).toBe("not_configured");
    expect(body.data.remediation.pullRequest).toMatchObject({ availability: "not_configured", status: "failed" });
    expect(body.data.remediation.pullRequestUrl).toBeNull();
    expect(JSON.stringify(body)).not.toContain("test-write-token");
  });
});
