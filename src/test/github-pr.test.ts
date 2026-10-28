import { beforeEach, describe, expect, it } from "vitest";
import { createRemediationPullRequest, remediationBranchName } from "@/server/remediation/github-pr";
import { applyDiffStrict, DiffApplyError } from "@/server/remediation/strict-apply";
import { FakeGitHub } from "@/test/fake-github";

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
  token: "test-user-token",
  expectedRepoId: 4242,
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
  it("sends only the user's own token and reports a base branch that moved since the scan", async () => {
    const result = await createRemediationPullRequest(params());
    expect(new Set(gh.calls.map((c) => c.auth))).toEqual(new Set(["Bearer test-user-token"]));
    expect(result.baseAdvanced).toBe(false);
    const again = await createRemediationPullRequest({ ...params(), remediationId: "0f2b1c3d-aaaa-bbbb-cccc-000000000009" });
    expect(again.status).toBe("created");
    gh.refs.set("heads/main", "f".repeat(40));
    const third = await createRemediationPullRequest({ ...params(), remediationId: "0f2b1c3d-aaaa-bbbb-cccc-000000000010" });
    expect(third.baseAdvanced).toBe(true);
    expect(gh.commits.get(third.headSha!)!.parents).toEqual([base]); // still based on the verified commit
  });

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

  it("refuses a repository recreated under the same name (different immutable ID)", async () => {
    const result = await createRemediationPullRequest({ ...params(), expectedRepoId: 9999 });
    expect(result).toMatchObject({ status: "failed", code: "repository_mismatch" });
    expect(gh.calls.some((c) => c.method === "POST")).toBe(false);
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
    expect(result.message).not.toContain("test-user-token");
    expect(gh.pulls).toHaveLength(0);
  });

  it("reports an unknown scanned commit", async () => {
    expect(await createRemediationPullRequest({ ...params(), commitSha: "f".repeat(40) })).toMatchObject({
      status: "failed",
      code: "commit_not_found",
    });
  });
});

