import { createHash } from "node:crypto";

/**
 * A small content-addressed model of GitHub's Git Data + Pulls API: enough to prove that the PR
 * branch holds exactly the patched files on top of the scanned commit, and that retries converge.
 */
type Entry = { path: string; mode: string; type: "blob" | "tree"; sha: string };
export class FakeGitHub {
  blobs = new Map<string, string>();
  trees = new Map<string, Entry[]>();
  commits = new Map<string, { tree: string; parents: string[]; message: string }>();
  refs = new Map<string, string>();
  pulls: { number: number; head: string; base: string; title: string; body: string; state: string; merged_at: null }[] = [];
  calls: { method: string; path: string; auth: string | null }[] = [];
  repo = { full_name: "acme/webapp", default_branch: "main", archived: false, permissions: { push: true } };
  repoId = 4242;
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
    this.calls.push({ method, path, auth: new Headers(init?.headers).get("authorization") });
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    if (this.mode === "offline") throw new TypeError("fetch failed");
    if (this.mode === "unauthorized") return json(401, { message: "Bad credentials" });
    if (this.mode === "rate_limited") return json(403, { message: "API rate limit exceeded" }, { "x-ratelimit-remaining": "0" });
    if (this.mode === "missing_repo") return json(404, { message: "Not Found" });
    if (this.mode === "deny_writes" && method !== "GET") return json(403, { message: "Resource not accessible by personal access token" });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;

    if (method === "GET" && path === "") return json(200, { id: this.repoId, ...this.repo });
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


type FakeUser = { id: number; login: string };

/**
 * GitHub App user-to-server model on top of FakeGitHub: OAuth code exchange with PKCE, rotating
 * single-use refresh tokens, grant revocation, per-user installations and repository permissions.
 * Writes through the Git Data/Pulls API are refused unless the token's user has push access and
 * the repository is in that user's installation, as on GitHub.
 */
export class FakeGitHubApp {
  git = new FakeGitHub();
  clientId = "Iv1.testclient";
  clientSecret = "test-client-secret";
  users = new Map<number, FakeUser>([
    [1001, { id: 1001, login: "alice" }],
    [1002, { id: 1002, login: "bob" }],
    [1003, { id: 1003, login: "mallory" }],
  ]);
  /** Repository role per user. */
  push = new Set<number>([1001]);
  read = new Set<number>([1001, 1002]);
  isPrivate = false;
  installation = { id: 77, account: "acme", repos: new Set<number>([4242]), permissions: { contents: "write", pull_requests: "write", metadata: "read" } };
  /** Users who can see the installation (members of the account). */
  installationUsers = new Set<number>([1001, 1002]);
  codes = new Map<string, { userId: number; challenge: string }>();
  tokens = new Map<string, number>();
  refreshTokens = new Map<string, number>();
  expiresIn = 28_800;
  oauthCalls: Record<string, string>[] = [];
  revoked: string[] = [];
  private n = 0;

  issueCode(userId: number, challenge: string): string {
    const code = `code-${++this.n}`;
    this.codes.set(code, { userId, challenge });
    return code;
  }
  tokenFor(userId: number): string {
    const t = `ghu_test_${userId}_${++this.n}`;
    this.tokens.set(t, userId);
    return t;
  }
  private pair(userId: number) {
    const refresh = `ghr_test_${userId}_${++this.n}`;
    this.refreshTokens.set(refresh, userId);
    return {
      access_token: this.tokenFor(userId),
      expires_in: this.expiresIn,
      refresh_token: refresh,
      refresh_token_expires_in: 15_811_200,
      token_type: "bearer",
    };
  }

  fetch = async (url: string, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;

    if (url === "https://github.com/login/oauth/access_token") {
      this.oauthCalls.push(body);
      if (body.client_id !== this.clientId || body.client_secret !== this.clientSecret) return json(200, { error: "incorrect_client_credentials" });
      if (body.grant_type === "refresh_token") {
        const userId = this.refreshTokens.get(body.refresh_token);
        if (!userId) return json(200, { error: "bad_refresh_token" });
        this.refreshTokens.delete(body.refresh_token); // single use
        return json(200, this.pair(userId));
      }
      const c = this.codes.get(body.code);
      this.codes.delete(body.code);
      const challenge = createHash("sha256").update(body.code_verifier ?? "").digest("base64url");
      if (!c || c.challenge !== challenge) return json(200, { error: "bad_verification_code" });
      return json(200, this.pair(c.userId));
    }

    const auth = new Headers(init?.headers).get("authorization") ?? "";
    if (url === `https://api.github.com/applications/${this.clientId}/grant` && method === "DELETE") {
      if (auth !== `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64")}`) return json(401, {});
      const userId = this.tokens.get(body.access_token);
      if (!userId) return json(404, {});
      for (const [t, u] of this.tokens) if (u === userId) this.tokens.delete(t);
      for (const [t, u] of this.refreshTokens) if (u === userId) this.refreshTokens.delete(t);
      this.revoked.push(body.access_token);
      return new Response(null, { status: 204 });
    }

    const userId = this.tokens.get(auth.replace(/^Bearer /, ""));
    if (!userId) return json(401, { message: "Bad credentials" });
    const path = url.replace("https://api.github.com", "");
    const installed = this.installation.repos.has(this.git.repoId);
    const visible = this.read.has(userId) && (!this.isPrivate || (installed && this.installationUsers.has(userId)));

    if (path === "/user") return json(200, { id: userId, login: this.users.get(userId)!.login, avatar_url: "https://avatars.example/x" });
    if (path.startsWith("/user/installations?")) {
      const list = this.installationUsers.has(userId)
        ? [{ id: this.installation.id, account: { login: this.installation.account }, permissions: this.installation.permissions }]
        : [];
      return json(200, { total_count: list.length, installations: list });
    }
    const m = path.match(/^\/user\/installations\/(\d+)\/repositories/);
    if (m) {
      if (Number(m[1]) !== this.installation.id || !this.installationUsers.has(userId)) return json(404, {});
      return json(200, { repositories: installed && this.read.has(userId) ? [{ id: this.git.repoId }] : [] });
    }
    if (path === "/repos/acme/webapp" && method === "GET") {
      if (!visible) return json(404, { message: "Not Found" });
      return json(200, {
        id: this.git.repoId,
        full_name: this.git.repo.full_name,
        private: this.isPrivate,
        default_branch: "main",
        archived: false,
        permissions: { pull: true, push: this.push.has(userId) },
      });
    }
    if (path === "/repos/acme/webapp/commits/main") {
      return visible ? new Response(this.git.refs.get("heads/main")!, { status: 200 }) : json(404, {});
    }
    const tb = path.match(/^\/repos\/acme\/webapp\/tarball\/([0-9a-f]{40})$/);
    if (tb) {
      if (!visible) return json(404, {});
      return new Response(null, { status: 302, headers: { location: `https://codeload.github.com/acme/webapp/legacy.tar.gz/${tb[1]}?token=TMPARCHIVE` } });
    }
    if (path.startsWith("/repos/acme/webapp")) {
      if (!visible) return json(404, { message: "Not Found" });
      // A user-to-server token can write only where the user can push and the app is installed.
      if (method !== "GET" && (!this.push.has(userId) || !installed)) return json(403, { message: "Resource not accessible by integration" });
      return this.git.fetch(url, init);
    }
    return json(404, { message: `unhandled ${method} ${path}` });
  };
}
