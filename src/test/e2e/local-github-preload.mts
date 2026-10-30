/**
 * LOCAL UI END-TO-END ONLY. Never imported by application code, so it cannot reach a production build.
 *
 * Loaded into a local `next start` with
 *   NODE_OPTIONS="--import tsx --import ./src/test/e2e/local-github-preload.mts"
 * it serves GitHub's API (user, installations, repository, contents, archive, Git Data, pulls)
 * from the in-memory FakeGitHubApp, seeded with a real repository snapshot at its real commit.
 * The npm registry and OSV are reached for real (public, read-only); every other outbound host,
 * including any AI provider, is refused. Pull requests it "creates" are simulated: their links use
 * the host simulated-github.local.
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { create as createTar } from "tar";
import { FakeGitHubApp } from "../fake-github";

const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`local-github-preload: ${k} is required`);
  return v;
};
if (process.env.E2E_SIMULATED_GITHUB !== "1") throw new Error("local-github-preload: set E2E_SIMULATED_GITHUB=1 (local UI tests only)");

const snapshotDir = env("E2E_SNAPSHOT_DIR");
const commitSha = env("E2E_COMMIT_SHA");
const [owner, repo] = env("E2E_REPOSITORY").split("/");
const stateFile = env("E2E_STATE_FILE");

const gh = new FakeGitHubApp();
const userId = Number(env("E2E_GITHUB_USER_ID"));
gh.users.set(userId, { id: userId, login: env("E2E_GITHUB_LOGIN") });
gh.tokens.set(env("E2E_GITHUB_TOKEN"), userId);
for (const set of [gh.read, gh.push, gh.admin, gh.installationUsers]) set.add(userId);
gh.owner = { id: Number(env("E2E_OWNER_ID")), login: owner, type: "User" };
gh.installation = {
  id: Number(env("E2E_INSTALLATION_ID")),
  account: owner,
  accountId: Number(env("E2E_OWNER_ID")),
  repositorySelection: "selected",
  repos: new Set([Number(env("E2E_REPOSITORY_ID"))]),
  permissions: { contents: "write", pull_requests: "write", metadata: "read" },
};
gh.git.repo.full_name = `${owner}/${repo}`;
gh.git.apiRepo = `${owner}/${repo}`;
gh.git.repoId = Number(env("E2E_REPOSITORY_ID"));
gh.git.webHost = "simulated-github.local";

// The repository at the scanned commit (text content; the archive below serves the exact bytes).
const files: Record<string, string> = {};
const walk = (dir: string) => {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full);
    else files[path.relative(snapshotDir, full).split(path.sep).join("/")] = readFileSync(full, "utf8");
  }
};
walk(snapshotDir);
gh.git.seed(files, commitSha);

let archive: Buffer | null = null;
async function archiveBytes(): Promise<Buffer> {
  if (archive) return archive;
  const out = path.join(tmpdir(), `e2e-archive-${process.pid}.tgz`);
  const top = `${owner}-${repo}-${commitSha.slice(0, 7)}`;
  // tar with a prefix directory, like GitHub's archive.
  await createTar({ gzip: true, file: out, cwd: snapshotDir, portable: true, prefix: top }, readdirSync(snapshotDir));
  archive = readFileSync(out);
  return archive;
}

const dumpState = () =>
  writeFileSync(
    stateFile,
    JSON.stringify(
      {
        simulated: true,
        pulls: gh.git.pulls.map((p) => ({ number: p.number, head: p.head, base: p.base, state: p.state, user: p.user, title: p.title })),
        branches: [...gh.git.refs.keys()],
        commitsCreated: gh.git.commitBodies.length,
        commitBodies: gh.git.commitBodies.map((b) => Object.keys(b).sort()),
        writes: gh.git.calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.path}`),
      },
      null,
      1,
    ),
  );
dumpState();

const realFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const req = input instanceof Request ? input : null;
  const url = req ? req.url : input instanceof URL ? input.href : String(input);
  if (url.startsWith("https://codeload.github.com/")) return new Response(new Uint8Array(await archiveBytes()), { status: 200 });
  if (url.startsWith("https://api.github.com/") || url.startsWith("https://github.com/login/oauth/")) {
    const opts: RequestInit = req ? { method: req.method, headers: req.headers, body: req.method === "GET" ? undefined : await req.text() } : (init ?? {});
    const res = await gh.fetch(url, opts);
    if ((opts.method ?? "GET") !== "GET") dumpState();
    if (process.env.E2E_TRACE === "1") console.log(`[simulated-github] ${opts.method ?? "GET"} ${url.split("?")[0]} -> ${res.status} (authorization header: ${new Headers(opts.headers).has("authorization") ? "present" : "absent"}; request object: ${Boolean(req)})`);
    return res;
  }
  if (/^https:\/\/(registry\.npmjs\.org|api\.osv\.dev)\//.test(url) || /^http:\/\/(localhost|127\.0\.0\.1)[:/]/.test(url)) return realFetch(input, init);
  throw new TypeError(`local E2E: outbound request to ${new URL(url).host} is blocked`);
}) as typeof fetch;
console.log(`[local-github-preload] simulating GitHub for ${owner}/${repo}@${commitSha.slice(0, 7)} (${Object.keys(files).length} files)`);
