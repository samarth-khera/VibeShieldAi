/**
 * Auto-Fix through the production composition (getRemediationDeps) and the full-snapshot
 * verification path. Unlike the fixture tests in remediation.test.ts, nothing here injects
 * `sourceFiles`: source comes from GitHub (mocked at the HTTP boundary) at the scanned commit.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { create as createTar } from "tar";
import { InMemoryJobStore } from "./mock-store";
import { getConfig, type ServerConfig } from "@/server/config";
import { getRemediationDeps } from "@/server/deps";
import {
  applyAndVerify,
  approveRemediation,
  createPreview,
  RemediationError,
  type RemediationDeps,
} from "@/server/remediation/service";
import { handleListRemediations, handleVerificationResult, handleVerificationSpec } from "@/server/remediation/api";
import { applyAndRescanInSandbox } from "@/server/remediation/sandbox";
import { verifyRemediationOnSnapshot } from "@/server/remediation/verify";
import { clearSourceCache } from "@/server/remediation/source-cache";
import { signCallbackPayload, verificationSpecSigningPayload } from "@/server/callback-auth";
import type { NormalizedFinding, ScanEngineResult } from "@/server/scanners/types";

/** The job owner's session subject; in production it comes from the signed owner grant. */
const TEST_OWNER = { ownerSubject: "test-owner-subject" };

const SHA = "3f9c2b1a4d5e6f708192a3b4c5d6e7f8091a2b3c";
const SECRET = "test-callback-secret";
const REQUIREMENTS = ["flask==2.2.5", "pytest==7.1.0", "requests==2.31.0", ""].join("\n");

function pytestFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    scanner: "osv-scanner",
    ruleId: "GHSA-6w46-j5rx-g56g",
    category: "Dependencies",
    severity: "medium",
    originalSeverity: "MODERATE",
    title: "pytest has vulnerable tmpdir handling",
    description: "pytest tmpdir handling",
    filePath: "backend/requirements.txt",
    fingerprint: "fp-pytest-prod",
    startLine: null,
    endLine: null,
    redactedEvidence: null,
    vulnerabilityId: "GHSA-6w46-j5rx-g56g",
    remediation: "Upgrade pytest to version 9.0.3 or higher.",
    packageInfo: { name: "pytest", version: "7.1.0", ecosystem: "PyPI", fixedVersion: "9.0.3" },
    metadata: { fixedVersion: "9.0.3" },
    ...overrides,
  };
}

function engineResult(findings: NormalizedFinding[], status: "completed" | "failed" = "completed"): ScanEngineResult {
  return {
    status: status === "failed" ? "completed_with_warnings" : "completed",
    findings,
    counts: { critical: 0, high: 0, medium: findings.length, low: 0, info: 0, total: findings.length },
    gitleaksStatus: "completed",
    gitleaksDurationMs: 1,
    gitleaksError: null,
    semgrepStatus: status,
    semgrepDurationMs: 1,
    semgrepError: status === "failed" ? "semgrep crashed" : null,
    osvStatus: "completed",
    osvDurationMs: 1,
    osvError: null,
    scannerVersions: { gitleaks: "8.18.2", semgrep: "1.182.0", osvScanner: "2.7.0" },
    scanCoverage: { scannersRun: ["gitleaks", "semgrep", "osv-scanner"], lockfilesFound: [], limitations: [] },
  };
}

/** Engine double that reports the pytest finding only while the vulnerable pin is present. */
function manifestAwareEngine(seen?: { files: string[] }) {
  return vi.fn(async (dir: string) => {
    if (seen) seen.files = await listFiles(dir);
    const manifest = await readFile(path.join(dir, "backend/requirements.txt"), "utf8");
    return engineResult(manifest.includes("pytest==7.1.0") ? [pytestFinding()] : []);
  });
}

async function listFiles(dir: string, prefix = ""): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...(await listFiles(path.join(dir, e.name), rel)));
    else out.push(rel);
  }
  return out.sort();
}

/** Builds a GitHub-style tarball (single `<owner>-<repo>-<sha>/` root) for the fixture repository. */
async function buildTarball(files: Record<string, string>): Promise<Buffer> {
  const root = await mkdtemp(path.join(tmpdir(), "vs-tarball-"));
  const top = `octocat-demo-${SHA.slice(0, 7)}`;
  for (const [rel, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, top, rel)), { recursive: true });
    await writeFile(path.join(root, top, rel), content);
  }
  const out = path.join(root, "archive.tgz");
  await createTar({ gzip: true, cwd: root, file: out, portable: true }, [top]);
  const bytes = await readFile(out);
  await rm(root, { recursive: true, force: true });
  return bytes;
}

const REPO_FILES = {
  "backend/requirements.txt": REQUIREMENTS,
  "backend/app.py": "print('hello')\n",
  "README.md": "# demo\n",
};

async function seedScan(store: InMemoryJobStore) {
  const job = await store.create({
    owner: "octocat",
    repo: "demo",
    repositoryUrl: "https://github.com/octocat/demo",
    expiresAt: new Date(Date.now() + 86400_000),
  });
  await store.update(job.id, { status: "completed", commitSha: SHA, defaultBranch: "main" });
  await store.saveFindings(job.id, [
    pytestFinding(),
    pytestFinding({ fingerprint: "fp-unrelated", ruleId: "PYSEC-OTHER", packageInfo: null, metadata: null }),
  ]);
  const finding = (await store.getFindings(job.id)).findings.find((f) => f.fingerprint === "fp-pytest-prod")!;
  return { job, finding };
}

function productionConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    ...getConfig(),
    scanDispatchBackend: "github-actions",
    githubDispatchToken: "test-dispatch-token",
    githubRepository: "owner/VibeShieldAi",
    githubWorkflowRef: "main",
    appUrl: "https://app.example",
    githubToken: undefined,
    scanCallbackSecret: SECRET,
    maxConcurrentHeavyScans: 2,
    ...overrides,
  };
}

type Call = { url: string; init?: RequestInit };

/** Fake GitHub at the HTTP boundary. Any unexpected request fails the test. */
function fakeGithub(opts: { tarball?: Buffer; dispatchStatus?: number } = {}) {
  const calls: Call[] = [];
  const impl = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    if (url.startsWith(`https://api.github.com/repos/octocat/demo/contents/backend/requirements.txt?ref=${SHA}`)) {
      return new Response(REQUIREMENTS, { status: 200 });
    }
    if (url === `https://api.github.com/repos/octocat/demo/tarball/${SHA}` && opts.tarball) {
      return new Response(new Uint8Array(opts.tarball), { status: 200 });
    }
    if (url.endsWith("/actions/workflows/scanner-worker.yml/dispatches")) {
      return new Response(null, { status: opts.dispatchStatus ?? 204 });
    }
    throw new Error(`Unexpected request in test: ${url}`);
  });
  return { calls, impl };
}

beforeEach(() => clearSourceCache());
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("Production Auto-Fix composition (getRemediationDeps)", () => {
  it("with the GitHub Actions backend, verification is dispatched to the worker, never run on injected files", async () => {
    const config = productionConfig();
    const github = fakeGithub();
    vi.stubGlobal("fetch", github.impl);
    const prod = getRemediationDeps(config);

    expect(prod.sourceFiles).toBeUndefined();
    expect(prod.scanEngine).toBeUndefined();
    expect(typeof prod.dispatchVerification).toBe("function");

    // Only the persistence adapter is swapped; dispatch, fetch, and config are the production ones.
    const store = new InMemoryJobStore();
    const deps: RemediationDeps = { ...prod, store, fetchImpl: github.impl };
    const { job, finding } = await seedScan(store);

    const preview = await createPreview(job.id, finding.id, deps);
    expect(preview.commitSha).toBe(SHA);
    expect(preview.unifiedDiff).toContain("+pytest==9.0.3");
    // Source was fetched at the immutable scan commit, never at a branch name.
    expect(github.calls.map((c) => c.url)).toEqual([
      `https://api.github.com/repos/octocat/demo/contents/backend/requirements.txt?ref=${SHA}`,
    ]);

    await expect(applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(/Explicit user approval is required/);
    await approveRemediation(job.id, preview.id, deps, TEST_OWNER);

    const applied = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);
    expect(applied.status).toBe("applied");
    expect(applied.rescanStatus).toBeNull();

    const dispatch = github.calls.find((c) => c.url.endsWith("/dispatches"))!;
    const body = JSON.parse(String(dispatch.init?.body));
    expect(body.inputs).toEqual({
      mode: "verify",
      job_id: job.id,
      remediation_id: preview.id,
      repository_url: "https://github.com/octocat/demo",
      callback_url: `https://app.example/api/scans/${job.id}/remediation/${preview.id}/verification`,
    });
    // Only identifiers travel through the workflow form; the diff stays in server storage.
    expect(JSON.stringify(body)).not.toContain("pytest");

    // A repeated click while the worker runs does not dispatch a second verification.
    expect((await applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).status).toBe("applied");
    expect(github.calls.filter((c) => c.url.endsWith("/dispatches"))).toHaveLength(1);
  });

  it("releases the slot and reports an explicit error when the worker cannot be dispatched", async () => {
    const github = fakeGithub({ dispatchStatus: 500 });
    vi.stubGlobal("fetch", github.impl);
    const store = new InMemoryJobStore();
    const deps: RemediationDeps = { ...getRemediationDeps(productionConfig()), store, fetchImpl: github.impl };
    const { job, finding } = await seedScan(store);
    const preview = await createPreview(job.id, finding.id, deps);
    await approveRemediation(job.id, preview.id, deps, TEST_OWNER);

    await expect(applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).rejects.toMatchObject({ code: "verification_unavailable", status: 503 });
    const after = await store.getRemediation(job.id, preview.id);
    expect(after?.status).toBe("approved");
    expect(after?.rescanStatus).toBeNull();
  });

  it("without the Actions backend, rebuilds the scanned commit from its archive and rescans the full tree", async () => {
    const tarball = await buildTarball(REPO_FILES);
    const github = fakeGithub({ tarball });
    const store = new InMemoryJobStore();
    const seen = { files: [] as string[] };
    const engine = manifestAwareEngine(seen);
    const local = getRemediationDeps(productionConfig({ scanDispatchBackend: "bullmq" }));
    expect(local.dispatchVerification).toBeUndefined();
    const deps: RemediationDeps = { ...local, store, fetchImpl: github.impl, scanEngine: engine };

    const { job, finding } = await seedScan(store);
    const preview = await createPreview(job.id, finding.id, deps);
    await approveRemediation(job.id, preview.id, deps, TEST_OWNER);
    const result = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);

    expect(result.status).toBe("verified");
    expect(result.rescanSummary?.snapshot).toEqual({ commitSha: SHA, fileCount: 3 });
    expect(result.rescanSummary?.runtime).toBe("local");
    expect(result.rescanSummary?.resolvedFingerprints).toEqual(["fp-pytest-prod"]);
    expect(seen.files).toEqual(["README.md", "backend/app.py", "backend/requirements.txt"]);
    expect(github.calls.some((c) => c.url.endsWith(`/tarball/${SHA}`))).toBe(true);
  });
});

describe("Sandbox never treats missing or mismatched source as verified", () => {
  const base = {
    originalFindings: [{ fingerprint: "fp-pytest-prod" }],
    targetedFingerprints: ["fp-pytest-prod"],
    unifiedDiff: "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -2,1 +2,1 @@\n-pytest==7.1.0\n+pytest==9.0.3\n",
  };

  it("fails without scanning when no repository snapshot is available (no placeholder files)", async () => {
    const engine = vi.fn();
    const result = await applyAndRescanInSandbox({ ...base, scanEngine: engine });
    expect(engine).not.toHaveBeenCalled();
    expect(result.rescanStatus).toBe("failed");
    expect(result.summary.reason).toBe("source_snapshot_unavailable");
    expect(result.summary.targetResolved).toBe(false);
    expect(result.summary.resolvedFingerprints).toEqual([]);
  });

  it("fails when the patch was generated for a different revision", async () => {
    const engine = vi.fn();
    const result = await applyAndRescanInSandbox({
      ...base,
      sourceFiles: { "backend/requirements.txt": "flask==2.2.5\npytest==8.0.0\n" },
      scanEngine: engine,
    });
    expect(engine).not.toHaveBeenCalled();
    expect(result.summary.reason).toBe("patch_does_not_apply");
    expect(result.rescanStatus).toBe("failed");
  });

  it("fails when a patched file is absent from the snapshot", async () => {
    const result = await applyAndRescanInSandbox({ ...base, sourceFiles: { "README.md": "x\n" }, scanEngine: vi.fn() });
    expect(result.summary.reason).toBe("patch_target_missing");
  });

  it("fails when any required scanner does not complete, even if the target looks resolved", async () => {
    const result = await applyAndRescanInSandbox({
      ...base,
      sourceFiles: { "backend/requirements.txt": REQUIREMENTS },
      scanEngine: async () => engineResult([], "failed"),
    });
    expect(result.rescanStatus).toBe("failed");
    expect(result.summary.reason).toBe("scanner_failed");
    expect(result.summary.targetResolved).toBe(false);
  });

  it("refuses a branch name in place of the scanned commit without downloading anything", async () => {
    const fetchImpl = vi.fn();
    const result = await verifyRemediationOnSnapshot({
      owner: "octocat",
      repo: "demo",
      commitSha: "main",
      unifiedDiff: base.unifiedDiff,
      targetedFingerprints: base.targetedFingerprints,
      baselineFindings: [{ fingerprint: "fp-pytest-prod" }],
      config: getConfig(),
      fetchImpl,
      scanEngine: vi.fn(),
    });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.summary.reason).toBe("commit_unknown");
    expect(result.rescanStatus).toBe("failed");
  });
});

describe("Signed verification worker protocol", () => {
  async function pendingVerification() {
    const store = new InMemoryJobStore();
    const github = fakeGithub();
    const deps: RemediationDeps = {
      store,
      fetchImpl: github.impl,
      config: productionConfig(),
      dispatchVerification: async () => undefined,
    };
    const { job, finding } = await seedScan(store);
    const preview = await createPreview(job.id, finding.id, deps);
    await approveRemediation(job.id, preview.id, deps, TEST_OWNER);
    await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);
    return { store, deps, jobId: job.id, rid: preview.id, diff: preview.unifiedDiff };
  }

  const specRequest = (jobId: string, rid: string, signature?: string) =>
    new Request(`https://app.example/api/scans/${jobId}/remediation/${rid}/verification`, {
      headers: signature ? { "X-VibeShield-Signature": signature } : {},
    });

  const resultRequest = (jobId: string, rid: string, body: unknown, secret = SECRET) => {
    const json = JSON.stringify(body);
    return new Request(`https://app.example/api/scans/${jobId}/remediation/${rid}/verification`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-VibeShield-Signature": signCallbackPayload(json, secret) },
      body: json,
    });
  };

  const goodSummary = {
    targetResolved: true,
    originalFindingsCount: 2,
    postRescanFindingsCount: 1,
    newFindingsCount: 0,
    resolvedFingerprints: ["fp-pytest-prod"],
    remainingFingerprints: [],
    regressions: [],
    scannerStatuses: { gitleaks: "completed", semgrep: "completed", osvScanner: "completed" },
    snapshot: { commitSha: SHA, fileCount: 3 },
    timings: { downloadMs: 120, extractionMs: 30, applyMs: 10, scanMs: 4000, totalMs: 4300 },
  };

  it("serves the approved diff and immutable commit only to a correctly signed worker", async () => {
    const { deps, jobId, rid, diff } = await pendingVerification();

    expect((await handleVerificationSpec(specRequest(jobId, rid), jobId, rid, deps)).status).toBe(401);
    const forged = signCallbackPayload(verificationSpecSigningPayload(jobId, rid), "wrong-secret");
    expect((await handleVerificationSpec(specRequest(jobId, rid, forged), jobId, rid, deps)).status).toBe(401);
    // A signature for another remediation cannot be replayed against this one.
    const other = signCallbackPayload(verificationSpecSigningPayload(jobId, "00000000-0000-0000-0000-000000000000"), SECRET);
    expect((await handleVerificationSpec(specRequest(jobId, rid, other), jobId, rid, deps)).status).toBe(401);

    const signed = signCallbackPayload(verificationSpecSigningPayload(jobId, rid), SECRET);
    const res = await handleVerificationSpec(specRequest(jobId, rid, signed), jobId, rid, deps);
    expect(res.status).toBe(200);
    const spec = (await res.json()).data;
    expect(spec).toMatchObject({ owner: "octocat", repo: "demo", commitSha: SHA, unifiedDiff: diff, targetedFingerprints: ["fp-pytest-prod"] });
    expect(spec.baselineFindings.map((f: { fingerprint: string }) => f.fingerprint).sort()).toEqual(["fp-pytest-prod", "fp-unrelated"]);
    expect(spec.baselineFindings.find((f: { fingerprint: string }) => f.fingerprint === "fp-pytest-prod")).toMatchObject({ scanner: "osv-scanner", packageName: "pytest" });
  });

  it("records a signed verified result once and ignores replays", async () => {
    const { store, deps, jobId, rid } = await pendingVerification();
    const body = { scanJobId: jobId, remediationId: rid, rescanStatus: "verified", summary: goodSummary };

    expect((await handleVerificationResult(resultRequest(jobId, rid, body, "wrong"), jobId, rid, deps)).status).toBe(401);
    const res = await handleVerificationResult(resultRequest(jobId, rid, body), jobId, rid, deps);
    expect((await res.json()).data).toEqual({ accepted: true, status: "verified" });
    const stored = await store.getRemediation(jobId, rid);
    expect(stored?.status).toBe("verified");
    expect(stored?.rescanSummary?.runtime).toBe("github-actions");

    const replay = await handleVerificationResult(
      resultRequest(jobId, rid, { ...body, rescanStatus: "failed" }),
      jobId,
      rid,
      deps,
    );
    expect((await replay.json()).data.accepted).toBe(false);
    expect((await store.getRemediation(jobId, rid))?.status).toBe("verified");
  });

  it.each([
    ["a scanner did not complete", { scannerStatuses: { gitleaks: "completed", semgrep: "failed", osvScanner: "completed" } }],
    ["the snapshot was a different commit", { snapshot: { commitSha: "f".repeat(40), fileCount: 3 } }],
    ["a regression was reported", { regressions: ["fp-new"], newFindingsCount: 1 }],
  ])("downgrades a 'verified' label to needs_review when %s", async (_label, override) => {
    const { store, deps, jobId, rid } = await pendingVerification();
    const body = { scanJobId: jobId, remediationId: rid, rescanStatus: "verified", summary: { ...goodSummary, ...override } };
    await handleVerificationResult(resultRequest(jobId, rid, body), jobId, rid, deps);
    expect((await store.getRemediation(jobId, rid))?.status).toBe("needs_review");
  });

  it("fails a verification whose worker never reported back once the job timeout passes", async () => {
    const { store, deps, jobId, rid } = await pendingVerification();
    store.backdate(rid, new Date(Date.now() - 16 * 60_000));
    const list = await (await handleListRemediations(jobId, deps)).json();
    const r = list.data.find((x: { id: string }) => x.id === rid);
    expect(r.status).toBe("failed");
    expect(r.rescanSummary.reason).toBe("verification_timeout");
  });

  it("counts an in-flight verification against the worker cap", async () => {
    const store = new InMemoryJobStore();
    const deps: RemediationDeps = {
      store,
      fetchImpl: fakeGithub().impl,
      config: productionConfig({ maxConcurrentHeavyScans: 1 }),
      dispatchVerification: async () => undefined,
    };
    const { job, finding } = await seedScan(store);
    const preview = await createPreview(job.id, finding.id, deps);
    await approveRemediation(job.id, preview.id, deps, TEST_OWNER);
    // Another user's scan is claimed by an executor and occupies the only slot (waiting scans do not).
    await store.create({ owner: "a", repo: "b", repositoryUrl: "https://github.com/a/b", expiresAt: new Date(Date.now() + 1e6) });
    expect(await store.claimNextScan({ kind: "github-actions" }, deps.config!)).not.toBeNull();

    const err = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER).catch((e) => e);
    expect(err).toBeInstanceOf(RemediationError);
    expect(err.status).toBe(429);
    expect((await store.getRemediation(job.id, preview.id))?.status).toBe("approved");
  });
});

describe("Immutable source cache for previews", () => {
  it("fetches a file once per commit across repeated previews", async () => {
    const store = new InMemoryJobStore();
    const github = fakeGithub();
    const deps: RemediationDeps = { store, fetchImpl: github.impl, config: productionConfig() };
    const { job, finding } = await seedScan(store);

    await createPreview(job.id, finding.id, deps);
    await createPreview(job.id, finding.id, deps);
    await Promise.all([createPreview(job.id, finding.id, deps), createPreview(job.id, finding.id, deps)]);
    expect(github.calls.filter((c) => c.url.includes("/contents/"))).toHaveLength(1);
  });

  it("never generates a patch when the scanned commit is unknown", async () => {
    const store = new InMemoryJobStore();
    const github = fakeGithub();
    const deps: RemediationDeps = { store, fetchImpl: github.impl, config: productionConfig() };
    const { job, finding } = await seedScan(store);
    await store.update(job.id, { commitSha: null });

    const preview = await createPreview(job.id, finding.id, deps);
    expect(preview.unifiedDiff).toBe("");
    expect(preview.eligibility).toBe("unsuitable");
    expect(preview.eligibilityReason).toMatch(/scanned commit is unknown/);
    expect(github.calls).toHaveLength(0);
  });
});
