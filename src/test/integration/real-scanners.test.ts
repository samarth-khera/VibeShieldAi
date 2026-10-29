/**
 * Real-scanner proof: runs the actual Gitleaks, Semgrep and OSV-Scanner binaries (OSV queries the
 * live OSV API) against a full repository snapshot, through the same verification path the worker
 * uses. Locally the suite is skipped (reported as skipped, never as passed) when a binary is missing;
 * `npm run test:scanners` sets REQUIRE_REAL_SCANNERS=1 so a missing binary fails instead.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { create as createTar } from "tar";
import { runSubprocess } from "@/server/scanners/runner";
import { runSecurityScanEngine } from "@/server/scanners/engine";
import { extractArchiveSafely } from "@/server/archive";
import { verifyRemediationOnSnapshot } from "@/server/remediation/verify";
import { toBaselineFinding } from "@/server/remediation/sandbox";
import { generateNpmLockfilePatch } from "@/server/remediation/npm-lockfile";
import { renderFileDiff } from "@/server/remediation/canonical-diff";
import { getConfig } from "@/server/config";
import type { NormalizedFinding } from "@/server/scanners/types";

const REQUIRED = process.env.REQUIRE_REAL_SCANNERS === "1";
const BINARIES = [
  ["gitleaks", ["version"]],
  ["semgrep", ["--version"]],
  ["osv-scanner", ["--version"]],
] as const;

async function missingBinaries(): Promise<string[]> {
  const missing: string[] = [];
  for (const [bin, args] of BINARIES) {
    const ok = await runSubprocess(bin, [...args], { cwd: tmpdir(), timeoutMs: 15_000 })
      .then((r) => r.exitCode === 0)
      .catch(() => false);
    if (!ok) missing.push(bin);
  }
  return missing;
}

const missing = await missingBinaries();
if (REQUIRED && missing.length > 0) {
  throw new Error(`REQUIRE_REAL_SCANNERS=1 but these scanners are not installed: ${missing.join(", ")}`);
}

const SHA = "9b1d3c5e7f90a2b4c6d8e0f1a3b5c7d9e1f3a5b7";
// Built at runtime so this repository never contains a credential-shaped literal.
const PLANTED_TOKEN = `ghp_${randomBytes(18).toString("hex")}`;
const FILES: Record<string, string> = {
  "backend/requirements.txt": "flask==3.1.1\npytest==7.1.0\n",
  "backend/app.py": "def handler(event):\n    return {'ok': True}\n",
  "config/settings.txt": `github_token = "${PLANTED_TOKEN}"\n`,
  "README.md": "# fixture\n",
};

async function tarballOf(files: Record<string, string>): Promise<Buffer> {
  const root = await mkdtemp(path.join(tmpdir(), "vs-real-"));
  const top = `octocat-fixture-${SHA.slice(0, 7)}`;
  for (const [rel, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, top, rel)), { recursive: true });
    await writeFile(path.join(root, top, rel), content);
  }
  await createTar({ gzip: true, cwd: root, file: path.join(root, "a.tgz"), portable: true }, [top]);
  const bytes = await readFile(path.join(root, "a.tgz"));
  await rm(root, { recursive: true, force: true });
  return bytes;
}

describe.skipIf(missing.length > 0)("Real scanners on a full repository snapshot", () => {
  let tarball: Buffer;
  let baseline: NormalizedFinding[];
  let pytestFinding: NormalizedFinding;

  const fetchImpl = async (url: string) => {
    if (url === `https://api.github.com/repos/octocat/fixture/tarball/${SHA}`) {
      return new Response(new Uint8Array(tarball), { status: 200 });
    }
    throw new Error(`Unexpected request: ${url}`);
  };

  beforeAll(async () => {
    tarball = await tarballOf(FILES);
    // Baseline: the original scan of the unpatched snapshot, exactly as the scan worker runs it.
    const dir = await mkdtemp(path.join(tmpdir(), "vs-real-base-"));
    try {
      await extractArchiveSafely(Readable.from(tarball), dir, getConfig());
      const result = await runSecurityScanEngine(dir);
      expect([result.gitleaksStatus, result.semgrepStatus, result.osvStatus]).toEqual(["completed", "completed", "completed"]);
      baseline = result.findings;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
    pytestFinding = baseline.find((f) => f.scanner === "osv-scanner" && f.packageInfo?.name === "pytest" && f.packageInfo.fixedVersion)!;
  }, 120_000);

  it("publishes each real scanner's result as it finishes, before the aggregate resolves", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vs-real-progressive-"));
    try {
      await extractArchiveSafely(Readable.from(tarball), dir, getConfig());
      const events: { scanner: string; status: string; at: number; findings: number }[] = [];
      const t0 = Date.now();
      const result = await runSecurityScanEngine(dir, {
        onScannerComplete: (r) => {
          events.push({ scanner: r.scanner, status: r.status, at: Date.now() - t0, findings: r.findings.length });
        },
      });
      const resolvedAt = Date.now() - t0;
      expect(events.map((e) => e.scanner).sort()).toEqual(["gitleaks", "osv-scanner", "semgrep"]);
      expect(events.every((e) => e.status === "completed")).toBe(true);
      // Ordered by completion, all delivered before the aggregate: the first is available early.
      expect(events.map((e) => e.at)).toEqual([...events.map((e) => e.at)].sort((x, y) => x - y));
      expect(events[events.length - 1].at).toBeLessThanOrEqual(resolvedAt);
      expect(events.reduce((n, e) => n + e.findings, 0)).toBe(result.findings.length);
      console.log(`[progressive] ${events.map((e) => `${e.scanner}@${e.at}ms(${e.findings})`).join(" ")} aggregate@${resolvedAt}ms`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 120_000);

  it("detects the planted secret (Gitleaks is genuinely scanning, not a no-op)", () => {
    const secret = baseline.find((f) => f.scanner === "gitleaks" && f.filePath === "config/settings.txt");
    expect(secret).toBeDefined();
    expect(JSON.stringify(baseline)).not.toContain(PLANTED_TOKEN);
  });

  it("verifies a real dependency fix: target resolved, every scanner completed, no new findings", async () => {
    expect(pytestFinding).toBeDefined();
    const fixed = pytestFinding.packageInfo!.fixedVersion!;
    const result = await verifyRemediationOnSnapshot({
      owner: "octocat",
      repo: "fixture",
      commitSha: SHA,
      unifiedDiff: `--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -2,1 +2,1 @@\n-pytest==7.1.0\n+pytest==${fixed}\n`,
      targetedFingerprints: [pytestFinding.fingerprint],
      baselineFindings: baseline.map(toBaselineFinding),
      config: getConfig(),
      fetchImpl,
    });

    expect(result.summary.scannerStatuses).toEqual({ gitleaks: "completed", semgrep: "completed", osvScanner: "completed" });
    expect(result.summary.snapshot).toEqual({ commitSha: SHA, fileCount: Object.keys(FILES).length });
    expect(result.summary.resolvedFingerprints).toEqual([pytestFinding.fingerprint]);
    expect(result.summary.regressions).toEqual([]);
    expect(result.rescanStatus).toBe("verified");
    // The unrelated secret is still reported: the whole tree was rescanned, not just the patched file.
    expect(result.rescanFindings.some((f) => f.scanner === "gitleaks")).toBe(true);
  }, 120_000);

  it("does not verify a bump to a version that is still vulnerable", async () => {
    const result = await verifyRemediationOnSnapshot({
      owner: "octocat",
      repo: "fixture",
      commitSha: SHA,
      unifiedDiff: "--- a/backend/requirements.txt\n+++ b/backend/requirements.txt\n@@ -2,1 +2,1 @@\n-pytest==7.1.0\n+pytest==7.1.1\n",
      targetedFingerprints: [pytestFinding.fingerprint],
      baselineFindings: baseline.map(toBaselineFinding),
      config: getConfig(),
      fetchImpl,
    });
    expect(result.rescanStatus).not.toBe("verified");
    expect(result.summary.targetResolved).toBe(false);
  }, 120_000);
});

describe.skipIf(missing.length > 0)("Real scanners: npm lockfile fix for Job-portal's multer", () => {
  const JP_SHA = "7f90143a47c6280f6bcf9d55bb7c4767a48c1542";
  const fixture = (f: string) => readFile(path.join(process.cwd(), "src/test/fixtures/npm-job-portal", f), "utf8");
  let files: Record<string, string>;
  let tarball: Buffer;
  let baseline: NormalizedFinding[];

  beforeAll(async () => {
    files = { "backend/package.json": await fixture("original.package.json"), "backend/package-lock.json": await fixture("original.package-lock.json"), "README.md": "# job portal\n" };
    tarball = await tarballOf(files);
    const dir = await mkdtemp(path.join(tmpdir(), "vs-real-npm-"));
    try {
      await extractArchiveSafely(Readable.from(tarball), dir, getConfig());
      const result = await runSecurityScanEngine(dir);
      expect([result.gitleaksStatus, result.semgrepStatus, result.osvStatus]).toEqual(["completed", "completed", "completed"]);
      baseline = result.findings;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("generates the npm-equivalent upgrade from live OSV and registry data and verifies it with a full rescan", async () => {
    const multer = baseline.filter((f) => f.scanner === "osv-scanner" && f.packageInfo?.name === "multer");
    expect(multer.length).toBeGreaterThanOrEqual(1);
    expect(multer.every((f) => f.filePath === "backend/package-lock.json" && f.packageInfo?.version === "2.0.2")).toBe(true);
    const target = multer.find((f) => f.packageInfo?.fixedVersion)!;
    const fp = (f: NormalizedFinding) => ({ ...f, fingerprint: f.fingerprint });
    const patch = await generateNpmLockfilePatch({
      finding: fp(target),
      scanFindings: baseline.map(fp),
      lockText: files["backend/package-lock.json"],
      readFile: async (p) => files[p],
      fetchImpl: fetch,
    });
    const diff = patch.files.map((f) => renderFileDiff(f.path, f.before, f.after)).join("");
    console.log(`[npm-fix] ${patch.patchSummary}; targets ${patch.findingFingerprints.length} of ${multer.length} multer findings`);

    const result = await verifyRemediationOnSnapshot({
      owner: "samarth-khera",
      repo: "Job-portal",
      commitSha: JP_SHA,
      unifiedDiff: diff,
      targetedFingerprints: patch.findingFingerprints,
      baselineFindings: baseline.map(toBaselineFinding),
      config: getConfig(),
      fetchImpl: async (url: string) => {
        if (url === `https://api.github.com/repos/samarth-khera/Job-portal/tarball/${JP_SHA}`) return new Response(new Uint8Array(tarball), { status: 200 });
        throw new Error(`Unexpected request: ${url}`);
      },
    });
    expect(result.summary.scannerStatuses).toEqual({ gitleaks: "completed", semgrep: "completed", osvScanner: "completed" });
    expect(new Set(result.summary.resolvedFingerprints)).toEqual(new Set(patch.findingFingerprints));
    expect(result.summary.regressions).toEqual([]);
    expect(result.rescanStatus).toBe("verified");
    expect(result.rescanFindings.filter((f) => f.packageInfo?.name === "multer")).toEqual([]);
  }, 180_000);

  it("verifies the transitive proxy-addr update (npm update semantics) with a full rescan", async () => {
    const proxy = baseline.find((f) => f.scanner === "osv-scanner" && f.packageInfo?.name === "proxy-addr");
    expect(proxy).toBeDefined();
    const patch = await generateNpmLockfilePatch({
      finding: proxy!,
      scanFindings: baseline,
      lockText: files["backend/package-lock.json"],
      readFile: async (p) => files[p],
      fetchImpl: fetch,
    });
    expect(patch.files.map((f) => f.path)).toEqual(["backend/package-lock.json"]); // package.json unchanged
    const diff = patch.files.map((f) => renderFileDiff(f.path, f.before, f.after)).join("");
    console.log(`[npm-fix] ${patch.patchSummary}`);
    const result = await verifyRemediationOnSnapshot({
      owner: "samarth-khera",
      repo: "Job-portal",
      commitSha: JP_SHA,
      unifiedDiff: diff,
      targetedFingerprints: patch.findingFingerprints,
      baselineFindings: baseline.map(toBaselineFinding),
      config: getConfig(),
      fetchImpl: async (url: string) => {
        if (url === `https://api.github.com/repos/samarth-khera/Job-portal/tarball/${JP_SHA}`) return new Response(new Uint8Array(tarball), { status: 200 });
        throw new Error(`Unexpected request: ${url}`);
      },
    });
    expect(result.summary.scannerStatuses).toEqual({ gitleaks: "completed", semgrep: "completed", osvScanner: "completed" });
    expect(result.summary.resolvedFingerprints).toEqual(patch.findingFingerprints);
    expect(result.summary.regressions).toEqual([]);
    expect(result.rescanStatus).toBe("verified");
    expect(result.rescanFindings.filter((f) => f.packageInfo?.name === "proxy-addr")).toEqual([]);
  }, 180_000);
});
