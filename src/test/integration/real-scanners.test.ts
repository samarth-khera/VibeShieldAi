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
