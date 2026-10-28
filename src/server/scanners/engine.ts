import { runGitleaksScan } from "./gitleaks";
import { runSemgrepScan } from "./semgrep";
import { runOsvScan } from "./osv";
import { runSubprocess } from "./runner";
import type { NormalizedFinding, ScanCoverage, ScanEngineResult, ScannerVersions, SingleScannerResult } from "./types";

let cachedVersions: ScannerVersions | null = null;

export async function detectScannerVersions(forceRefresh = false): Promise<ScannerVersions> {
  if (!forceRefresh && cachedVersions) {
    return cachedVersions;
  }

  const [gitleaksRes, semgrepRes, osvRes] = await Promise.all([
    runSubprocess("gitleaks", ["version"], { cwd: "/tmp", timeoutMs: 5000 }).catch(() => null),
    runSubprocess("semgrep", ["--version"], { cwd: "/tmp", timeoutMs: 5000 }).catch(() => null),
    runSubprocess("osv-scanner", ["--version"], { cwd: "/tmp", timeoutMs: 5000 }).catch(() => null),
  ]);

  const gitleaks = gitleaksRes?.stdout ? gitleaksRes.stdout.trim() || null : "unavailable";
  const semgrep = semgrepRes?.stdout ? semgrepRes.stdout.trim().split("\n")[0] || null : "unavailable";
  let osvScanner: string | null = "unavailable";
  if (osvRes?.stdout) {
    const line = osvRes.stdout.trim().split("\n").find((l) => l.includes("osv-scanner version:"));
    osvScanner = line ? line.replace("osv-scanner version:", "").trim() : (osvRes.stdout.trim().split("\n")[0] || null);
  }

  const versions: ScannerVersions = {
    gitleaks,
    semgrep,
    osvScanner,
  };

  cachedVersions = versions;
  return versions;
}

export type ScanEngineOptions = {
  gitleaksBinary?: string;
  semgrepBinary?: string;
  semgrepRulesPath?: string;
  osvBinary?: string;
  timeoutMs?: number;
  /**
   * Called as soon as each scanner finishes (in completion order), so its findings can be
   * published before the slower scanners are done. The engine awaits every callback before
   * resolving, so the final aggregate is never reported ahead of a partial result.
   */
  onScannerComplete?: (result: SingleScannerResult) => Promise<void> | void;
};

export async function runSecurityScanEngine(
  targetDir: string,
  options?: ScanEngineOptions,
): Promise<ScanEngineResult> {
  const versions = await detectScannerVersions();

  // Run all three scanners in parallel; publish each result as it lands.
  const callbacks: Promise<void>[] = [];
  const settle = (p: Promise<SingleScannerResult>) =>
    p.then((r) => {
      if (options?.onScannerComplete) {
        callbacks.push(Promise.resolve(options.onScannerComplete(r)).catch(() => undefined));
      }
      return r;
    });
  const [gitleaksRes, semgrepRes, osvRes] = await Promise.all([
    settle(
      runGitleaksScan(targetDir, {
        binaryPath: options?.gitleaksBinary,
        timeoutMs: options?.timeoutMs,
      }),
    ),
    settle(
      runSemgrepScan(targetDir, {
        binaryPath: options?.semgrepBinary,
        rulesPath: options?.semgrepRulesPath,
        timeoutMs: options?.timeoutMs,
      }),
    ),
    settle(
      runOsvScan(targetDir, {
        binaryPath: options?.osvBinary,
        timeoutMs: options?.timeoutMs,
      }),
    ),
  ]);
  await Promise.all(callbacks);

  // Aggregate findings with deduplication by fingerprint
  const seenFingerprints = new Set<string>();
  const allFindings: NormalizedFinding[] = [];

  for (const f of [...gitleaksRes.findings, ...semgrepRes.findings, ...osvRes.findings]) {
    if (!seenFingerprints.has(f.fingerprint)) {
      seenFingerprints.add(f.fingerprint);
      allFindings.push(f);
    }
  }

  // Count severities
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: allFindings.length,
  };

  for (const f of allFindings) {
    if (f.severity in counts) {
      counts[f.severity as keyof typeof counts]++;
    }
  }

  // Determine overall status
  const statuses = [gitleaksRes.status, semgrepRes.status, osvRes.status];
  const failures = statuses.filter((s) => s === "failed").length;

  let overallStatus: "completed" | "completed_with_warnings" | "failed" = "completed";
  if (failures === 3) {
    overallStatus = "failed";
  } else if (failures > 0) {
    overallStatus = "completed_with_warnings";
  }

  const limitations: string[] = [];
  if (gitleaksRes.coverage?.limitations) limitations.push(...gitleaksRes.coverage.limitations);
  if (semgrepRes.coverage?.limitations) limitations.push(...semgrepRes.coverage.limitations);
  if (osvRes.coverage?.limitations) limitations.push(...osvRes.coverage.limitations);

  const coverage: ScanCoverage = {
    scannersRun: ["gitleaks", "semgrep", "osv-scanner"],
    lockfilesFound: osvRes.coverage?.lockfilesFound ?? [],
    limitations,
  };

  return {
    status: overallStatus,
    gitleaksStatus: gitleaksRes.status,
    gitleaksDurationMs: gitleaksRes.durationMs,
    gitleaksError: gitleaksRes.error ?? null,

    semgrepStatus: semgrepRes.status,
    semgrepDurationMs: semgrepRes.durationMs,
    semgrepError: semgrepRes.error ?? null,

    osvStatus: osvRes.status,
    osvDurationMs: osvRes.durationMs,
    osvError: osvRes.error ?? null,

    scannerVersions: versions,
    scanCoverage: coverage,

    findings: allFindings,
    counts,
  };
}
