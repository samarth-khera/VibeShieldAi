import { runGitleaksScan } from "./gitleaks";
import { runSemgrepScan } from "./semgrep";
import { runOsvScan } from "./osv";
import { runSubprocess } from "./runner";
import type { NormalizedFinding, ScanCoverage, ScanEngineResult, ScannerVersions } from "./types";

export async function detectScannerVersions(): Promise<ScannerVersions> {
  const versions: ScannerVersions = {
    gitleaks: null,
    semgrep: null,
    osvScanner: null,
  };

  try {
    const res = await runSubprocess("gitleaks", ["version"], { cwd: "/tmp", timeoutMs: 5000 });
    versions.gitleaks = res.stdout.trim() || null;
  } catch {
    versions.gitleaks = "unavailable";
  }

  try {
    const res = await runSubprocess("semgrep", ["--version"], { cwd: "/tmp", timeoutMs: 5000 });
    versions.semgrep = res.stdout.trim().split("\n")[0] || null;
  } catch {
    versions.semgrep = "unavailable";
  }

  try {
    const res = await runSubprocess("osv-scanner", ["--version"], { cwd: "/tmp", timeoutMs: 5000 });
    const line = res.stdout.trim().split("\n").find((l) => l.includes("osv-scanner version:"));
    versions.osvScanner = line ? line.replace("osv-scanner version:", "").trim() : (res.stdout.trim().split("\n")[0] || null);
  } catch {
    versions.osvScanner = "unavailable";
  }

  return versions;
}

export type ScanEngineOptions = {
  gitleaksBinary?: string;
  semgrepBinary?: string;
  semgrepRulesPath?: string;
  osvBinary?: string;
  timeoutMs?: number;
};

export async function runSecurityScanEngine(
  targetDir: string,
  options?: ScanEngineOptions,
): Promise<ScanEngineResult> {
  const versions = await detectScannerVersions();

  // Run all three scanners
  const [gitleaksRes, semgrepRes, osvRes] = await Promise.all([
    runGitleaksScan(targetDir, {
      binaryPath: options?.gitleaksBinary,
      timeoutMs: options?.timeoutMs,
    }),
    runSemgrepScan(targetDir, {
      binaryPath: options?.semgrepBinary,
      rulesPath: options?.semgrepRulesPath,
      timeoutMs: options?.timeoutMs,
    }),
    runOsvScan(targetDir, {
      binaryPath: options?.osvBinary,
      timeoutMs: options?.timeoutMs,
    }),
  ]);

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
