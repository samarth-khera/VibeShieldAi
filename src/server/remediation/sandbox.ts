import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runSubprocess } from "../scanners/runner";
import { runSecurityScanEngine } from "../scanners/engine";
import { safeEntryPath } from "../archive";
import type { NormalizedFinding, ScanEngineResult } from "../scanners/types";
import type { RescanComparison, VerificationFailureReason } from "./types";
import { validateUnifiedDiff, applyUnifiedDiffString } from "./patch";
export { applyUnifiedDiffString };

/** What verification needs to know about each finding of the original scan. */
export type BaselineFinding = {
  fingerprint: string;
  scanner?: string;
  ruleId?: string;
  filePath?: string;
  packageName?: string | null;
};

/**
 * Identity of a finding that survives the patch itself. Fingerprints embed the package version
 * (OSV) or line number (Semgrep, Gitleaks), so after a version bump or a line shift the same issue
 * reappears under a new fingerprint. Matching on rule, file and package avoids reporting that as
 * "resolved". Findings without those fields fall back to their fingerprint.
 */
function identityOf(f: BaselineFinding): string {
  if (!f.scanner || !f.ruleId || !f.filePath) return `fp:${f.fingerprint}`;
  const pkg = f.scanner === "osv-scanner" ? (f.packageName ?? "").toLowerCase() : "";
  return [f.scanner, f.ruleId, f.filePath, pkg].join("\u0000");
}

export function toBaselineFinding(f: {
  fingerprint: string;
  scanner: string;
  ruleId: string;
  filePath: string;
  packageInfo?: unknown;
}): BaselineFinding {
  const name = (f.packageInfo as { name?: unknown } | null | undefined)?.name;
  return {
    fingerprint: f.fingerprint,
    scanner: f.scanner,
    ruleId: f.ruleId,
    filePath: f.filePath,
    packageName: typeof name === "string" ? name : null,
  };
}

/**
 * Compares the rescan with the original scan per identity. A targeted finding is resolved only if
 * its identity occurs at least that many times fewer; any identity that occurs more often than
 * before is a regression.
 */
export function compareWithBaseline(
  baseline: BaselineFinding[],
  targetedFingerprints: string[],
  rescan: NormalizedFinding[],
): { resolved: string[]; remaining: string[]; regressions: string[] } {
  const count = (list: BaselineFinding[]) => {
    const m = new Map<string, number>();
    for (const f of list) m.set(identityOf(f), (m.get(identityOf(f)) ?? 0) + 1);
    return m;
  };
  const targeted = new Set(targetedFingerprints);
  const baselineByFp = new Map(baseline.map((f) => [f.fingerprint, f]));
  const targets = targetedFingerprints.map((fp) => baselineByFp.get(fp) ?? { fingerprint: fp });
  const before = count(baseline);
  const targetCounts = count(targets);
  const after = count(rescan.map(toBaselineFinding));
  const baselineFps = new Set(baseline.map((f) => f.fingerprint));

  const resolved: string[] = [];
  const remaining: string[] = [];
  for (const t of targets) {
    const id = identityOf(t);
    const expected = (before.get(id) ?? targetCounts.get(id) ?? 0) - (targetCounts.get(id) ?? 0);
    ((after.get(id) ?? 0) > Math.max(0, expected) ? remaining : resolved).push(t.fingerprint);
  }

  const regressions: string[] = [];
  for (const f of rescan) {
    const id = identityOf(toBaselineFinding(f));
    if (baselineFps.has(f.fingerprint) || targeted.has(f.fingerprint)) continue;
    const allowed = Math.max(before.get(id) ?? 0, 0);
    if ((after.get(id) ?? 0) > allowed) regressions.push(f.fingerprint);
  }
  return { resolved, remaining, regressions };
}

export type ApplyAndRescanParams = {
  /** Every finding recorded by the original scan (the regression baseline). */
  originalFindings: BaselineFinding[];
  targetedFingerprints: string[];
  unifiedDiff: string;
  /**
   * Directory holding the complete repository snapshot at the scanned commit.
   * The patch is applied in place, so the caller must pass a disposable copy.
   */
  sourceDir?: string;
  /** Complete in-memory repository snapshot (local fixtures and tests). */
  sourceFiles?: Record<string, string>;
  scanEngine?: (dir: string) => Promise<ScanEngineResult>;
};

export type SandboxResult = {
  rescanStatus: "verified" | "needs_review" | "failed";
  summary: RescanComparison;
  rescanFindings: NormalizedFinding[];
};

export function failedResult(
  params: Pick<ApplyAndRescanParams, "originalFindings" | "targetedFingerprints">,
  reason: VerificationFailureReason,
  detail: string,
  extra?: Partial<RescanComparison>,
): SandboxResult {
  return {
    rescanStatus: "failed",
    rescanFindings: [],
    summary: {
      // Nothing was verified, so nothing may be reported as resolved.
      targetResolved: false,
      originalFindingsCount: params.originalFindings.length,
      postRescanFindingsCount: 0,
      newFindingsCount: 0,
      resolvedFingerprints: [],
      remainingFingerprints: [...params.targetedFingerprints],
      regressions: [],
      reason,
      detail,
      ...extra,
    },
  };
}

async function materializeSourceFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [relPath, content] of Object.entries(files)) {
    // Reuse the archive extractor's boundary check: the first segment is a synthetic root.
    const dest = safeEntryPath(root, `snapshot/${relPath}`);
    if (!dest) throw new Error(`Snapshot path escapes the sandbox: ${relPath}`);
    await mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
    await writeFile(dest, content, { mode: 0o600 });
  }
}

/**
 * Applies an approved patch to a complete repository snapshot and runs the real security
 * scanners against the patched tree.
 *
 * The result is `verified` only when the patch applies cleanly to the intended revision,
 * every scanner finishes successfully, every targeted finding is gone, and no finding
 * appears that the original scan did not report. Missing source, a patch that does not
 * apply, or a failed scanner is reported as `failed` and never as a resolution.
 */
export async function applyAndRescanInSandbox(params: ApplyAndRescanParams): Promise<SandboxResult> {
  const validation = validateUnifiedDiff(params.unifiedDiff);
  if (!validation.valid) {
    throw new Error(`Invalid patch diff: ${validation.error}`);
  }

  if (!params.sourceDir && !params.sourceFiles) {
    return failedResult(
      params,
      "source_snapshot_unavailable",
      "No repository snapshot was available for the scanned commit, so the patch could not be verified.",
    );
  }

  const scratch = await mkdtemp(path.join(tmpdir(), "vibeshield-sandbox-"));
  await chmod(scratch, 0o700);
  const engine = params.scanEngine ?? runSecurityScanEngine;

  try {
    let workspace = params.sourceDir;
    if (!workspace) {
      workspace = path.join(scratch, "tree");
      await mkdir(workspace, { mode: 0o700 });
      await materializeSourceFiles(workspace, params.sourceFiles!);
    }

    // Every file the diff modifies must exist in the snapshot; otherwise it targets another revision.
    for (const rel of validation.affectedFiles) {
      const target = safeEntryPath(workspace, `snapshot/${rel}`);
      const info = target ? await stat(target).catch(() => null) : null;
      if (!info?.isFile()) {
        return failedResult(params, "patch_target_missing", `Patched file is not present in the snapshot: ${rel}`);
      }
    }

    // Keep the patch outside the scanned tree so scanners never see it.
    const patchPath = path.join(scratch, "fix.patch");
    await writeFile(patchPath, params.unifiedDiff, { mode: 0o600 });

    const tApply = Date.now();
    // Generated hunks carry no context lines; --unidiff-zero still requires every removed line to
    // match the snapshot exactly, so a patch for another revision is rejected.
    const gitArgs = ["apply", "--whitespace=nowarn", "--unidiff-zero"];
    const check = await runSubprocess("git", [...gitArgs, "--check", patchPath], {
      cwd: workspace,
      timeoutMs: 10_000,
      allowedExitCodes: [0, 1, 128],
    }).catch(() => null);
    if (!check) {
      return failedResult(params, "patch_tool_unavailable", "git is not available to apply the patch.");
    }
    if (check.exitCode !== 0) {
      return failedResult(
        params,
        "patch_does_not_apply",
        "The approved patch does not apply cleanly to the scanned revision.",
      );
    }
    await runSubprocess("git", [...gitArgs, patchPath], { cwd: workspace, timeoutMs: 10_000 });
    const applyMs = Date.now() - tApply;

    const tScan = Date.now();
    const rescanResult = await engine(workspace);
    const scanMs = Date.now() - tScan;

    const scannerStatuses = {
      gitleaks: rescanResult.gitleaksStatus,
      semgrep: rescanResult.semgrepStatus,
      osvScanner: rescanResult.osvStatus,
    };
    const timings = {
      applyMs,
      scanMs,
      gitleaksMs: rescanResult.gitleaksDurationMs,
      semgrepMs: rescanResult.semgrepDurationMs,
      osvMs: rescanResult.osvDurationMs,
    };
    const failedScanners = Object.entries(scannerStatuses)
      .filter(([, status]) => status !== "completed")
      .map(([name]) => name);
    if (failedScanners.length > 0) {
      return failedResult(
        params,
        "scanner_failed",
        `Required scanners did not complete: ${failedScanners.join(", ")}.`,
        { scannerStatuses, timings },
      );
    }

    const {
      resolved: resolvedFingerprints,
      remaining: remainingFingerprints,
      regressions: newFindings,
    } = compareWithBaseline(params.originalFindings, params.targetedFingerprints, rescanResult.findings);

    const targetResolved = remainingFingerprints.length === 0 && resolvedFingerprints.length > 0;
    const hasRegressions = newFindings.length > 0;
    const rescanStatus = targetResolved && !hasRegressions ? "verified" : "needs_review";

    return {
      rescanStatus,
      rescanFindings: rescanResult.findings,
      summary: {
        targetResolved,
        originalFindingsCount: params.originalFindings.length,
        postRescanFindingsCount: rescanResult.findings.length,
        newFindingsCount: newFindings.length,
        resolvedFingerprints,
        remainingFingerprints,
        regressions: newFindings,
        reason: rescanStatus === "verified" ? undefined : hasRegressions ? "new_findings_introduced" : "target_not_resolved",
        scannerStatuses,
        timings,
      },
    };
  } finally {
    await rm(scratch, { recursive: true, force: true }).catch(() => undefined);
  }
}
