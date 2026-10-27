import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runSubprocess } from "../scanners/runner";
import { runSecurityScanEngine } from "../scanners/engine";
import type { NormalizedFinding, ScanEngineResult } from "../scanners/types";
import type { RescanComparison } from "./types";
import { validateUnifiedDiff, applyUnifiedDiffString } from "./patch";
export { applyUnifiedDiffString };

export type ApplyAndRescanParams = {
  originalFindings: NormalizedFinding[];
  targetedFingerprints: string[];
  unifiedDiff: string;
  sourceFiles?: Record<string, string>; // In-memory source files (or downloaded repo files)
  scanEngine?: (dir: string) => Promise<ScanEngineResult>;
};

/**
 * Executes the patch application and rescan pipeline in a strictly isolated temporary workspace.
 * Verifies that:
 * 1. The target finding(s) are eliminated.
 * 2. No new security regressions or findings are introduced.
 * 3. Scanners execute cleanly without errors.
 */
export async function applyAndRescanInSandbox(params: ApplyAndRescanParams): Promise<{
  rescanStatus: "verified" | "needs_review" | "failed";
  summary: RescanComparison;
  rescanFindings: NormalizedFinding[];
}> {
  const validation = validateUnifiedDiff(params.unifiedDiff);
  if (!validation.valid) {
    throw new Error(`Invalid patch diff: ${validation.error}`);
  }

  const workspace = await mkdtemp(path.join(tmpdir(), "vibeshield-sandbox-"));
  await chmod(workspace, 0o700);

  const engine = params.scanEngine ?? runSecurityScanEngine;

  try {
    // 1. Initialize empty git workspace for patch execution
    await runSubprocess("git", ["init", "-q"], { cwd: workspace, timeoutMs: 5000 }).catch(() => undefined);

    // 2. Populate sandbox with source files if provided
    if (params.sourceFiles) {
      for (const [relPath, content] of Object.entries(params.sourceFiles)) {
        const dest = path.join(workspace, relPath);
        await mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
        await writeFile(dest, content, { mode: 0o600 });
      }
    } else {
      // Create minimal placeholders for affected files so patch can apply
      for (const rel of validation.affectedFiles) {
        const dest = path.join(workspace, rel);
        await mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
        await writeFile(dest, "// source file placeholder\n", { mode: 0o600 });
      }
    }

    // 3. Write and apply patch
    const patchPath = path.join(workspace, "fix.patch");
    await writeFile(patchPath, params.unifiedDiff, { mode: 0o600 });

    const applyResult = await runSubprocess("git", ["apply", "--whitespace=fix", "fix.patch"], {
      cwd: workspace,
      timeoutMs: 10000,
      allowedExitCodes: [0, 1],
    }).catch(() => null);

    // If git apply is not available or failed on empty placeholder, apply in memory
    if (!applyResult || applyResult.exitCode !== 0) {
      for (const rel of validation.affectedFiles) {
        const filePath = path.join(workspace, rel);
        const originalContent = await readFile(filePath, "utf8").catch(() => "");
        const patched = applyUnifiedDiffString(originalContent, params.unifiedDiff);
        await writeFile(filePath, patched, { mode: 0o600 });
      }
    }

    // Remove the patch file before scanning so scanners don't scan the patch itself
    await rm(patchPath, { force: true }).catch(() => undefined);

    // 4. Run real security scanner rescan on the patched code
    const rescanResult = await engine(workspace);

    // 5. Compare findings before and after
    const targetedSet = new Set(params.targetedFingerprints);
    const originalSet = new Set(params.originalFindings.map((f) => f.fingerprint));

    const remainingFingerprints: string[] = [];
    const resolvedFingerprints: string[] = [];
    const newFindings: string[] = [];

    for (const f of rescanResult.findings) {
      if (targetedSet.has(f.fingerprint)) {
        remainingFingerprints.push(f.fingerprint);
      }
      if (!originalSet.has(f.fingerprint)) {
        newFindings.push(f.fingerprint);
      }
    }

    for (const fp of params.targetedFingerprints) {
      if (!remainingFingerprints.includes(fp)) {
        resolvedFingerprints.push(fp);
      }
    }

    const targetResolved = remainingFingerprints.length === 0 && resolvedFingerprints.length > 0;
    const isCleanRescan = rescanResult.status === "completed" || rescanResult.status === "completed_with_warnings";
    const hasRegressions = newFindings.length > 0;

    let rescanStatus: "verified" | "needs_review" | "failed" = "needs_review";

    if (isCleanRescan && targetResolved && !hasRegressions) {
      rescanStatus = "verified";
    } else if (rescanResult.status === "failed") {
      rescanStatus = "failed";
    } else {
      rescanStatus = "needs_review";
    }

    const summary: RescanComparison = {
      targetResolved,
      originalFindingsCount: params.originalFindings.length,
      postRescanFindingsCount: rescanResult.findings.length,
      newFindingsCount: newFindings.length,
      resolvedFingerprints,
      remainingFingerprints,
      regressions: newFindings,
    };

    return {
      rescanStatus,
      summary,
      rescanFindings: rescanResult.findings,
    };
  } finally {
    await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  }
}
