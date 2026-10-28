import path from "node:path";
import { runSubprocess } from "./runner";
import { computeFingerprint, redactEvidence, redactText } from "./redact";
import type { NormalizedFinding, SingleScannerResult } from "./types";

export type GitleaksRawFinding = {
  RuleID?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  Fingerprint?: string;
};

export async function runGitleaksScan(
  targetDir: string,
  options?: { binaryPath?: string; timeoutMs?: number },
): Promise<SingleScannerResult> {
  const binary = options?.binaryPath || process.env.GITLEAKS_PATH || "gitleaks";
  const startTime = Date.now();

  try {
    const res = await runSubprocess(
      binary,
      ["dir", targetDir, "--report-format", "json", "--report-path", "-", "--redact", "--no-banner", "--exit-code", "0"],
      {
        cwd: targetDir,
        timeoutMs: options?.timeoutMs ?? 60_000,
        // With --exit-code 0 a non-zero exit only means Gitleaks itself failed (e.g. an unsupported
        // subcommand on an old binary), which must never be reported as a clean scan.
        allowedExitCodes: [0],
      },
    );

    const stdout = res.stdout.trim();
    if (!stdout) {
      throw new Error("Gitleaks produced no JSON report.");
    }
    if (stdout === "[]" || stdout === "null") {
      return {
        scanner: "gitleaks",
        status: "completed",
        durationMs: res.durationMs,
        findings: [],
        coverage: { scanned: true },
      };
    }

    // Gitleaks might output log lines on stdout before the JSON array if flags aren't quiet enough
    let jsonStart = stdout.indexOf("[");
    if (jsonStart === -1) {
      jsonStart = stdout.indexOf("{");
    }
    const jsonStr = jsonStart >= 0 ? stdout.slice(jsonStart) : stdout;

    const rawList: GitleaksRawFinding[] = JSON.parse(jsonStr);
    const findings: NormalizedFinding[] = [];

    const realTargetDir = path.resolve(targetDir);
    for (const raw of rawList) {
      const rawFile = raw.File || "unknown";
      let relPath = path.isAbsolute(rawFile) ? path.relative(realTargetDir, rawFile) : rawFile;
      if (relPath.startsWith("..") || relPath.startsWith("/")) {
        const targetBase = path.basename(realTargetDir);
        const idx = rawFile.indexOf(targetBase);
        if (idx >= 0) {
          relPath = rawFile.slice(idx + targetBase.length).replace(/^[/\\]+/, "");
        } else {
          relPath = path.basename(rawFile);
        }
      }
      const ruleId = raw.RuleID || "exposed-secret";
      const startLine = raw.StartLine ?? null;
      const endLine = raw.EndLine ?? startLine;

      // Double-redact to be completely certain no unredacted secret enters the system
      const redactedMatch = redactEvidence(raw.Match || raw.Secret || "REDACTED");

      findings.push({
        fingerprint: computeFingerprint(["gitleaks", ruleId, relPath, startLine]),
        scanner: "gitleaks",
        ruleId,
        category: "Secrets",
        severity: "critical",
        originalSeverity: "CRITICAL",
        title: raw.Description ? `Secret detected: ${raw.Description}` : `Exposed secret (${ruleId})`,
        description: raw.Description || "An exposed credential or sensitive token was detected in the repository.",
        filePath: relPath,
        startLine,
        endLine,
        redactedEvidence: redactedMatch,
        vulnerabilityId: null,
        remediation: "Revoke and rotate this secret immediately in the provider dashboard. Remove the secret from code history and load it securely through environment variables.",
        metadata: {
          scanner: "gitleaks",
          ruleId,
        },
      });
    }

    return {
      scanner: "gitleaks",
      status: "completed",
      durationMs: res.durationMs,
      findings,
      coverage: { scanned: true },
    };
  } catch (err) {
    return {
      scanner: "gitleaks",
      status: "failed",
      durationMs: Date.now() - startTime,
      error: redactText(err instanceof Error ? err.message : "Gitleaks execution failed"),
      findings: [],
      coverage: { scanned: false, limitations: ["Gitleaks scanner failed during execution."] },
    };
  }
}
