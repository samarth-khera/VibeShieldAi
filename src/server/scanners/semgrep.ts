import path from "node:path";
import { runSubprocess } from "./runner";
import { computeFingerprint, redactEvidence, redactText } from "./redact";
import type { NormalizedFinding, NormalizedSeverity, SingleScannerResult } from "./types";

export type SemgrepRawResult = {
  check_id: string;
  path: string;
  start: { line: number; col?: number; offset?: number };
  end: { line: number; col?: number; offset?: number };
  extra: {
    message: string;
    severity: string;
    lines?: string;
    metadata?: {
      cwe?: string[];
      owasp?: string[];
      references?: string[];
      remediation?: string;
      confidence?: string;
    };
  };
};

export type SemgrepOutput = {
  results: SemgrepRawResult[];
  errors?: unknown[];
};

function normalizeSemgrepSeverity(rawSeverity: string, checkId: string): NormalizedSeverity {
  const upper = rawSeverity.toUpperCase();
  if (upper === "ERROR") {
    // If it's an RCE or direct eval injection, mark as critical
    if (checkId.includes("eval") || checkId.includes("command-injection") || checkId.includes("pickle")) {
      return "critical";
    }
    return "high";
  }
  if (upper === "WARNING") return "medium";
  if (upper === "INFO") return "low";
  return "medium";
}

export async function runSemgrepScan(
  targetDir: string,
  options?: { rulesPath?: string; binaryPath?: string; timeoutMs?: number },
): Promise<SingleScannerResult> {
  const binary = options?.binaryPath || process.env.SEMGREP_PATH || "semgrep";
  const rulesPath = options?.rulesPath || path.resolve(process.cwd(), "rules/semgrep-rules.yaml");
  const startTime = Date.now();

  try {
    const res = await runSubprocess(
      binary,
      [
        "scan",
        "--config",
        rulesPath,
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--disable-version-check",
        "--metrics=off",
        targetDir,
      ],
      {
        cwd: targetDir,
        timeoutMs: options?.timeoutMs ?? 60_000,
        allowedExitCodes: [0, 1],
      },
    );

    const stdout = res.stdout.trim();
    if (!stdout) {
      // `semgrep --json` always prints a report when it actually ran.
      throw new Error("Semgrep produced no JSON report.");
    }

    const jsonStart = stdout.indexOf("{");
    const jsonStr = jsonStart >= 0 ? stdout.slice(jsonStart) : stdout;
    const parsed: SemgrepOutput = JSON.parse(jsonStr);

    const findings: NormalizedFinding[] = [];

    const realTargetDir = path.resolve(targetDir);
    for (const r of parsed.results || []) {
      let relPath = path.isAbsolute(r.path) ? path.relative(realTargetDir, r.path) : r.path;
      if (relPath.startsWith("..") || relPath.startsWith("/")) {
        const targetBase = path.basename(realTargetDir);
        const idx = r.path.indexOf(targetBase);
        if (idx >= 0) {
          relPath = r.path.slice(idx + targetBase.length).replace(/^[/\\]+/, "");
        } else {
          relPath = path.basename(r.path);
        }
      }
      const startLine = r.start?.line ?? null;
      const endLine = r.end?.line ?? startLine;
      const ruleId = r.check_id.split(".").pop() || r.check_id;
      const severity = normalizeSemgrepSeverity(r.extra.severity, ruleId);

      const firstSentence = r.extra.message.split(".")[0]?.trim() || ruleId;
      const title = firstSentence.length > 80 ? `${firstSentence.slice(0, 77)}...` : firstSentence;

      const metadata = r.extra.metadata || {};
      const remediation =
        metadata.remediation ||
        "Review this code construct and refactor to use safe, parameterized APIs or static validation.";

      findings.push({
        fingerprint: computeFingerprint(["semgrep", ruleId, relPath, startLine]),
        scanner: "semgrep",
        ruleId,
        category: "Code Analysis",
        severity,
        originalSeverity: r.extra.severity,
        title,
        description: r.extra.message,
        filePath: relPath,
        startLine,
        endLine,
        redactedEvidence: redactEvidence(r.extra.lines),
        vulnerabilityId: null,
        remediation,
        metadata: {
          cwe: metadata.cwe,
          owasp: metadata.owasp,
          references: metadata.references,
          confidence: metadata.confidence,
        },
      });
    }

    return {
      scanner: "semgrep",
      status: "completed",
      durationMs: res.durationMs,
      findings,
      coverage: { scanned: true },
    };
  } catch (err) {
    return {
      scanner: "semgrep",
      status: "failed",
      durationMs: Date.now() - startTime,
      error: redactText(err instanceof Error ? err.message : "Semgrep execution failed"),
      findings: [],
      coverage: { scanned: false, limitations: ["Semgrep static analysis failed during execution."] },
    };
  }
}
