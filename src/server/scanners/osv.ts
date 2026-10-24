import path from "node:path";
import { runSubprocess } from "./runner";
import { computeFingerprint } from "./redact";
import type { NormalizedFinding, NormalizedSeverity, SingleScannerResult } from "./types";

export type OSVVulnerability = {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
  };
  affected?: {
    package?: { name: string; ecosystem?: string };
    ranges?: {
      type: string;
      events?: { introduced?: string; fixed?: string; last_affected?: string }[];
    }[];
  }[];
};

export type OSVPackage = {
  package: {
    name: string;
    version: string;
    ecosystem?: string;
  };
  vulnerabilities?: OSVVulnerability[];
};

export type OSVSourceResult = {
  source: {
    path: string;
    type?: string;
  };
  packages?: OSVPackage[];
};

export type OSVScannerOutput = {
  results?: OSVSourceResult[];
};

function parseCvssScore(vector: string): number | null {
  // Rough CVSS v3 score estimation from base metrics or vector if score isn't numeric
  const match = vector.match(/CVSS:[34]\.[01]\/.*\/([0-9.]+)/);
  if (match) return Number.parseFloat(match[1]);
  return null;
}

function normalizeOsvSeverity(vuln: OSVVulnerability): NormalizedSeverity {
  // Check CVSS score entries first
  for (const s of vuln.severity || []) {
    const numeric = parseCvssScore(s.score);
    if (numeric != null) {
      if (numeric >= 9.0) return "critical";
      if (numeric >= 7.0) return "high";
      if (numeric >= 4.0) return "medium";
      return "low";
    }
  }

  // Fall back to database_specific severity string
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev) {
    if (dbSev === "CRITICAL") return "critical";
    if (dbSev === "HIGH") return "high";
    if (dbSev === "MODERATE" || dbSev === "MEDIUM") return "medium";
    if (dbSev === "LOW") return "low";
  }

  return "medium";
}

function findFixedVersion(vuln: OSVVulnerability): string | null {
  for (const aff of vuln.affected || []) {
    for (const r of aff.ranges || []) {
      for (const ev of r.events || []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

export async function runOsvScan(
  targetDir: string,
  options?: { binaryPath?: string; timeoutMs?: number },
): Promise<SingleScannerResult> {
  const binary = options?.binaryPath || process.env.OSV_SCANNER_PATH || "osv-scanner";
  const startTime = Date.now();

  try {
    const { realpath } = await import("node:fs/promises");
    const scanPath = await realpath(targetDir).catch(() => path.resolve(targetDir));

    const res = await runSubprocess(
      binary,
      ["scan", "source", "-r", "--format", "json", "--allow-no-lockfiles", "--no-ignore", scanPath],
      {
        cwd: scanPath,
        timeoutMs: options?.timeoutMs ?? 60_000,
        allowedExitCodes: [0, 1],
      },
    );

    const stdout = res.stdout.trim();
    if (!stdout) {
      return {
        scanner: "osv-scanner",
        status: "completed",
        durationMs: res.durationMs,
        findings: [],
        coverage: {
          scanned: true,
          lockfilesFound: [],
          limitations: ["No supported dependency lockfiles were found in the repository."],
        },
      };
    }

    const jsonStart = stdout.indexOf("{");
    const jsonStr = jsonStart >= 0 ? stdout.slice(jsonStart) : stdout;
    const parsed: OSVScannerOutput = JSON.parse(jsonStr);

    const realTargetDir = path.resolve(targetDir);
    const results = parsed.results || [];
    const lockfilesFound: string[] = [];
    const findings: NormalizedFinding[] = [];

    for (const src of results) {
      const srcPath = src.source.path;
      let relPath = path.isAbsolute(srcPath) ? path.relative(realTargetDir, srcPath) : srcPath;
      if (relPath.startsWith("..") || relPath.startsWith("/")) {
        // Handle symlinked temp dirs like /private/var on macOS
        const targetBase = path.basename(realTargetDir);
        const idx = srcPath.indexOf(targetBase);
        if (idx >= 0) {
          relPath = srcPath.slice(idx + targetBase.length).replace(/^[/\\]+/, "");
        } else {
          relPath = path.basename(srcPath);
        }
      }
      if (!lockfilesFound.includes(relPath)) lockfilesFound.push(relPath);

      for (const pkg of src.packages || []) {
        const pkgName = pkg.package.name;
        const pkgVersion = pkg.package.version;
        const ecosystem = pkg.package.ecosystem;

        for (const vuln of pkg.vulnerabilities || []) {
          const vulnId = vuln.id;
          const severity = normalizeOsvSeverity(vuln);
          const fixedVer = findFixedVersion(vuln);

          const cveAlias = vuln.aliases?.find((a) => a.startsWith("CVE-"));
          const primaryId = cveAlias || vulnId;

          const title = vuln.summary || `Vulnerability ${vulnId} in ${pkgName}@${pkgVersion}`;
          const description = vuln.details || vuln.summary || `Known vulnerability affecting ${pkgName}@${pkgVersion}.`;

          const remediation = fixedVer
            ? `Upgrade ${pkgName} to version ${fixedVer} or higher.`
            : `Review advisory ${vulnId} for mitigation details and monitor for patched versions.`;

          findings.push({
            fingerprint: computeFingerprint(["osv-scanner", vulnId, relPath, pkgName, pkgVersion]),
            scanner: "osv-scanner",
            ruleId: vulnId,
            category: "Dependencies",
            severity,
            originalSeverity: vuln.database_specific?.severity ?? null,
            title,
            description,
            filePath: relPath,
            startLine: null,
            endLine: null,
            redactedEvidence: null,
            vulnerabilityId: primaryId,
            remediation,
            packageInfo: {
              name: pkgName,
              version: pkgVersion,
              ecosystem,
            },
            metadata: {
              aliases: vuln.aliases,
              fixedVersion: fixedVer,
              cwes: vuln.database_specific?.cwe_ids,
            },
          });
        }
      }
    }

    const limitations: string[] = [];
    if (lockfilesFound.length === 0) {
      limitations.push("No supported dependency lockfiles found in repository snapshot.");
    }

    return {
      scanner: "osv-scanner",
      status: "completed",
      durationMs: res.durationMs,
      findings,
      coverage: {
        scanned: true,
        lockfilesFound,
        limitations: limitations.length > 0 ? limitations : undefined,
      },
    };
  } catch (err) {
    return {
      scanner: "osv-scanner",
      status: "failed",
      durationMs: Date.now() - startTime,
      error: err instanceof Error ? err.message : "OSV-Scanner execution failed",
      findings: [],
      coverage: {
        scanned: false,
        lockfilesFound: [],
        limitations: ["OSV-Scanner failed during dependency analysis."],
      },
    };
  }
}
