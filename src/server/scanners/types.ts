export type NormalizedSeverity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory = "Secrets" | "Code Analysis" | "Dependencies";

export type NormalizedFinding = {
  id?: string;
  fingerprint: string;
  scanner: "gitleaks" | "semgrep" | "osv-scanner";
  ruleId: string;
  category: FindingCategory;
  severity: NormalizedSeverity;
  originalSeverity?: string | null;
  title: string;
  description: string;
  filePath: string;
  startLine: number | null;
  endLine: number | null;
  redactedEvidence: string | null;
  vulnerabilityId: string | null;
  remediation: string | null;
  packageInfo?: {
    name: string;
    version: string;
    ecosystem?: string;
  } | null;
  metadata?: Record<string, unknown> | null;
};

export type ScannerStatus = "completed" | "failed" | "skipped";

export type SingleScannerResult = {
  scanner: "gitleaks" | "semgrep" | "osv-scanner";
  status: ScannerStatus;
  durationMs: number;
  error?: string | null;
  findings: NormalizedFinding[];
  coverage?: {
    scanned: boolean;
    filesCount?: number;
    lockfilesFound?: string[];
    limitations?: string[];
  };
};

export type ScannerVersions = {
  gitleaks: string | null;
  semgrep: string | null;
  osvScanner: string | null;
};

export type ScanCoverage = {
  filesAnalyzed?: number;
  lockfilesFound: string[];
  scannersRun: string[];
  limitations: string[];
};

export type ScanEngineResult = {
  status: "completed" | "completed_with_warnings" | "failed";
  gitleaksStatus: ScannerStatus;
  gitleaksDurationMs: number;
  gitleaksError: string | null;

  semgrepStatus: ScannerStatus;
  semgrepDurationMs: number;
  semgrepError: string | null;

  osvStatus: ScannerStatus;
  osvDurationMs: number;
  osvError: string | null;

  scannerVersions: ScannerVersions;
  scanCoverage: ScanCoverage;

  findings: NormalizedFinding[];
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
};
