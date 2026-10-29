import type { PullRequestState } from "./github-pr";
export type RemediationEligibilityType = "safe" | "potentially_breaking" | "unsuitable";

export type RemediationStatus =
  | "preview"
  | "approved"
  /** Approved patch handed to the verification worker; result pending. */
  | "applied"
  | "verified"
  | "needs_review"
  | "failed"
  | "rejected";

export type RemediationEligibility = {
  eligibility: RemediationEligibilityType;
  reason: string;
  canAutoFix: boolean;
  requiresRotation: boolean;
  warnings: string[];
};

export type VerificationFailureReason =
  | "source_snapshot_unavailable"
  | "commit_unknown"
  | "patch_target_missing"
  | "patch_tool_unavailable"
  | "patch_does_not_apply"
  | "patch_integrity_mismatch"
  | "scanner_failed"
  | "target_not_resolved"
  | "new_findings_introduced"
  | "verification_timeout"
  | "worker_failed";

export type VerificationTimings = {
  queueMs?: number;
  specFetchMs?: number;
  downloadMs?: number;
  extractionMs?: number;
  applyMs?: number;
  scanMs?: number;
  gitleaksMs?: number;
  semgrepMs?: number;
  osvMs?: number;
  totalMs?: number;
};

export type RescanComparison = {
  targetResolved: boolean;
  originalFindingsCount: number;
  postRescanFindingsCount: number;
  newFindingsCount: number;
  resolvedFingerprints: string[];
  remainingFingerprints: string[];
  regressions: string[];
  /** Why the result is not `verified`. Absent on success. */
  reason?: VerificationFailureReason;
  detail?: string;
  scannerStatuses?: { gitleaks: string; semgrep: string; osvScanner: string };
  timings?: VerificationTimings;
  /** Where verification ran and what it ran against. */
  runtime?: "github-actions" | "warm-worker" | "local";
  snapshot?: { commitSha: string; fileCount: number };
  /** Whether the repository archive came from the worker's commit-keyed cache. */
  archiveCache?: "hit" | "miss" | "none";
  workflowRunUrl?: string;
};

export type RemediationRecord = {
  id: string;
  scanJobId: string;
  status: RemediationStatus;
  findingFingerprints: string[];
  commitSha: string;

  patchSummary: string;
  unifiedDiff: string;
  affectedFiles: string[];
  eligibility: RemediationEligibilityType;
  eligibilityReason: string;
  requiresRotation: boolean;
  warnings?: string[];

  approvedAt: Date | null;
  approvedOperations?: unknown;

  rescanStatus: "verified" | "needs_review" | "failed" | null;
  rescanSummary?: RescanComparison | null;

  branchName: string | null;
  pullRequestUrl: string | null;

  createdAt: Date;
  updatedAt: Date;
};

export type NewRemediation = Omit<RemediationRecord, "createdAt" | "updatedAt">;

export type PublicRemediation = {
  id: string;
  scanJobId: string;
  status: RemediationStatus;
  findingFingerprints: string[];
  commitSha: string;
  patchSummary: string;
  unifiedDiff: string;
  affectedFiles: string[];
  eligibility: RemediationEligibilityType;
  eligibilityReason: string;
  requiresRotation: boolean;
  warnings: string[];
  approvedAt: string | null;
  rescanStatus: "verified" | "needs_review" | "failed" | null;
  rescanSummary: RescanComparison | null;
  branchName: string | null;
  pullRequestUrl: string | null;
  /** Outcome of the last pull-request attempt; GitHub authorization state comes from /api/auth/github/status. */
  pullRequest: PullRequestState | null;
  createdAt: string;
  updatedAt: string;
};

export function toPublicRemediation(r: RemediationRecord): PublicRemediation {
  const last = (r.approvedOperations as { pullRequest?: PullRequestState } | null)?.pullRequest;
  return {
    id: r.id,
    scanJobId: r.scanJobId,
    status: r.status,
    findingFingerprints: r.findingFingerprints,
    commitSha: r.commitSha,
    patchSummary: r.patchSummary,
    unifiedDiff: r.unifiedDiff,
    affectedFiles: r.affectedFiles,
    eligibility: r.eligibility,
    eligibilityReason: r.eligibilityReason,
    requiresRotation: r.requiresRotation,
    warnings: r.warnings || [],
    approvedAt: r.approvedAt ? r.approvedAt.toISOString() : null,
    rescanStatus: r.rescanStatus,
    rescanSummary: r.rescanSummary ?? null,
    branchName: r.branchName,
    pullRequestUrl: r.pullRequestUrl,
    pullRequest: last ?? null,
    createdAt: r.createdAt.toISOString(),
    updatedAt: r.updatedAt.toISOString(),
  };
}
