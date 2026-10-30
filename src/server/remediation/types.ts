import type { PullRequestState } from "./github-pr";
import { verificationClaimOf } from "./claims";
import { isWarmLease } from "../quota";
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
  /** While status is "applied": whether a worker has claimed the verification yet (never the lease itself). */
  verification: { claimedAt: string | null; runtime: "warm-worker" | "github-actions" | null; progress: VerificationProgress | null } | null;
  /** How the preview was produced and its stored steps (present from the first step on). */
  generation: GenerationState | null;
  /** Who approved: the job owner, or the repository's Safe Auto-Fix policy. */
  approvedBy: "job_owner" | "safe_autofix" | null;
  /** The approval also authorized publishing after a passed verification, as this GitHub user. */
  publishAfterVerification: { login: string } | null;
  createdAt: string;
  updatedAt: string;
};

export function toPublicRemediation(r: RemediationRecord): PublicRemediation {
  const last = (r.approvedOperations as { pullRequest?: PullRequestState } | null)?.pullRequest;
  const claim = r.status === "applied" ? verificationClaimOf(r.approvedOperations) : null;
  const ops = (r.approvedOperations ?? {}) as {
    verificationProgress?: VerificationProgress;
    generation?: GenerationState;
    approvedBy?: string;
    publish?: { login?: string } | null;
  };
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
    verification:
      r.status === "applied"
        ? {
            claimedAt: claim?.at ?? null,
            runtime: claim ? (isWarmLease(claim.lease) ? "warm-worker" : "github-actions") : null,
            progress: ops.verificationProgress ?? null,
          }
        : null,
    generation: ops.generation ?? null,
    approvedBy: r.approvedAt ? (ops.approvedBy === "safe_autofix" ? "safe_autofix" : "job_owner") : null,
    publishAfterVerification: r.approvedAt && ops.publish?.login ? { login: ops.publish.login } : null,
    createdAt: r.createdAt.toISOString(),
    updatedAt: r.updatedAt.toISOString(),
  };
}

/** Remediation text columns and their database limits (characters), from prisma/schema.prisma. */
export const REMEDIATION_TEXT_LIMITS = { patchSummary: 500, eligibilityReason: 500, branchName: 120, pullRequestUrl: 300 } as const;

/** Free text shortened to fit its column instead of failing the write (Prisma P2000). */
export function fitColumn(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/** Which engine produces a fix: only "ai" calls the AI provider (and uses its quota). */
export type RemediationEngine = "npm" | "manifest" | "deterministic" | "ai" | "none";

export type GenerationStage =
  | "checking_repository"
  | "checking_eligibility"
  | "generating_remediation"
  | "validating_dependency_changes"
  | "generating_patch";

/** Stored in approvedOperations.generation while (and after) a preview is generated. */
export type GenerationState = {
  state: "running" | "done" | "failed";
  stage?: GenerationStage;
  engine: RemediationEngine;
  /** Live repository check made when generation started (informational; previews never write). */
  repository?: { canPublish: boolean; reason: string | null; fullName: string; login: string | null } | null;
  stages: { stage: GenerationStage; at: string }[];
  startedAt: string;
  at: string;
};

export type ScannerProgress = "pending" | "running" | "completed" | "failed" | "timed_out" | "skipped";

/** Stored in approvedOperations.verificationProgress from real worker events while verifying. */
export type VerificationProgress = {
  stage: "preparing_snapshot" | "applying_patch" | "scanning";
  scanners: { gitleaks: ScannerProgress; semgrep: ScannerProgress; osvScanner: ScannerProgress };
  at: string;
};
