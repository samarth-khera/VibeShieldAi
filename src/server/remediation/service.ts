import { randomUUID } from "node:crypto";
import type { JobStore } from "../job-store";
import type { LlmProvider } from "../ai/client";
import type { FetchLike } from "../github";
import { classifyRemediationEligibility } from "./eligibility";
import { generateRemediationPatch } from "./patch";
import { applyAndRescanInSandbox } from "./sandbox";
import { createRemediationPullRequest } from "./github-pr";
import type { RemediationRecord } from "./types";

export type RemediationDeps = {
  store: JobStore;
  llmProvider?: LlmProvider;
  fetchImpl?: FetchLike;
  scanEngine?: (dir: string) => Promise<import("../scanners/types").ScanEngineResult>;
};

export class RemediationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number = 400,
  ) {
    super(message);
  }
}

/**
 * Creates an exact, reviewable remediation preview without modifying any repository files.
 */
export async function createPreview(
  scanJobId: string,
  findingId: string,
  deps: RemediationDeps,
): Promise<RemediationRecord> {
  const job = await deps.store.get(scanJobId);
  if (!job) {
    throw new RemediationError("scan_not_found", "Scan job not found.", 404);
  }

  const finding = await deps.store.getFinding(scanJobId, findingId);
  if (!finding) {
    throw new RemediationError("finding_not_found", "Finding not found on this scan report.", 404);
  }

  const eligibility = classifyRemediationEligibility(finding);
  const commitSha = job.commitSha || "main";

  let unifiedDiff = "";
  let patchSummary = "";
  let affectedFiles: string[] = [];

  if (eligibility.canAutoFix) {
    const patchResult = await generateRemediationPatch({
      finding,
      scanJobId,
      commitSha,
      llmProvider: deps.llmProvider,
    });
    unifiedDiff = patchResult.unifiedDiff;
    patchSummary = patchResult.patchSummary;
    affectedFiles = patchResult.affectedFiles;
  } else {
    patchSummary = `Manual review required for ${finding.ruleId}`;
    affectedFiles = [finding.filePath];
  }

  const record = await deps.store.createRemediation({
    id: randomUUID(),
    scanJobId,
    status: "preview",
    findingFingerprints: [finding.fingerprint],
    commitSha,
    patchSummary,
    unifiedDiff,
    affectedFiles,
    eligibility: eligibility.eligibility,
    eligibilityReason: eligibility.reason,
    requiresRotation: eligibility.requiresRotation,
    warnings: eligibility.warnings,
    approvedAt: null,
    rescanStatus: null,
    rescanSummary: null,
    branchName: null,
    pullRequestUrl: null,
  });

  return record;
}

/**
 * Requires explicit user approval before any changes may be applied.
 */
export async function approveRemediation(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  approvedBy?: string,
): Promise<RemediationRecord> {
  const job = await deps.store.get(scanJobId);
  if (!job) throw new RemediationError("scan_not_found", "Scan job not found.", 404);

  const remediation = await deps.store.getRemediation(scanJobId, remediationId);
  if (!remediation) throw new RemediationError("remediation_not_found", "Remediation preview not found.", 404);

  if (remediation.status === "rejected") {
    throw new RemediationError("invalid_status", "Rejected remediation cannot be approved.", 400);
  }

  if (remediation.requiresRotation || remediation.eligibility === "unsuitable") {
    throw new RemediationError(
      "unsuitable_for_autofix",
      "This finding requires manual intervention and cannot be auto-approved.",
      400,
    );
  }

  const updated = await deps.store.updateRemediation(scanJobId, remediationId, {
    status: "approved",
    approvedAt: new Date(),
    approvedOperations: { approvedBy: approvedBy || "user", approvedFiles: remediation.affectedFiles },
  });

  return updated;
}

/**
 * Applies approved patch inside an isolated sandbox and runs a real security rescan.
 */
export async function applyAndVerify(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<RemediationRecord> {
  const job = await deps.store.get(scanJobId);
  if (!job) throw new RemediationError("scan_not_found", "Scan job not found.", 404);

  const remediation = await deps.store.getRemediation(scanJobId, remediationId);
  if (!remediation) throw new RemediationError("remediation_not_found", "Remediation preview not found.", 404);

  if (!remediation.approvedAt || (remediation.status !== "approved" && remediation.status !== "applied")) {
    throw new RemediationError(
      "approval_required",
      "Explicit user approval is required before applying this patch.",
      403,
    );
  }

  const { findings } = await deps.store.getFindings(scanJobId, { limit: 200 });

  // Run isolated sandbox application and security rescan
  const rescanResult = await applyAndRescanInSandbox({
    originalFindings: findings as never[],
    targetedFingerprints: remediation.findingFingerprints,
    unifiedDiff: remediation.unifiedDiff,
    scanEngine: deps.scanEngine,
  });

  const nextStatus = rescanResult.rescanStatus === "verified" ? "verified" : "needs_review";

  const updated = await deps.store.updateRemediation(scanJobId, remediationId, {
    status: nextStatus,
    rescanStatus: rescanResult.rescanStatus,
    rescanSummary: rescanResult.summary,
  });

  return updated;
}

/**
 * Requests Pull Request creation on a separate branch after verification.
 */
export async function requestPullRequest(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  token?: string,
): Promise<{ remediation: RemediationRecord; message: string; hasWriteAccess: boolean }> {
  const job = await deps.store.get(scanJobId);
  if (!job) throw new RemediationError("scan_not_found", "Scan job not found.", 404);

  const remediation = await deps.store.getRemediation(scanJobId, remediationId);
  if (!remediation) throw new RemediationError("remediation_not_found", "Remediation not found.", 404);

  if (!remediation.approvedAt) {
    throw new RemediationError("approval_required", "Remediation must be approved before opening a PR.", 403);
  }

  const prResult = await createRemediationPullRequest({
    owner: job.owner,
    repo: job.repo,
    defaultBranch: job.defaultBranch || "main",
    commitSha: remediation.commitSha,
    scanJobId,
    remediationId,
    patchSummary: remediation.patchSummary,
    unifiedDiff: remediation.unifiedDiff,
    token,
    fetchImpl: deps.fetchImpl,
  });

  const updated = await deps.store.updateRemediation(scanJobId, remediationId, {
    branchName: prResult.branchName,
    pullRequestUrl: prResult.pullRequestUrl,
  });

  return {
    remediation: updated,
    message: prResult.message,
    hasWriteAccess: prResult.hasWriteAccess,
  };
}
