import { createHash, randomUUID } from "node:crypto";
import type { FindingRecord, JobRecord, JobStore, VerificationReservation } from "../job-store";
import type { LlmProvider } from "../ai/client";
import type { FetchLike } from "../github";
import { getConfig, type ServerConfig } from "../config";
import { log } from "../errors";
import { classifyRemediationEligibility } from "./eligibility";
import { generateRemediationPatch } from "./patch";
import { applyAndRescanInSandbox, toBaselineFinding, type BaselineFinding, type SandboxResult } from "./sandbox";
import { COMMIT_SHA_RE, verifyRemediationOnSnapshot } from "./verify";
import { fetchSourceAtCommit } from "./source-cache";
import { verificationClaimOf, withVerificationClaim } from "./claims";
import { createRemediationPullRequest, type PullRequestState } from "./github-pr";
import type { RemediationRecord, RescanComparison } from "./types";

export type RemediationDeps = {
  store: JobStore;
  llmProvider?: LlmProvider;
  fetchImpl?: FetchLike;
  config?: ServerConfig;
  scanEngine?: (dir: string) => Promise<import("../scanners/types").ScanEngineResult>;
  /**
   * Complete in-memory repository snapshot. Only for local fixtures and tests; production
   * always rebuilds the snapshot from the scanned commit.
   */
  sourceFiles?: Record<string, string>;
  /**
   * Production: hands the approved remediation to the GitHub Actions verification worker,
   * where the scanner binaries exist. When absent, verification runs in this process.
   */
  dispatchVerification?: (job: JobRecord, remediation: RemediationRecord) => Promise<void>;
  /** True while a persistent warm worker is healthy; it then gets first claim on verifications. */
  warmWorkerHealthy?: () => Promise<boolean>;
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
  // Patches are only ever generated against the immutable commit the scan ran on, never a branch.
  const commitSha = job.commitSha && COMMIT_SHA_RE.test(job.commitSha) ? job.commitSha : null;
  if (!commitSha && eligibility.canAutoFix) {
    eligibility.canAutoFix = false;
    eligibility.eligibility = "unsuitable";
    eligibility.reason = "The scanned commit is unknown, so an exact patch cannot be generated.";
  }

  let unifiedDiff = "";
  let patchSummary = "";
  let affectedFiles: string[] = [];

  if (eligibility.canAutoFix) {
    let sourceContent = deps.sourceFiles ? deps.sourceFiles[finding.filePath] : undefined;
    if (sourceContent === undefined && deps.fetchImpl && commitSha) {
      sourceContent = await fetchSourceAtCommit(
        deps.fetchImpl,
        { owner: job.owner, repo: job.repo, commitSha, filePath: finding.filePath },
        deps.config ?? getConfig(),
      ).catch(() => undefined); // Fail closed: the patch generator handles missing source.
    }

    try {
      const patchResult = await generateRemediationPatch({
        finding,
        scanJobId,
        commitSha: commitSha!,
        llmProvider: deps.llmProvider,
        sourceContent,
      });
      unifiedDiff = patchResult.unifiedDiff;
      patchSummary = patchResult.patchSummary;
      affectedFiles = patchResult.affectedFiles;
    } catch (err: unknown) {
      const message = err instanceof Error && err.message ? err.message : "Manual review required.";
      patchSummary = `Manual review required for ${finding.ruleId}`;
      affectedFiles = [finding.filePath];
      unifiedDiff = "";
      eligibility.canAutoFix = false;
      eligibility.eligibility = "unsuitable";
      eligibility.reason = message;
      eligibility.warnings.push("No automated fix could be safely generated. Please review and apply changes manually.");
    }
  } else {
    patchSummary = `Manual review required for ${finding.ruleId}`;
    affectedFiles = [finding.filePath];
  }

  const record = await deps.store.createRemediation({
    id: randomUUID(),
    scanJobId,
    status: "preview",
    findingFingerprints: [finding.fingerprint],
    commitSha: commitSha ?? "",
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

  if (remediation.requiresRotation || remediation.eligibility === "unsuitable" || !remediation.unifiedDiff) {
    throw new RemediationError(
      "unsuitable_for_autofix",
      "This finding requires manual intervention and cannot be auto-approved.",
      400,
    );
  }

  if (remediation.status === "approved") return remediation;

  // A failed verification (e.g. worker outage) may be re-approved; in-flight or finished ones may not.
  const updated = await deps.store.transitionRemediation(scanJobId, remediationId, ["preview", "failed"], {
    status: "approved",
    approvedAt: new Date(),
    approvedOperations: {
      approvedBy: approvedBy || "user",
      approvedFiles: remediation.affectedFiles,
      diffSha256: diffDigest(remediation.unifiedDiff),
    },
    rescanStatus: null,
  });
  if (!updated) {
    throw new RemediationError("invalid_status", `A remediation in status "${remediation.status}" cannot be approved.`, 409);
  }
  return updated;
}

/**
 * Verifies an approved patch against the complete repository snapshot of the scanned commit.
 *
 * In production the work is dispatched to the GitHub Actions scanner worker (the only runtime with
 * Gitleaks, Semgrep and OSV-Scanner installed) and the remediation stays `applied` until the worker
 * reports back through the signed verification callback. Locally it runs in this process.
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

  // Idempotent while a verification is already in flight.
  if (remediation.status === "applied" && remediation.approvedAt) return remediation;

  if (!remediation.unifiedDiff || !remediation.approvedAt || remediation.status !== "approved") {
    throw new RemediationError(
      "approval_required",
      "Explicit user approval is required before applying this patch.",
      403,
    );
  }
  if (!COMMIT_SHA_RE.test(remediation.commitSha) || remediation.commitSha !== job.commitSha) {
    throw new RemediationError(
      "commit_unknown",
      "This patch is not tied to the scanned commit, so it cannot be verified.",
      409,
    );
  }

  const config = deps.config ?? getConfig();
  const reservation: VerificationReservation = deps.store.beginRemediationVerification
    ? await deps.store.beginRemediationVerification(scanJobId, remediationId, config)
    : await deps.store
        .transitionRemediation(scanJobId, remediationId, ["approved"], { status: "applied", rescanStatus: null, rescanSummary: null })
        .then((r) => (r ? { ok: true as const, remediation: r } : { ok: false as const }));
  if (!reservation.ok) {
    if (reservation.rateLimit) {
      throw new RemediationError("concurrency_limit", reservation.rateLimit.message ?? "All worker slots are busy.", 429);
    }
    throw new RemediationError("invalid_status", "This remediation is no longer awaiting verification.", 409);
  }

  if (deps.dispatchVerification) {
    if (deps.warmWorkerHealthy && (await deps.warmWorkerHealthy().catch(() => false))) {
      // The slot is reserved; the warm worker claims it on its next poll (Actions takes over after the grace period).
      log("info", "remediation_verification_queued_for_warm_worker", { jobId: scanJobId, remediationId });
      return reservation.remediation;
    }
    try {
      await dispatchToActions(job, reservation.remediation, deps);
      log("info", "remediation_verification_dispatched", { jobId: scanJobId, remediationId });
      return reservation.remediation;
    } catch (err) {
      // Release the slot and the executor claim and let the user retry; nothing was verified.
      await deps.store.transitionRemediation(scanJobId, remediationId, ["applied"], {
        status: "approved",
        approvedOperations: withVerificationClaim(reservation.remediation.approvedOperations, null),
      });
      log("error", "remediation_verification_dispatch_failed", {
        jobId: scanJobId,
        remediationId,
        error: err instanceof Error ? err.message.slice(0, 200) : "unknown",
      });
      throw new RemediationError(
        "verification_unavailable",
        "The verification worker could not be started. Please try again shortly.",
        503,
      );
    }
  }

  const baselineFindings = await listBaselineFindings(deps.store, scanJobId);
  const t0 = Date.now();
  let result: SandboxResult;
  if (deps.sourceFiles) {
    result = await applyAndRescanInSandbox({
      originalFindings: baselineFindings,
      targetedFingerprints: remediation.findingFingerprints,
      unifiedDiff: remediation.unifiedDiff,
      sourceFiles: deps.sourceFiles,
      scanEngine: deps.scanEngine,
    });
  } else {
    result = await verifyRemediationOnSnapshot({
      owner: job.owner,
      repo: job.repo,
      commitSha: remediation.commitSha,
      unifiedDiff: remediation.unifiedDiff,
      targetedFingerprints: remediation.findingFingerprints,
      baselineFindings,
      config,
      fetchImpl: deps.fetchImpl,
      scanEngine: deps.scanEngine,
    });
  }
  result.summary.runtime = "local";
  result.summary.timings = { ...result.summary.timings, totalMs: Date.now() - t0 };

  const recorded = await recordVerificationResult(scanJobId, remediationId, result.rescanStatus, result.summary, deps);
  if (!recorded) throw new RemediationError("invalid_status", "This remediation is no longer awaiting verification.", 409);
  return recorded;
}

/**
 * Assigns the verification to a GitHub Actions lease, then dispatches it. Returns false (and does
 * nothing) if another executor already claimed it, so a verification never runs twice.
 */
async function dispatchToActions(job: JobRecord, remediation: RemediationRecord, deps: RemediationDeps): Promise<boolean> {
  const lease = `gha:${randomUUID()}`;
  if (deps.store.assignVerification && !(await deps.store.assignVerification(job.id, remediation.id, lease))) return false;
  await deps.dispatchVerification!(job, remediation);
  return true;
}

/**
 * Falls back to GitHub Actions for in-flight verifications that no warm worker claimed within the
 * grace period (or when no warm worker is healthy). Called while the client polls the remediation list.
 */
export async function pumpVerifications(scanJobId: string, deps: RemediationDeps, now = new Date()): Promise<number> {
  if (!deps.dispatchVerification) return 0;
  const config = deps.config ?? getConfig();
  const pending = (await deps.store.listRemediations(scanJobId)).filter(
    (r) => r.status === "applied" && !verificationClaimOf(r.approvedOperations),
  );
  if (pending.length === 0) return 0;
  const warm = deps.warmWorkerHealthy ? await deps.warmWorkerHealthy().catch(() => false) : false;
  const job = await deps.store.get(scanJobId);
  if (!job) return 0;
  let dispatched = 0;
  for (const r of pending) {
    if (warm && now.getTime() - r.updatedAt.getTime() < config.warmWorkerGraceMs) continue;
    try {
      if (!(await dispatchToActions(job, r, deps))) continue;
      dispatched++;
      log("info", "remediation_verification_fallback_dispatched", { jobId: scanJobId, remediationId: r.id, warmHealthy: warm });
    } catch {
      await deps.store.transitionRemediation(scanJobId, r.id, ["applied"], {
        status: "approved",
        approvedOperations: withVerificationClaim(r.approvedOperations, null),
      });
    }
  }
  return dispatched;
}

/** Every finding of the original scan: the regression baseline for verification. */
export async function listBaselineFindings(store: JobStore, scanJobId: string): Promise<BaselineFinding[]> {
  const { findings } = await store.getFindings(scanJobId, { limit: 1000 });
  return findings.map(toBaselineFinding);
}

/** Stores a verification outcome. Only a remediation that is still `applied` accepts one. */
export async function recordVerificationResult(
  scanJobId: string,
  remediationId: string,
  rescanStatus: "verified" | "needs_review" | "failed",
  summary: RescanComparison,
  deps: Pick<RemediationDeps, "store">,
): Promise<RemediationRecord | null> {
  return deps.store.transitionRemediation(scanJobId, remediationId, ["applied"], {
    status: rescanStatus,
    rescanStatus,
    rescanSummary: summary,
  });
}

const PR_RECHECK_MS = 15_000;

/** SHA-256 of the exact diff the user approved; a PR may only carry that diff. */
export const diffDigest = (diff: string) => createHash("sha256").update(diff, "utf8").digest("hex");

export function pullRequestStateOf(ops: unknown): PullRequestState | null {
  const pr = (ops as { pullRequest?: PullRequestState } | null)?.pullRequest;
  return pr && typeof pr.status === "string" ? pr : null;
}

function pullRequestText(
  job: JobRecord,
  remediation: RemediationRecord,
  findings: FindingRecord[],
): { title: string; body: string } {
  const s = remediation.rescanSummary;
  const scanners = s?.scannerStatuses;
  const findingLines = findings.length
    ? findings.map((f) => {
        const where = f.startLine ? `${f.filePath}:${f.startLine}` : f.filePath;
        const id = f.vulnerabilityId ? ` (${f.vulnerabilityId})` : "";
        return `- **${f.severity.toUpperCase()}** ${f.title}${id} — \`${where}\` — ${f.scanner} rule \`${f.ruleId}\``;
      })
    : [`- ${remediation.findingFingerprints.length} finding(s) targeted`];
  const limitations = [
    remediation.eligibility === "potentially_breaking"
      ? "- This change was classified as **potentially breaking**: run your test suite before merging."
      : null,
    ...(remediation.warnings ?? []).map((w) => `- ${w}`),
    "- Verification re-ran the security scanners only; it does not run this repository's own tests or build.",
  ].filter(Boolean);
  const body = [
    "## VibeShield AI security remediation",
    "",
    "### Finding",
    ...findingLines,
    "",
    "### Change",
    remediation.patchSummary,
    "",
    `Files: ${remediation.affectedFiles.map((f) => `\`${f}\``).join(", ")}`,
    "",
    "### Why",
    remediation.eligibilityReason,
    "",
    "### Verification",
    `- Patch applied to the scanned commit \`${remediation.commitSha}\` (this branch's parent) and the full snapshot was rescanned.`,
    scanners
      ? `- Gitleaks: ${scanners.gitleaks} · Semgrep: ${scanners.semgrep} · OSV-Scanner: ${scanners.osvScanner}`
      : null,
    s ? `- Targeted finding resolved: ${s.targetResolved ? "yes" : "no"} · new findings introduced: ${s.newFindingsCount}` : null,
    s ? `- Findings before → after: ${s.originalFindingsCount} → ${s.postRescanFindingsCount}` : null,
    s?.workflowRunUrl ? `- Verification run: ${s.workflowRunUrl}` : null,
    `- Scan job \`${job.id}\`, remediation \`${remediation.id}\``,
    "",
    "### Limitations",
    ...limitations,
    "",
    "---",
    "Opened by VibeShield AI after explicit human approval. Review before merging; nothing was merged automatically.",
  ]
    .filter((l): l is string => l !== null)
    .join("\n");
  return { title: `[VibeShield AI] ${remediation.patchSummary}`.slice(0, 120), body: body.slice(0, 60_000) };
}

/**
 * Opens a pull request carrying exactly the approved and verified patch, on a branch whose only
 * parent is the scanned commit. Idempotent: retries find the same branch and PR.
 */
export async function requestPullRequest(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<{ remediation: RemediationRecord; pullRequest: PullRequestState }> {
  const config = deps.config ?? getConfig();
  const job = await deps.store.get(scanJobId);
  if (!job) throw new RemediationError("scan_not_found", "Scan job not found.", 404);

  const remediation = await deps.store.getRemediation(scanJobId, remediationId);
  if (!remediation) throw new RemediationError("remediation_not_found", "Remediation not found.", 404);

  if (!remediation.approvedAt) {
    throw new RemediationError("approval_required", "Remediation must be approved before opening a PR.", 403);
  }
  if (remediation.status !== "verified" || remediation.rescanStatus !== "verified") {
    throw new RemediationError(
      "not_verified",
      "Only a patch that passed the security rescan can be opened as a pull request.",
      409,
    );
  }
  // The patch, its verification and the PR all refer to the one scanned commit of this job.
  if (!job.commitSha || !COMMIT_SHA_RE.test(job.commitSha) || remediation.commitSha !== job.commitSha) {
    throw new RemediationError("commit_mismatch", "The remediation does not belong to the scanned commit.", 409);
  }
  const approvedDigest = (remediation.approvedOperations as { diffSha256?: string } | null)?.diffSha256;
  if (approvedDigest && approvedDigest !== diffDigest(remediation.unifiedDiff)) {
    throw new RemediationError("patch_mismatch", "The patch differs from the one that was approved.", 409);
  }

  // Repeated clicks or scripted calls inside this window reuse the stored outcome instead of
  // spending the server credential's GitHub API rate limit.
  const last = pullRequestStateOf(remediation.approvedOperations);
  if (last && Date.now() - Date.parse(last.at) < PR_RECHECK_MS) return { remediation, pullRequest: last };

  const { findings } = await deps.store.getFindings(scanJobId, { limit: 1000 });
  const targeted = findings.filter((f) => remediation.findingFingerprints.includes(f.fingerprint));
  const { title, body } = pullRequestText(job, remediation, targeted);

  const pullRequest = await createRemediationPullRequest({
    owner: job.owner,
    repo: job.repo,
    commitSha: remediation.commitSha,
    scanJobId,
    remediationId,
    unifiedDiff: remediation.unifiedDiff,
    title,
    body,
    token: config.githubWriteToken,
    allowedRepositories: config.pullRequestRepositories,
    fetchImpl: deps.fetchImpl,
    timeoutMs: config.githubApiTimeoutMs,
  });
  log(pullRequest.status === "failed" ? "warn" : "info", "remediation_pull_request", {
    jobId: scanJobId,
    remediationId,
    status: pullRequest.status,
    code: pullRequest.code,
    number: pullRequest.number,
  });

  const succeeded = pullRequest.status !== "failed";
  const updated = await deps.store.updateRemediation(scanJobId, remediationId, {
    approvedOperations: { ...((remediation.approvedOperations as Record<string, unknown> | null) ?? {}), pullRequest },
    ...(succeeded ? { branchName: pullRequest.branch, pullRequestUrl: pullRequest.url ?? null } : {}),
  });
  return { remediation: updated, pullRequest };
}
