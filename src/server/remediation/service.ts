import { createHash, randomUUID } from "node:crypto";
import type { FindingRecord, JobRecord, JobStore, VerificationReservation } from "../job-store";
import type { LlmProvider } from "../ai/client";
import type { FetchLike } from "../github";
import { getConfig, type ServerConfig } from "../config";
import { log } from "../errors";
import { classifyRemediationEligibility } from "./eligibility";
import { generateRemediationPatch } from "./patch";
import {
  applyAndRescanInSandbox,
  toBaselineFinding,
  type BaselineFinding,
  type SandboxResult,
  type VerificationProgressEvent,
} from "./sandbox";
import { COMMIT_SHA_RE, verifyRemediationOnSnapshot } from "./verify";
import { fetchSourceAtCommit } from "./source-cache";
import { canonicalizeDiff, diffFiles, renderFileDiff } from "./canonical-diff";
import { generateNpmLockfilePatch, isNpmLockfileFinding } from "./npm-lockfile";
import { parseDiffByFile } from "./strict-apply";
import { verificationClaimOf, withVerificationClaim } from "./claims";
import { createRemediationPullRequest, remediationBranchName, type PrStep, type PullRequestState } from "./github-pr";
import {
  fitColumn,
  REMEDIATION_TEXT_LIMITS,
  type GenerationStage,
  type GenerationState,
  type NewRemediation,
  type RemediationEngine,
  type RemediationRecord,
  type RescanComparison,
  type ScannerProgress,
  type VerificationProgress,
} from "./types";
import type { AuthDeps } from "../auth/service";

export type RemediationDeps = {
  store: JobStore;
  /** GitHub App user authorization; PR creation and private-repository access need it. */
  auth?: AuthDeps;
  llmProvider?: LlmProvider;
  fetchImpl?: FetchLike;
  config?: ServerConfig;
  scanEngine?: (dir: string) => Promise<import("../scanners/types").ScanEngineResult>;
  /**
   * Complete in-memory repository snapshot. Only for local fixtures and tests; production
   * always rebuilds the snapshot from the scanned commit.
   */
  sourceFiles?: Record<string, string>;
  /** Public npm registry access for lockfile fixes (tests inject recorded metadata). */
  registryFetch?: FetchLike;
  /**
   * Production: hands the approved remediation to the GitHub Actions verification worker,
   * where the scanner binaries exist. When absent, verification runs in this process.
   */
  dispatchVerification?: (job: JobRecord, remediation: RemediationRecord) => Promise<void>;
  /** True while a persistent warm worker is healthy; it then gets first claim on verifications. */
  warmWorkerHealthy?: () => Promise<boolean>;
  /** Runs a task after the HTTP response (Vercel `after`); absent in tests, where tasks run inline. */
  defer?: (task: () => Promise<void>) => void;
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
 * The exact contents at the scanned commit of every file `diff` touches. Throws if any is
 * unavailable: a patch is only offered after it has been checked against the real files.
 */
async function originalsAtCommit(
  job: JobRecord,
  commitSha: string,
  diff: string,
  deps: RemediationDeps,
  known: Record<string, string | undefined> = {},
): Promise<Map<string, string>> {
  const originals = new Map<string, string>();
  for (const file of diffFiles(diff)) {
    let content = known[file] ?? deps.sourceFiles?.[file];
    if (content === undefined && deps.fetchImpl) {
      content = await fetchSourceAtCommit(
        deps.fetchImpl,
        { owner: job.owner, repo: job.repo, commitSha, filePath: file },
        deps.config ?? getConfig(),
      ).catch(() => undefined);
    }
    if (content === undefined) throw new Error(`The source of ${file} at the scanned commit is unavailable, so the patch cannot be checked.`);
    originals.set(file, content);
  }
  return originals;
}

/** A hunk without any context line can only be anchored at the start or end of a file by `git apply`. */
function hasContextFreeHunk(diff: string): boolean {
  for (const hunks of parseDiffByFile(diff).values()) {
    if (hunks.some((h) => !h.lines.some((l) => l.startsWith(" ")))) return true;
  }
  return false;
}

/**
 * Remediations created before diffs carried context lines are re-rendered against the scanned
 * commit before they may be approved or verified. If that changes the diff (and so its hash), the
 * remediation returns to preview with the new diff and any approval is void: the owner must review
 * and approve the new exact diff.
 */
async function upgradeLegacyDiff(job: JobRecord, remediation: RemediationRecord, deps: RemediationDeps): Promise<void> {
  if (!remediation.unifiedDiff || !hasContextFreeHunk(remediation.unifiedDiff)) return;
  let canonical: string;
  try {
    const originals = await originalsAtCommit(job, remediation.commitSha, remediation.unifiedDiff, deps);
    canonical = canonicalizeDiff(originals, remediation.unifiedDiff);
  } catch {
    throw new RemediationError(
      "patch_does_not_apply",
      "This patch could not be checked against the scanned commit. Generate a new preview.",
      409,
    );
  }
  if (canonical === remediation.unifiedDiff) return;
  const updated = await deps.store.transitionRemediation(job.id, remediation.id, ["preview", "failed", "approved"], {
    status: "preview",
    unifiedDiff: canonical,
    approvedAt: null,
    approvedOperations: null,
    rescanStatus: null,
  });
  if (!updated) throw new RemediationError("invalid_status", "The remediation changed state; reload and try again.", 409);
  throw new RemediationError(
    "patch_regenerated",
    "The patch was regenerated with context lines so it applies with standard git apply. Review the new diff and approve it again.",
    409,
  );
}

/** Live repository check result recorded as the first generation step (previews never write). */
export type RepositoryCheck = { canPublish: boolean; reason: string | null; fullName: string; login: string | null };

/** Which engine will produce the fix; only "ai" calls the AI provider. Mirrors generateRemediationPatch. */
export function remediationEngineFor(
  finding: Pick<FindingRecord, "fingerprint" | "scanner" | "filePath" | "ruleId" | "category" | "packageInfo" | "redactedEvidence">,
  canAutoFix: boolean,
): RemediationEngine {
  if (!canAutoFix) return "none";
  if (isNpmLockfileFinding(finding)) return "npm";
  if (finding.packageInfo != null || finding.scanner === "osv-scanner" || finding.category === "Dependencies") return "manifest";
  const rule = (finding.ruleId || "").toLowerCase();
  if (rule.includes("eval") || /\beval\s*\(/.test(finding.redactedEvidence || "")) return "deterministic";
  return "ai";
}

/**
 * Creates an exact, reviewable remediation preview without modifying any repository files. The
 * record is stored at the first step and each step is recorded as it starts, so the report shows
 * real progress and a reload finds it; the final diff, decision and reason replace it at the end.
 */
export async function createPreview(
  scanJobId: string,
  findingId: string,
  deps: RemediationDeps,
  opts: { checkRepository?: () => Promise<RepositoryCheck | null> } = {},
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

  const id = randomUUID();
  const now = () => new Date().toISOString();
  const generation: GenerationState = {
    state: "running",
    engine: remediationEngineFor(finding, eligibility.canAutoFix),
    stages: [],
    startedAt: now(),
    at: now(),
  };
  await deps.store.createRemediation({
    id,
    scanJobId,
    status: "preview",
    findingFingerprints: [finding.fingerprint],
    commitSha: commitSha ?? "",
    patchSummary: `Generating a fix for ${finding.ruleId}…`.slice(0, 500),
    unifiedDiff: "",
    affectedFiles: [finding.filePath],
    eligibility: eligibility.eligibility,
    eligibilityReason: "Generating…",
    requiresRotation: eligibility.requiresRotation,
    warnings: [],
    approvedAt: null,
    approvedOperations: { generation },
    rescanStatus: null,
    rescanSummary: null,
    branchName: null,
    pullRequestUrl: null,
  } as NewRemediation);
  const stage = async (s: GenerationStage) => {
    generation.stage = s;
    generation.stages.push({ stage: s, at: now() });
    generation.at = now();
    await deps.store.updateRemediation(scanJobId, id, { approvedOperations: { generation } });
  };

  let unifiedDiff = "";
  let patchSummary = "";
  let affectedFiles: string[] = [];
  let findingFingerprints = [finding.fingerprint];

  try {
    if (opts.checkRepository) {
      await stage("checking_repository");
      generation.repository = await opts.checkRepository().catch(() => null);
    }
    await stage("checking_eligibility");
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
        if (isNpmLockfileFinding(finding)) {
          if (sourceContent === undefined) throw new Error(`${finding.filePath} could not be read at the scanned commit. Manual review is required.`);
          const readFile = async (filePath: string) =>
            deps.sourceFiles?.[filePath] ??
            (deps.fetchImpl
              ? await fetchSourceAtCommit(deps.fetchImpl, { owner: job.owner, repo: job.repo, commitSha: commitSha!, filePath }, deps.config ?? getConfig()).catch(
                  () => undefined,
                )
              : undefined);
          const { findings: scanFindings } = await deps.store.getFindings(scanJobId, { limit: 1000 });
          const npm = await generateNpmLockfilePatch({
            finding,
            scanFindings,
            lockText: sourceContent,
            readFile,
            // Never the GitHub fetch: no repository credentials go to the npm registry.
            fetchImpl: deps.registryFetch ?? fetch,
            onStage: stage,
          });
          await stage("generating_patch");
          const raw = npm.files.map((f) => renderFileDiff(f.path, f.before, f.after)).join("");
          unifiedDiff = canonicalizeDiff(new Map(npm.files.map((f) => [f.path, f.before])), raw);
          patchSummary = npm.patchSummary;
          affectedFiles = npm.files.map((f) => f.path);
          findingFingerprints = npm.findingFingerprints;
          eligibility.reason = npm.reason;
          if (npm.safe) {
            eligibility.eligibility = "safe";
            eligibility.warnings = ["Patch-level update inside the declared range; still run the project's tests before merging."];
          }
        } else {
          await stage("generating_remediation");
          const patchResult = await generateRemediationPatch({
            finding,
            scanJobId,
            commitSha: commitSha!,
            llmProvider: deps.llmProvider,
            sourceContent,
          });
          // Re-render against the real files at the scanned commit, with context lines, so the patch
          // applies with plain `git apply`; refuse it if it does not match those files exactly.
          await stage("generating_patch");
          const originals = await originalsAtCommit(job, commitSha!, patchResult.unifiedDiff, deps, { [finding.filePath]: sourceContent });
          unifiedDiff = canonicalizeDiff(originals, patchResult.unifiedDiff);
          patchSummary = patchResult.patchSummary;
          affectedFiles = patchResult.affectedFiles;
        }
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
    generation.state = "done";
  } catch (err) {
    // Storage or infrastructure failure: record it instead of leaving a step "running".
    generation.state = "failed";
    unifiedDiff = "";
    patchSummary = `Fix generation failed for ${finding.ruleId}`;
    eligibility.eligibility = "unsuitable";
    eligibility.reason = `Generating the fix failed (${err instanceof Error ? err.message.slice(0, 200) : "unknown error"}). Nothing was changed; try again.`;
  }
  generation.at = now();

  return deps.store.updateRemediation(scanJobId, id, {
    findingFingerprints,
    patchSummary: fitColumn(patchSummary, REMEDIATION_TEXT_LIMITS.patchSummary),
    unifiedDiff,
    affectedFiles,
    eligibility: eligibility.eligibility,
    eligibilityReason: fitColumn(eligibility.reason, REMEDIATION_TEXT_LIMITS.eligibilityReason),
    requiresRotation: eligibility.requiresRotation,
    warnings: eligibility.warnings,
    approvedOperations: { generation },
  });
}

/**
 * Who approves: the job owner's session subject, their GitHub user when connected, and the
 * canonical GitHub repository ID recorded for the scan (when the GitHub App is configured).
 */
export type ApprovalActor = {
  ownerSubject: string;
  githubUserId?: number | null;
  githubRepoId?: number | null;
  /**
   * The approval also authorizes publishing (branch, commit, pull request) after the patch passes the
   * full security rescan, as this GitHub user. Only set after the repository was confirmed writable.
   */
  publish?: { githubUserId: number; login: string } | null;
  /** "safe_autofix": approved by the repository's Safe Auto-Fix policy instead of a person. */
  approvedBy?: "job_owner" | "safe_autofix";
};

/** An approval is valid for this long; after that the owner must review and approve again. */
export const APPROVAL_TTL_MS = 24 * 3600_000;

/** Stored in Remediation.approvedOperations: what exactly was approved, and by whom. */
export type ApprovalBinding = {
  approvedBy: "job_owner" | "safe_autofix";
  ownerSubject: string;
  githubUserId: number | null;
  /** Canonical (immutable) GitHub repository ID of the scanned repository, when known. */
  githubRepoId: number | null;
  scanJobId: string;
  remediationId: string;
  commitSha: string;
  findingFingerprints: string[];
  approvedFiles: string[];
  diffSha256: string;
  approvedAt: string;
  /** Publish after a passed verification, as this GitHub user (null: the user publishes manually). */
  publish: { githubUserId: number; login: string } | null;
};

export type ApprovalProblem =
  | "approval_missing"
  | "approval_session_mismatch"
  | "approval_target_mismatch"
  | "approval_diff_changed"
  | "approval_expired";

const APPROVAL_MESSAGES: Record<ApprovalProblem, string> = {
  approval_missing: "This patch has no valid approval. Review the diff and approve it again.",
  approval_session_mismatch: "This approval was made in a different session. Review the diff and approve it again.",
  approval_target_mismatch: "The repository, commit or finding changed since approval. Review the diff and approve it again.",
  approval_diff_changed: "The patch changed after it was approved. Review the new diff and approve it again.",
  approval_expired: "The approval expired. Review the diff and approve it again.",
};

/** Re-derives every bound identifier from server state; null when the approval still holds. */
export function approvalProblem(
  job: JobRecord,
  remediation: RemediationRecord,
  actor: { ownerSubject: string },
  now: Date,
  opts: { checkExpiry?: boolean } = {},
): ApprovalProblem | null {
  const b = remediation.approvedOperations as Partial<ApprovalBinding> | null;
  if (!remediation.approvedAt || !b || (b.approvedBy !== "job_owner" && b.approvedBy !== "safe_autofix") || !b.ownerSubject) {
    return "approval_missing";
  }
  if (b.ownerSubject !== actor.ownerSubject) return "approval_session_mismatch";
  const sameFindings =
    Array.isArray(b.findingFingerprints) &&
    b.findingFingerprints.length === remediation.findingFingerprints.length &&
    b.findingFingerprints.every((f, i) => f === remediation.findingFingerprints[i]);
  if (
    b.scanJobId !== job.id ||
    b.remediationId !== remediation.id ||
    b.commitSha !== remediation.commitSha ||
    b.commitSha !== job.commitSha ||
    !sameFindings
  ) {
    return "approval_target_mismatch";
  }
  if (b.diffSha256 !== diffDigest(remediation.unifiedDiff)) return "approval_diff_changed";
  if (opts.checkExpiry !== false && now.getTime() - Date.parse(b.approvedAt ?? "") > APPROVAL_TTL_MS) return "approval_expired";
  return null;
}

/** Returns an approved-but-stale remediation to preview so the owner must approve it again. */
async function invalidateApproval(scanJobId: string, remediationId: string, deps: RemediationDeps): Promise<void> {
  await deps.store.transitionRemediation(scanJobId, remediationId, ["approved"], {
    status: "preview",
    approvedAt: null,
    approvedOperations: null,
  });
}

/**
 * Requires explicit approval by the job owner before any change may be applied. The approval is
 * bound to the owner's session, the job, the remediation, the scanned commit, the targeted
 * findings and the SHA-256 of the exact diff.
 */
export async function approveRemediation(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  actor: ApprovalActor,
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

  if (!job.commitSha || !COMMIT_SHA_RE.test(job.commitSha) || remediation.commitSha !== job.commitSha) {
    throw new RemediationError("commit_unknown", "The patch does not belong to this scan's commit.", 409);
  }
  await upgradeLegacyDiff(job, remediation, deps);

  const now = new Date();
  // Idempotent: a still-valid approval by the same owner is returned unchanged.
  const samePublish =
    ((remediation.approvedOperations as Partial<ApprovalBinding> | null)?.publish?.githubUserId ?? null) === (actor.publish?.githubUserId ?? null);
  if (remediation.status === "approved" && samePublish && !approvalProblem(job, remediation, actor, now)) return remediation;

  if (actor.approvedBy === "safe_autofix" && remediation.eligibility !== "safe") {
    throw new RemediationError("not_safe", "Only fixes classified as safe can be approved by the Safe Auto-Fix policy.", 409);
  }
  const binding: ApprovalBinding = {
    approvedBy: actor.approvedBy ?? "job_owner",
    ownerSubject: actor.ownerSubject,
    githubUserId: actor.githubUserId ?? null,
    githubRepoId: actor.githubRepoId ?? null,
    scanJobId,
    remediationId,
    commitSha: remediation.commitSha,
    findingFingerprints: [...remediation.findingFingerprints],
    approvedFiles: [...remediation.affectedFiles],
    diffSha256: diffDigest(remediation.unifiedDiff),
    approvedAt: now.toISOString(),
    publish: actor.publish ?? null,
  };
  // A failed verification (e.g. worker outage) or a lapsed approval may be re-approved; in-flight
  // or finished ones may not.
  const updated = await deps.store.transitionRemediation(scanJobId, remediationId, ["preview", "failed", "approved"], {
    status: "approved",
    approvedAt: now,
    approvedOperations: binding,
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
  actor: { ownerSubject: string },
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
  // The approval must still describe exactly this job, commit, findings and diff, by this owner.
  const problem = approvalProblem(job, remediation, actor, new Date());
  if (problem) {
    await invalidateApproval(scanJobId, remediationId, deps);
    throw new RemediationError(problem, APPROVAL_MESSAGES[problem], 409);
  }
  await upgradeLegacyDiff(job, remediation, deps);

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
  // Real progress, stored one event at a time (scanner callbacks can arrive together).
  let progressChain: Promise<unknown> = Promise.resolve();
  const onProgress = async (event: VerificationProgressEvent): Promise<void> => {
    progressChain = progressChain.then(() => recordVerificationProgress(scanJobId, remediationId, event, deps)).catch(() => undefined);
    await progressChain;
  };
  const t0 = Date.now();
  let result: SandboxResult;
  if (deps.sourceFiles) {
    result = await applyAndRescanInSandbox({
      originalFindings: baselineFindings,
      targetedFingerprints: remediation.findingFingerprints,
      unifiedDiff: remediation.unifiedDiff,
      sourceFiles: deps.sourceFiles,
      scanEngine: deps.scanEngine,
      onProgress,
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
      onProgress,
    });
  }
  await progressChain;
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

const SCANNER_KEYS = { gitleaks: "gitleaks", semgrep: "semgrep", "osv-scanner": "osvScanner" } as const;

/**
 * Merges one real verification event (from the worker's signed callback or the in-process run) into
 * the stored progress. Only a remediation that is still being verified accepts it.
 */
export async function recordVerificationProgress(
  scanJobId: string,
  remediationId: string,
  event: VerificationProgressEvent,
  deps: Pick<RemediationDeps, "store">,
): Promise<boolean> {
  const r = await deps.store.getRemediation(scanJobId, remediationId);
  if (!r || r.status !== "applied") return false;
  const ops = (r.approvedOperations as Record<string, unknown> | null) ?? {};
  const at = new Date().toISOString();
  const prev = (ops.verificationProgress as VerificationProgress | undefined) ?? {
    stage: "preparing_snapshot" as const,
    scanners: { gitleaks: "pending" as const, semgrep: "pending" as const, osvScanner: "pending" as const },
    at,
  };
  const next: VerificationProgress = { ...prev, scanners: { ...prev.scanners }, at };
  if ("stage" in event) {
    next.stage = event.stage;
    if (event.stage === "scanning") {
      for (const k of Object.keys(next.scanners) as (keyof VerificationProgress["scanners"])[]) {
        if (next.scanners[k] === "pending") next.scanners[k] = "running";
      }
    }
  } else {
    const key = SCANNER_KEYS[event.scanner];
    const allowed: ScannerProgress[] = ["completed", "failed", "timed_out", "skipped"];
    next.scanners[key] = (allowed as string[]).includes(event.status) ? (event.status as ScannerProgress) : "failed";
  }
  return Boolean(
    await deps.store.transitionRemediation(scanJobId, remediationId, ["applied"], { approvedOperations: { ...ops, verificationProgress: next } }),
  );
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

const PR_STEP_MESSAGES: Record<PrStep, string> = {
  checking_repository: "Re-checking repository access and write permission with GitHub.",
  creating_commit: "Creating the commit with exactly the verified change, on top of the scanned commit.",
  pushing_branch: "Creating and pushing the remediation branch.",
  creating_pull_request: "Creating the pull request against the default branch.",
  confirming: "Reading the branch, commit and pull request back from GitHub.",
};

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
  login: string,
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
    `Prepared by VibeShield AI on behalf of @${login}, who approved this exact diff; the branch, commit and pull request were created with @${login}'s own GitHub authorization through the VibeShield AI GitHub App. Review before merging; nothing was merged automatically.`,
  ]
    .filter((l): l is string => l !== null)
    .join("\n");
  return { title: `[VibeShield AI] ${remediation.patchSummary}`.slice(0, 120), body: body.slice(0, 60_000) };
}

/**
 * Opens a pull request carrying exactly the approved and verified patch, on a branch whose only
 * parent is the scanned commit. Idempotent: retries find the same branch and PR.
 */
/** Who is publishing the PR, established by a live GitHub check in the route handler. */
export type PullRequestActor = {
  githubUserId: number;
  login: string;
  /** The actor's own user-to-server token; never another user's and never an operator token. */
  token: string;
  /** Live GitHub repository ID that the handler matched against the scan. */
  repoId: number;
  /** SHA-256 of the diff the user confirmed in the dialog; must equal the approved diff. */
  confirmedDiffSha256: string;
  /** The job owner's session subject; must be the one that approved the patch. */
  ownerSubject: string;
};

export async function requestPullRequest(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  actor: PullRequestActor,
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
  const currentDigest = diffDigest(remediation.unifiedDiff);
  if (approvedDigest && approvedDigest !== currentDigest) {
    throw new RemediationError("patch_mismatch", "The patch differs from the one that was approved.", 409);
  }
  // Same owner session and same job/commit/findings/diff as approved (verification already
  // happened, so the approval's age no longer matters here).
  const problem = approvalProblem(job, remediation, actor, new Date(), { checkExpiry: false });
  if (problem) throw new RemediationError(problem, APPROVAL_MESSAGES[problem], 409);
  // The approval was for this repository and, when a GitHub account was connected, by this account.
  const binding = remediation.approvedOperations as Partial<ApprovalBinding> | null;
  if (binding?.githubRepoId != null && binding.githubRepoId !== actor.repoId) {
    throw new RemediationError("approval_target_mismatch", APPROVAL_MESSAGES.approval_target_mismatch, 409);
  }
  if (binding?.githubUserId != null && binding.githubUserId !== actor.githubUserId) {
    throw new RemediationError(
      "approval_user_mismatch",
      "This patch was approved while a different GitHub account was connected. Review the diff and approve it again.",
      409,
    );
  }
  // The publishing user explicitly confirmed this exact diff, not just "a" fix for the finding.
  if (actor.confirmedDiffSha256 !== currentDigest) {
    throw new RemediationError(
      "diff_confirmation_mismatch",
      "The diff you confirmed is not the approved and verified diff. Reload and review it again.",
      409,
    );
  }

  // Repeated clicks by the same user inside this window reuse the stored outcome instead of
  // spending their GitHub API rate limit. Another user always gets a fresh check with their own token.
  const last = pullRequestStateOf(remediation.approvedOperations);
  if (last && last.openedBy?.githubUserId === actor.githubUserId && Date.now() - Date.parse(last.at) < PR_RECHECK_MS) {
    return { remediation, pullRequest: last };
  }

  const { findings } = await deps.store.getFindings(scanJobId, { limit: 1000 });
  const targeted = findings.filter((f) => remediation.findingFingerprints.includes(f.fingerprint));
  const { title, body } = pullRequestText(job, remediation, targeted, actor.login);

  // Each step is stored as it starts, so the report shows real progress and a reload finds it. A run
  // that stops updating is no longer "in progress" after PR_RECHECK_MS and may be retried safely.
  const openedBy = { githubUserId: actor.githubUserId, login: actor.login };
  const onProgress = async (step: PrStep) => {
    const current = await deps.store.getRemediation(scanJobId, remediationId);
    const inProgress: PullRequestState = {
      status: "in_progress",
      step,
      message: PR_STEP_MESSAGES[step],
      branch: remediationBranchName(scanJobId, remediationId),
      openedBy,
      at: new Date().toISOString(),
    };
    await deps.store.updateRemediation(scanJobId, remediationId, {
      approvedOperations: { ...((current?.approvedOperations as Record<string, unknown> | null) ?? {}), pullRequest: inProgress },
    });
  };

  const pullRequest = await createRemediationPullRequest({
    owner: job.owner,
    repo: job.repo,
    commitSha: remediation.commitSha,
    scanJobId,
    remediationId,
    unifiedDiff: remediation.unifiedDiff,
    title,
    body,
    token: actor.token,
    expectedRepoId: actor.repoId,
    fetchImpl: deps.fetchImpl,
    timeoutMs: config.githubApiTimeoutMs,
    onProgress,
  });
  pullRequest.openedBy = openedBy;
  log(pullRequest.status === "failed" ? "warn" : "info", "remediation_pull_request", {
    jobId: scanJobId,
    remediationId,
    status: pullRequest.status,
    code: pullRequest.code,
    number: pullRequest.number,
  });

  const succeeded = pullRequest.status !== "failed";
  const latest = (await deps.store.getRemediation(scanJobId, remediationId)) ?? remediation;
  const updated = await deps.store.updateRemediation(scanJobId, remediationId, {
    approvedOperations: { ...((latest.approvedOperations as Record<string, unknown> | null) ?? {}), pullRequest },
    ...(succeeded ? { branchName: pullRequest.branch, pullRequestUrl: pullRequest.url ?? null } : {}),
  });
  return { remediation: updated, pullRequest };
}
