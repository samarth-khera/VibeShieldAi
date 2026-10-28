import { z } from "zod";
import { fail, ok } from "../api";
import { verificationSpecSigningPayload, verifyCallbackSignature } from "../callback-auth";
import { getConfig } from "../config";
import { log } from "../errors";
import { JOB_ID_RE } from "../job-store";
import {
  approveRemediation,
  applyAndVerify,
  createPreview,
  listBaselineFindings,
  pumpVerifications,
  recordVerificationResult,
  requestPullRequest,
  RemediationError,
  type RemediationDeps,
} from "./service";
import { toPublicRemediation, type RemediationRecord, type RescanComparison } from "./types";
import { isWarmLease } from "../quota";
import { verificationClaimOf } from "./claims";
import { AUTH_FAILURE, authorizeRepository, checkJobAccess } from "../auth/repository-access";
import { isSameOrigin, loadSession, type AuthDeps } from "../auth/service";
import { loadScanAccess } from "../auth/repository-access";
import { resolvePrivateSource } from "../auth/private-source";
import type { JobRecord, JobStore } from "../job-store";

const REMEDIATION_ID_RE = /^[0-9a-f-]{36}$/;
const MAX_RESULT_BYTES = 256 * 1024;

export async function handleCreatePreview(
  req: Request,
  scanJobId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  let body: { findingId?: string } = {};
  try {
    body = (await req.json()) as { findingId?: string };
  } catch {
    return fail(400, "invalid_json", "Request body must be valid JSON.");
  }

  const findingId = body.findingId?.trim();
  if (!findingId) return fail(400, "missing_parameter", "findingId is required.");

  try {
    const preview = await createPreview(scanJobId, findingId, deps);
    return ok(toPublicRemediation(preview), 201);
  } catch (err) {
    console.error("Preview error:", err);
    if (err instanceof RemediationError) {
      return fail(err.status, err.code, err.message);
    }
    return fail(500, "internal_error", "Failed to generate remediation preview.");
  }
}

export async function handleListRemediations(
  scanJobId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  // Release slots held by verifications whose worker never reported back, so the UI sees a final state.
  await deps.store.reapStale(new Date(), deps.config ?? getConfig()).catch(() => undefined);
  await pumpVerifications(scanJobId, deps).catch(() => undefined);
  const list = await deps.store.listRemediations(scanJobId);
  return ok(list.map((r) => toPublicRemediation(r)));
}

/**
 * POST …/approve. `ownerSubject` comes from the verified owner grant (route gate), never from the
 * request body. A connected GitHub user is recorded too, so publishing can be tied to them.
 */
export async function handleApproveRemediation(
  req: Request,
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  ownerSubject: string,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  try {
    const session = deps.auth?.app ? await loadSession(req, deps.auth).catch(() => null) : null;
    const approved = await approveRemediation(scanJobId, remediationId, deps, {
      ownerSubject,
      githubUserId: session?.account?.githubUserId ?? null,
    });
    return ok(toPublicRemediation(approved));
  } catch (err) {
    if (err instanceof RemediationError) {
      return fail(err.status, err.code, err.message);
    }
    return fail(500, "internal_error", "Failed to approve remediation.");
  }
}

export async function handleApplyRemediation(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  ownerSubject: string,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  try {
    const result = await applyAndVerify(scanJobId, remediationId, deps, { ownerSubject });
    // 202: verification is running on the worker; poll the remediation list for the result.
    return ok(toPublicRemediation(result), result.status === "applied" ? 202 : 200);
  } catch (err) {
    if (err instanceof RemediationError) {
      return fail(err.status, err.code, err.message, err.status === 429 ? { "Retry-After": "60" } : undefined);
    }
    log("error", "remediation_apply_failed", { jobId: scanJobId, remediationId });
    return fail(500, "internal_error", "Failed to apply and verify remediation.");
  }
}

const PR_FAILURE_STATUS: Record<string, number> = {
  credential_invalid: 401,
  access_denied: 403,
  repository_not_found: 404,
  rate_limited: 429,
  patch_conflict: 409,
  branch_conflict: 409,
  repository_mismatch: 409,
  commit_not_found: 409,
  unsafe_target: 422,
};

const PrRequestSchema = z.object({ approvedDiffSha256: z.string().regex(/^[0-9a-f]{64}$/) }).strict();

/**
 * Opens a GitHub PR for a verified remediation with the requesting user's own GitHub App
 * authorization, re-checked live against the exact scanned repository on every call. The client
 * supplies only the digest of the diff it showed the user; repository, commit, branch and diff all
 * come from the stored scan.
 */
export async function handleCreatePullRequest(
  req: Request,
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
  ownerSubject: string,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");
  const auth = deps.auth;
  if (!auth?.app) return fail(503, "not_configured", AUTH_FAILURE.not_configured.message);
  if (!isSameOrigin(req, auth.app)) return fail(403, "forbidden_origin", "Cross-site request refused.");

  let confirmed: string;
  try {
    confirmed = PrRequestSchema.parse(await req.json()).approvedDiffSha256;
  } catch {
    return fail(400, "invalid_request", "Confirm the exact diff before opening a pull request.");
  }

  try {
    const job = await deps.store.get(scanJobId);
    if (!job) return fail(404, "not_found", "Scan job not found.");
    const gate = await checkJobAccess(req, auth, job);
    if (gate.denied) return gate.denied;

    const authz = await authorizeRepository(req, auth, job, gate.scanAccess, "write");
    const repository = `${job.owner}/${job.repo}`;
    if (!authz.ok) {
      await auth.store.audit({
        action: "pull_request",
        outcome: "denied",
        githubUserId: authz.account?.githubUserId,
        githubLogin: authz.account?.login,
        scanJobId,
        remediationId,
        repository,
        detail: authz.code,
      });
      const f = AUTH_FAILURE[authz.code];
      return fail(f.status, authz.code, f.message);
    }

    const { remediation, pullRequest } = await requestPullRequest(scanJobId, remediationId, deps, {
      githubUserId: authz.account.githubUserId,
      login: authz.account.login,
      token: authz.token,
      repoId: authz.access.repoId!,
      confirmedDiffSha256: confirmed,
      ownerSubject,
    });
    await auth.store.audit({
      action: "pull_request",
      outcome: pullRequest.status === "failed" ? `failed:${pullRequest.code}` : pullRequest.status,
      githubUserId: authz.account.githubUserId,
      githubLogin: authz.account.login,
      scanJobId,
      remediationId,
      repository,
      detail: pullRequest.number ? `#${pullRequest.number}` : null,
    });
    const body = { remediation: toPublicRemediation(remediation), pullRequest };
    if (pullRequest.status === "failed") {
      const status = PR_FAILURE_STATUS[pullRequest.code ?? ""] ?? 502;
      return Response.json(
        { error: { code: pullRequest.code ?? "github_error", message: pullRequest.message }, data: body },
        { status, headers: { "Cache-Control": "no-store" } },
      );
    }
    return ok(body, pullRequest.status === "created" ? 201 : 200);
  } catch (err) {
    if (err instanceof RemediationError) {
      return fail(err.status, err.code, err.message);
    }
    log("error", "remediation_pull_request_failed", { jobId: scanJobId, remediationId });
    return fail(500, "internal_error", "Failed to create pull request.");
  }
}

export async function handleDownloadPatch(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  const remediation = await deps.store.getRemediation(scanJobId, remediationId);
  if (!remediation) return fail(404, "not_found", "Remediation not found.");

  return new Response(remediation.unifiedDiff, {
    status: 200,
    headers: {
      "Content-Type": "text/x-diff; charset=utf-8",
      "Content-Disposition": `attachment; filename="vibeshield-fix-${remediationId.slice(0, 8)}.patch"`,
      "Cache-Control": "no-store",
    },
  });
}

function workerSecret(deps: RemediationDeps): string | undefined {
  return (deps.config ?? getConfig()).scanCallbackSecret;
}

/**
 * GET /api/scans/:id/remediation/:rid/verification — called only by the verification worker.
 * Returns the approved diff and the immutable commit to verify, authenticated by an HMAC over a
 * canonical string so the endpoint reveals nothing to unsigned callers.
 */
export async function handleVerificationSpec(
  req: Request,
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId) || !REMEDIATION_ID_RE.test(remediationId)) {
    return fail(404, "not_found", "Remediation not found.");
  }
  const secret = workerSecret(deps);
  if (!secret) return fail(500, "callback_misconfigured", "Callback authentication secret is not configured.");
  const auth = verifyCallbackSignature(
    verificationSpecSigningPayload(scanJobId, remediationId),
    req.headers.get("x-vibeshield-signature"),
    secret,
  );
  if (!auth.valid) return fail(401, "unauthorized", "Invalid or missing worker signature.");

  const [job, remediation] = await Promise.all([
    deps.store.get(scanJobId),
    deps.store.getRemediation(scanJobId, remediationId),
  ]);
  if (!job || !remediation) return fail(404, "not_found", "Remediation not found.");
  if (remediation.status !== "applied" || !remediation.approvedAt) {
    return fail(409, "not_awaiting_verification", "This remediation is not awaiting verification.");
  }

  try {
    return ok(await buildVerificationSpec(job, remediation, deps.store, deps.auth));
  } catch (err) {
    if (err instanceof RemediationError) return fail(err.status, err.code, err.message);
    throw err;
  }
}

/** The approved remediation and immutable commit a verification worker needs; never includes secrets. */
export async function buildVerificationSpec(job: JobRecord, remediation: RemediationRecord, store: JobStore, auth?: AuthDeps) {
  // Private repositories: a fresh short-lived archive URL obtained with the authorizing user's
  // token. Workers never receive the token itself, and the spec endpoint is signed.
  let archiveUrl: string | undefined;
  if (auth?.app) {
    const access = await loadScanAccess(auth, job.id);
    if (access?.isPrivate) {
      const src = await resolvePrivateSource(job, access, "verify", auth, getConfig());
      if ("code" in src) throw new RemediationError("source_unavailable", "The private repository source is no longer available.", 409);
      archiveUrl = src.archiveUrl;
    }
  }
  return {
    ...(archiveUrl ? { archiveUrl, private: true } : {}),
    scanJobId: job.id,
    remediationId: remediation.id,
    owner: job.owner,
    repo: job.repo,
    commitSha: remediation.commitSha,
    unifiedDiff: remediation.unifiedDiff,
    targetedFingerprints: remediation.findingFingerprints,
    baselineFindings: await listBaselineFindings(store, job.id),
    approvedAt: remediation.approvedAt?.toISOString() ?? null,
    queuedAt: remediation.updatedAt.toISOString(),
  };
}

const ScannerStatusSchema = z.string().max(30);
const VerificationResultSchema = z.object({
  scanJobId: z.string().max(32),
  remediationId: z.string().max(36),
  lease: z.string().max(100).optional(),
  rescanStatus: z.enum(["verified", "needs_review", "failed"]),
  summary: z.object({
    targetResolved: z.boolean(),
    originalFindingsCount: z.number().int().nonnegative(),
    postRescanFindingsCount: z.number().int().nonnegative(),
    newFindingsCount: z.number().int().nonnegative(),
    resolvedFingerprints: z.array(z.string().max(64)).max(1000),
    remainingFingerprints: z.array(z.string().max(64)).max(1000),
    regressions: z.array(z.string().max(64)).max(1000),
    reason: z.string().max(40).optional(),
    detail: z.string().max(300).optional(),
    scannerStatuses: z
      .object({ gitleaks: ScannerStatusSchema, semgrep: ScannerStatusSchema, osvScanner: ScannerStatusSchema })
      .optional(),
    timings: z.record(z.string(), z.number().int().nonnegative()).optional(),
    snapshot: z.object({ commitSha: z.string().max(40), fileCount: z.number().int().nonnegative() }).optional(),
    workflowRunUrl: z.string().max(300).optional(),
    archiveCache: z.enum(["hit", "miss", "none"]).optional(),
  }),
});

/**
 * POST /api/scans/:id/remediation/:rid/verification — signed result from the verification worker.
 * The server re-checks the invariants for `verified` instead of trusting the label alone.
 */
export async function handleVerificationResult(
  req: Request,
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId) || !REMEDIATION_ID_RE.test(remediationId)) {
    return fail(404, "not_found", "Remediation not found.");
  }
  const secret = workerSecret(deps);
  if (!secret) return fail(500, "callback_misconfigured", "Callback authentication secret is not configured.");

  const raw = await req.text();
  if (raw.length > MAX_RESULT_BYTES) return fail(413, "payload_too_large", "Verification result is too large.");
  const signature = req.headers.get("x-vibeshield-signature");
  const warmSecret = (deps.config ?? getConfig()).warmWorkerSecret;
  let signedBy: "callback" | "warm" = "callback";
  if (!verifyCallbackSignature(raw, signature, secret).valid) {
    if (!warmSecret || !verifyCallbackSignature(raw, signature, warmSecret).valid) {
      return fail(401, "unauthorized", "Invalid or missing worker signature.");
    }
    signedBy = "warm";
  }

  let parsed;
  try {
    parsed = VerificationResultSchema.safeParse(JSON.parse(raw));
  } catch {
    return fail(400, "invalid_json", "Verification result must be valid JSON.");
  }
  if (!parsed.success) return fail(400, "validation_failed", "Verification result does not match schema.");
  const body = parsed.data;
  if (body.scanJobId !== scanJobId || body.remediationId !== remediationId) {
    return fail(400, "id_mismatch", "Payload identifiers do not match the route.");
  }

  const remediation = await deps.store.getRemediation(scanJobId, remediationId);
  if (!remediation) return fail(404, "not_found", "Remediation not found.");

  // The executor holding the verification lease is the only one whose result counts.
  const claim = verificationClaimOf(remediation.approvedOperations);
  const warmOwned = isWarmLease(claim?.lease);
  if (warmOwned ? body.lease !== claim?.lease : signedBy === "warm" || Boolean(body.lease)) {
    return fail(409, "stale_lease", "This worker no longer owns the verification.");
  }

  const summary = body.summary as RescanComparison;
  summary.runtime = warmOwned ? "warm-worker" : "github-actions";
  let status = body.rescanStatus;
  if (status === "verified") {
    const scannersOk =
      summary.scannerStatuses &&
      Object.values(summary.scannerStatuses).every((s) => s === "completed");
    const snapshotOk = summary.snapshot?.commitSha === remediation.commitSha;
    if (!scannersOk || !snapshotOk || !summary.targetResolved || summary.regressions.length > 0) {
      status = "needs_review";
      summary.reason = summary.reason ?? "target_not_resolved";
      summary.detail = "The worker result did not meet every verification requirement.";
    }
  }

  const updated = await recordVerificationResult(scanJobId, remediationId, status, summary, deps);
  log("info", "remediation_verification_recorded", {
    jobId: scanJobId,
    remediationId,
    status: updated ? status : "ignored",
    reason: summary.reason ?? null,
    totalMs: summary.timings?.totalMs ?? null,
  });
  if (!updated) return ok({ accepted: false, message: "Remediation is not awaiting verification." });
  return ok({ accepted: true, status });
}
