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
  recordVerificationResult,
  requestPullRequest,
  RemediationError,
  type RemediationDeps,
} from "./service";
import { toPublicRemediation, type RescanComparison } from "./types";

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
  await deps.store.reapStale(new Date(), (deps.config ?? getConfig()).jobTimeoutMs).catch(() => undefined);
  const list = await deps.store.listRemediations(scanJobId);
  return ok(list.map(toPublicRemediation));
}

export async function handleApproveRemediation(
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  try {
    const approved = await approveRemediation(scanJobId, remediationId, deps);
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
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  try {
    const result = await applyAndVerify(scanJobId, remediationId, deps);
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

export async function handleCreatePullRequest(
  req: Request,
  scanJobId: string,
  remediationId: string,
  deps: RemediationDeps,
): Promise<Response> {
  if (!JOB_ID_RE.test(scanJobId)) return fail(404, "not_found", "Scan job not found.");

  const authHeader = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");

  try {
    const result = await requestPullRequest(scanJobId, remediationId, deps, authHeader);
    return ok({
      remediation: toPublicRemediation(result.remediation),
      message: result.message,
      hasWriteAccess: result.hasWriteAccess,
    });
  } catch (err) {
    if (err instanceof RemediationError) {
      return fail(err.status, err.code, err.message);
    }
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

  return ok({
    scanJobId,
    remediationId,
    owner: job.owner,
    repo: job.repo,
    commitSha: remediation.commitSha,
    unifiedDiff: remediation.unifiedDiff,
    targetedFingerprints: remediation.findingFingerprints,
    baselineFindings: await listBaselineFindings(deps.store, scanJobId),
    approvedAt: remediation.approvedAt.toISOString(),
    queuedAt: remediation.updatedAt.toISOString(),
  });
}

const ScannerStatusSchema = z.string().max(30);
const VerificationResultSchema = z.object({
  scanJobId: z.string().max(32),
  remediationId: z.string().max(36),
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
  const auth = verifyCallbackSignature(raw, req.headers.get("x-vibeshield-signature"), secret);
  if (!auth.valid) return fail(401, "unauthorized", "Invalid or missing worker signature.");

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

  const summary = body.summary as RescanComparison;
  summary.runtime = "github-actions";
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
