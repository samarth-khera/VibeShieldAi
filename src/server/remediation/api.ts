import { fail, ok } from "../api";
import { JOB_ID_RE } from "../job-store";
import {
  approveRemediation,
  applyAndVerify,
  createPreview,
  requestPullRequest,
  RemediationError,
  type RemediationDeps,
} from "./service";
import { toPublicRemediation } from "./types";

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
    return ok(toPublicRemediation(result));
  } catch (err) {
    if (err instanceof RemediationError) {
      return fail(err.status, err.code, err.message);
    }
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
