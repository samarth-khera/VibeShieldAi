import { fail } from "../api";
import { getConfig, type ServerConfig } from "../config";
import { checkOwner, grantCookieForNewJob, isSameOriginMutation, ownerKeyFrom, type OwnershipConfig } from "./ownership";

export function ownershipConfig(config: ServerConfig = getConfig()): OwnershipConfig {
  return {
    key: ownerKeyFrom({ OWNER_SESSION_SECRET: process.env.OWNER_SESSION_SECRET, SCAN_CALLBACK_SECRET: config.scanCallbackSecret }),
    appOrigin: new URL(config.appUrl).origin,
    ttlSeconds: config.jobTtlHours * 3600,
  };
}

export type OwnerGate = { ok: true; subject: string } | { ok: false; response: Response };

export const NOT_OWNER_MESSAGE =
  "Only the browser session that started this scan can generate, approve, apply or publish fixes. A report link alone is read-only.";

/**
 * Every state-changing scan/remediation action: same-origin request (CSRF) from the browser
 * session that created the job. A job ID, report URL or client-supplied identity is never enough.
 */
export function requireJobOwner(req: Request, jobId: string, cfg: OwnershipConfig = ownershipConfig()): OwnerGate {
  if (!isSameOriginMutation(req, cfg.appOrigin)) {
    return { ok: false, response: fail(403, "forbidden_origin", "Cross-site request refused.") };
  }
  const check = checkOwner(req, jobId, cfg);
  if (check.owner) return { ok: true, subject: check.subject };
  if (check.reason === "unavailable") {
    return { ok: false, response: fail(503, "ownership_unavailable", "Scan ownership is not configured on this deployment.") };
  }
  return { ok: false, response: fail(403, "not_job_owner", NOT_OWNER_MESSAGE) };
}

/**
 * POST /api/scans: the response that creates a job is the only place a grant for it is issued.
 * The job ID is read from the server's own response, never from the request.
 */
export async function attachOwnerGrant(req: Request, res: Response, cfg: OwnershipConfig = ownershipConfig()): Promise<Response> {
  if (res.status !== 202) return res;
  const id = ((await res.clone().json().catch(() => null)) as { data?: { id?: unknown } } | null)?.data?.id;
  if (typeof id !== "string") return res;
  const cookie = grantCookieForNewJob(req, id, cfg);
  if (!cookie) return res;
  const headers = new Headers(res.headers);
  headers.append("Set-Cookie", cookie);
  return new Response(res.body, { status: res.status, headers });
}

/** GET /api/scans/:id: tells the UI whether this browser may change the job (display only; every change is re-checked). */
export async function attachViewer(req: Request, jobId: string, res: Response, cfg: OwnershipConfig = ownershipConfig()): Promise<Response> {
  if (res.status !== 200) return res;
  const body = (await res.json()) as { data: Record<string, unknown> };
  body.data.viewer = { isOwner: checkOwner(req, jobId, cfg).owner };
  return Response.json(body, { status: 200, headers: res.headers });
}
