import { getConfig } from "../config";
import { prismaJobStore } from "../db";
import { JOB_ID_RE } from "../job-store";
import { getAuthDeps } from "../deps";
import { checkJobAccess } from "./repository-access";

/**
 * Route-level access gate for one scan. Public scans pass through (the unguessable job ID remains
 * the capability). Private scans require the authorizing GitHub user; `live` additionally re-checks
 * that user's current access with GitHub, for operations that read or change repository content.
 */
export async function gateScanAccess(req: Request, jobId: string, opts: { live?: boolean } = {}): Promise<Response | null> {
  const config = getConfig();
  if (!config.githubApp || !JOB_ID_RE.test(jobId)) return null; // no private scans can exist
  const job = await prismaJobStore.get(jobId);
  if (!job) return null; // the handler returns its own 404
  const gate = await checkJobAccess(req, getAuthDeps(config), job, opts);
  return gate.denied;
}

/**
 * Like `gateScanAccess({ live: true })`, and also returns the authorizing user's token for a
 * private scan so server-side source reads (patch preview) use that user's own access.
 */
export async function gateScanAccessWithToken(
  req: Request,
  jobId: string,
): Promise<{ denied: Response } | { denied: null; privateToken?: string }> {
  const config = getConfig();
  if (!config.githubApp || !JOB_ID_RE.test(jobId)) return { denied: null };
  const job = await prismaJobStore.get(jobId);
  if (!job) return { denied: null };
  return checkJobAccess(req, getAuthDeps(config), job, { live: true });
}
