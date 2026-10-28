import { fail, ok } from "../api";
import { JOB_ID_RE, type JobStore } from "../job-store";
import { checkJobAccess } from "./repository-access";
import type { AuthDeps } from "./service";
import { githubStatus } from "./status";

/** GET /api/auth/github/status?jobId=… */
export async function handleGithubStatus(req: Request, deps: AuthDeps, jobs: JobStore): Promise<Response> {
  const jobId = new URL(req.url).searchParams.get("jobId");
  let job = null;
  if (jobId) {
    if (!JOB_ID_RE.test(jobId)) return fail(404, "not_found", "Scan job not found.");
    job = await jobs.get(jobId);
    if (!job) return fail(404, "not_found", "Scan job not found.");
    const gate = await checkJobAccess(req, deps, job);
    if (gate.denied) return gate.denied;
  }
  return ok(await githubStatus(req, deps, job));
}
