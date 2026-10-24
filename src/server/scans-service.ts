import { parseGithubRepoUrl } from "@/lib/github-url";
import type { ServerConfig } from "./config";
import { fail, ok, toPublicFinding, toPublicJob } from "./api";
import { log } from "./errors";
import { JOB_ID_RE, MAX_ATTEMPTS, type JobStore } from "./job-store";
import type { RateLimitResult } from "./rate-limit";

export type ScanDeps = {
  store: JobStore;
  config: ServerConfig;
  enqueue: (jobId: string, attempt: number) => Promise<void>;
  rateLimit: (headers: Headers) => Promise<RateLimitResult>;
  workerOnline: () => Promise<boolean>;
  now?: () => Date;
};

const MAX_BODY_BYTES = 2048;

/** POST /api/scans */
export async function submitScan(req: Request, deps: ScanDeps): Promise<Response> {
  if (!req.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return fail(415, "unsupported_media_type", "Send the request as application/json.");
  }
  const declared = Number.parseInt(req.headers.get("content-length") ?? "0", 10);
  if (declared > MAX_BODY_BYTES) return fail(413, "payload_too_large", "Request body is too large.");

  let limit: RateLimitResult;
  try {
    limit = await deps.rateLimit(req.headers);
  } catch (err) {
    console.error("Rate limit check failed:", err);
    return fail(503, "service_unavailable", "The service is temporarily unavailable. Please try again shortly.");
  }
  if (!limit.allowed) {
    return fail(429, "rate_limited", "Too many scan requests. Please wait before trying again.", {
      "Retry-After": String(limit.retryAfterSeconds),
    });
  }

  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) return fail(413, "payload_too_large", "Request body is too large.");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return fail(400, "invalid_json", "Request body must be valid JSON.");
  }
  const parsed = parseGithubRepoUrl((body as { repositoryUrl?: unknown } | null)?.repositoryUrl);
  if (!parsed.ok) return fail(400, parsed.code, parsed.error);

  const now = (deps.now ?? (() => new Date()))();
  let job;
  try {
    job = await deps.store.create({
      owner: parsed.owner,
      repo: parsed.repo,
      repositoryUrl: parsed.url,
      expiresAt: new Date(now.getTime() + deps.config.jobTtlHours * 3600_000),
    });
  } catch (err) {
    console.error("Job store create failed:", err);
    log("error", "job_create_failed");
    return fail(503, "service_unavailable", "The service is temporarily unavailable. Please try again shortly.");
  }

  try {
    await deps.enqueue(job.id, 0);
  } catch {
    // Nothing was queued: remove the orphan row so no job is left pretending to be pending.
    await deps.store
      .update(job.id, {
        status: "failed",
        failureCategory: "queue_unavailable",
        errorMessage: "The scan queue is unavailable.",
        completedAt: now,
      })
      .catch(() => undefined);
    log("error", "enqueue_failed", { jobId: job.id });
    return fail(503, "queue_unavailable", "The scan queue is unavailable. Please try again shortly.");
  }
  return ok(toPublicJob(job), 202);
}

/** GET /api/scans/:id */
export async function getScan(id: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");
  const online = job.status === "queued" ? await deps.workerOnline() : undefined;
  return ok(toPublicJob(job, online));
}

/** GET /api/scans/:id/repository */
export async function getScanRepository(id: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");
  if (!job.defaultBranch) return fail(409, "metadata_unavailable", "Repository metadata has not been retrieved yet.");
  return ok({ jobId: job.id, status: job.status, repository: toPublicJob(job).repository });
}

/** POST /api/scans/:id/scan — explicit action to start or retry security scan */
export async function startScan(id: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");

  if (job.status === "scanning" || job.status === "retrieving") {
    return fail(409, "already_scanning", "A scan is already in progress for this repository.");
  }

  const now = (deps.now ?? (() => new Date()))();
  await deps.store.update(id, {
    status: "queued",
    failureCategory: null,
    errorMessage: null,
    completedAt: null,
  });

  try {
    await deps.enqueue(id, job.attempts + 1);
  } catch {
    await deps.store
      .update(id, {
        status: "failed",
        failureCategory: "queue_unavailable",
        errorMessage: "The scan queue is unavailable.",
        completedAt: now,
      })
      .catch(() => undefined);
    return fail(503, "queue_unavailable", "The scan queue is unavailable. Please try again shortly.");
  }

  const fresh = (await deps.store.get(id)) ?? job;
  return ok(toPublicJob(fresh), 202);
}

/** POST /api/scans/:id/retry */
export async function retryScan(id: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");
  if (!(await deps.store.requeue(id, MAX_ATTEMPTS))) {
    return fail(409, "not_retryable", "This job cannot be retried.");
  }
  try {
    await deps.enqueue(id, job.attempts + 1);
  } catch {
    await deps.store
      .update(id, {
        status: "failed",
        failureCategory: "queue_unavailable",
        errorMessage: "The scan queue is unavailable.",
        completedAt: (deps.now ?? (() => new Date()))(),
      })
      .catch(() => undefined);
    return fail(503, "queue_unavailable", "The scan queue is unavailable. Please try again shortly.");
  }
  const fresh = (await deps.store.get(id)) ?? job;
  return ok(toPublicJob(fresh), 202);
}

/** GET /api/scans/:id/findings */
export async function listScanFindings(id: string, req: Request, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");

  const url = new URL(req.url);
  const severity = url.searchParams.get("severity") || undefined;
  const category = url.searchParams.get("category") || undefined;
  const query = url.searchParams.get("query") || undefined;
  const rawLimit = Number.parseInt(url.searchParams.get("limit") ?? "100", 10);
  const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 200) : 100;
  const rawOffset = Number.parseInt(url.searchParams.get("offset") ?? "0", 10);
  const offset = Number.isFinite(rawOffset) && rawOffset >= 0 ? rawOffset : 0;

  const result = await deps.store.getFindings(id, { severity, category, query, limit, offset });
  return ok({
    jobId: id,
    status: job.status,
    total: result.total,
    limit,
    offset,
    findings: result.findings.map(toPublicFinding),
  });
}

/** GET /api/scans/:id/findings/:findingId */
export async function getScanFinding(id: string, findingId: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  if (!findingId || findingId.length > 50) return fail(400, "invalid_id", "Invalid finding identifier.");

  const job = await deps.store.get(id).catch(() => undefined);
  if (!job) return fail(404, "not_found", "Scan job not found.");

  const finding = await deps.store.getFinding(id, findingId).catch(() => undefined);
  if (!finding) return fail(404, "not_found", "Finding not found.");

  return ok(toPublicFinding(finding));
}
