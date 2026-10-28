import { parseGithubRepoUrl } from "@/lib/github-url";
import type { ServerConfig } from "./config";
import { fail, ok, toPublicFinding, toPublicJob } from "./api";
import { log } from "./errors";
import type { ScanStatus } from "@prisma/client";
import {
  ACTIVE_STATUSES,
  JOB_ID_RE,
  MAX_ATTEMPTS,
  RETRYABLE_STATUSES,
  type JobRecord,
  type JobStore,
} from "./job-store";

const ALL_STATUSES: readonly ScanStatus[] = [
  "queued",
  "retrieving",
  "ready_for_scan",
  "scanning",
  "completed",
  "completed_with_warnings",
  "cancelled",
  "invalid_repository",
  "download_failed",
  "rejected_by_limits",
  "failed",
];
import { clientKey, type RateLimitResult } from "./rate-limit";
import { explainFinding } from "./ai/service";
import { getLlmProvider, type LlmProvider } from "./ai/client";
import { checkAiQuotaAndCircuitBreaker, type AiQuotaCheckResult } from "./ai/circuit-breaker";
import { computeContextHash, AI_PROMPT_VERSION } from "./ai/prompts";
import { AiExplanationSchema, type CachedAiExplanation } from "./ai/types";
import { verifyTurnstileToken } from "./turnstile";

export type ScanDeps = {
  store: JobStore;
  config: ServerConfig;
  enqueue: (jobId: string, attempt: number, repoUrl?: string) => Promise<void>;
  rateLimit: (headers: Headers) => Promise<RateLimitResult>;
  workerOnline: () => Promise<boolean>;
  now?: () => Date;
  llmProvider?: LlmProvider;
  verifyTurnstile?: typeof verifyTurnstileToken;
  verifyRepo?: (owner: string, repo: string) => Promise<{ ok: boolean; code?: string; error?: string }>;
  checkAiQuota?: (clientIpHash: string) => Promise<AiQuotaCheckResult>;
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
    return fail(429, limit.reason || "rate_limited", limit.message || "Too many scan requests. Please wait before trying again.", {
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
  const rawBody = body as { repositoryUrl?: unknown; turnstileToken?: unknown } | null;
  const parsed = parseGithubRepoUrl(rawBody?.repositoryUrl);
  if (!parsed.ok) return fail(400, parsed.code, parsed.error);

  const turnstileToken = typeof rawBody?.turnstileToken === "string" ? rawBody.turnstileToken : undefined;
  const clientIp = req.headers.get("cf-connecting-ip")?.trim() || req.headers.get("x-real-ip")?.trim() || undefined;
  const turnstileFn = deps.verifyTurnstile ?? verifyTurnstileToken;
  const turnstileResult = await turnstileFn({ token: turnstileToken, clientIp });
  if (!turnstileResult.success) {
    if (turnstileResult.status === "service_unavailable") {
      return fail(503, "abuse_protection_unavailable", turnstileResult.message);
    }
    return fail(403, "turnstile_verification_failed", turnstileResult.message);
  }

  // Pre-validate public repository accessibility if verifier provided
  if (deps.verifyRepo) {
    const repoCheck = await deps.verifyRepo(parsed.owner, parsed.repo);
    if (!repoCheck.ok) {
      return fail(400, repoCheck.code || "invalid_repository", repoCheck.error || "Repository is not accessible.");
    }
  }

  const now = (deps.now ?? (() => new Date()))();
  let job;

  if (deps.store.createWithQuota) {
    let quotaRes;
    try {
      quotaRes = await deps.store.createWithQuota(
        {
          owner: parsed.owner,
          repo: parsed.repo,
          repositoryUrl: parsed.url,
          clientIpHash: clientKey(req.headers),
          expiresAt: new Date(now.getTime() + deps.config.jobTtlHours * 3600_000),
        },
        deps.config,
        now,
      );
    } catch (err) {
      console.error("Job store createWithQuota failed:", err);
      log("error", "job_create_failed");
      return fail(503, "service_unavailable", "The service is temporarily unavailable. Please try again shortly.");
    }

    if (!quotaRes.ok) {
      const limit = quotaRes.rateLimit;
      return fail(429, limit.reason || "rate_limited", limit.message || "Too many scan requests. Please wait before trying again.", {
        "Retry-After": String(limit.retryAfterSeconds),
      });
    }
    job = quotaRes.job;
  } else {
    try {
      job = await deps.store.create({
        owner: parsed.owner,
        repo: parsed.repo,
        repositoryUrl: parsed.url,
        clientIpHash: clientKey(req.headers),
        expiresAt: new Date(now.getTime() + deps.config.jobTtlHours * 3600_000),
      });
    } catch (err) {
      console.error("Job store create failed:", err);
      log("error", "job_create_failed");
      return fail(503, "service_unavailable", "The service is temporarily unavailable. Please try again shortly.");
    }
  }

  try {
    await deps.enqueue(job.id, 0, parsed.url);
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
  const now = (deps.now ?? (() => new Date()))();
  if (ACTIVE_STATUSES.includes(job.status) && job.updatedAt.getTime() < now.getTime() - deps.config.jobTimeoutMs) {
    // The worker stopped reporting: fail it explicitly instead of showing "queued" forever.
    await deps.store.reapStale(now, deps.config.jobTimeoutMs).catch(() => undefined);
    const fresh = await deps.store.get(id).catch(() => null);
    if (fresh) return ok(toPublicJob(fresh));
  }
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

/** Reserves a worker slot for an existing job and dispatches it; shared by rescan and retry. */
async function requeueAndDispatch(
  job: JobRecord,
  from: readonly ScanStatus[],
  deps: ScanDeps,
  notAllowed: () => Response,
): Promise<Response> {
  const now = (deps.now ?? (() => new Date()))();
  let reserved;
  if (deps.store.requeueWithQuota) {
    try {
      reserved = await deps.store.requeueWithQuota(job.id, from, MAX_ATTEMPTS, deps.config, now);
    } catch (err) {
      console.error("Job store requeueWithQuota failed:", err);
      return fail(503, "service_unavailable", "The service is temporarily unavailable. Please try again shortly.");
    }
  } else {
    reserved = { ok: await deps.store.transition(job.id, from, { status: "queued", failureCategory: null, errorMessage: null, completedAt: null }) };
  }
  if (!reserved.ok) {
    if ("rateLimit" in reserved && reserved.rateLimit) {
      const limit = reserved.rateLimit;
      return fail(429, limit.reason || "rate_limited", limit.message || "All scan worker slots are busy.", {
        "Retry-After": String(limit.retryAfterSeconds),
      });
    }
    return notAllowed();
  }

  try {
    await deps.enqueue(job.id, job.attempts + 1, job.repositoryUrl);
  } catch {
    await deps.store
      .update(job.id, {
        status: "failed",
        failureCategory: "queue_unavailable",
        errorMessage: "The scan queue is unavailable.",
        completedAt: now,
      })
      .catch(() => undefined);
    return fail(503, "queue_unavailable", "The scan queue is unavailable. Please try again shortly.");
  }
  const fresh = (await deps.store.get(job.id)) ?? job;
  return ok(toPublicJob(fresh), 202);
}

/** POST /api/scans/:id/scan — explicit action to start or retry security scan */
export async function startScan(id: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");

  // A job that is still queued or running already has a worker; dispatching again would duplicate it.
  // ready_for_scan (local BullMQ mode) is waiting for exactly this action.
  const rescannable = ALL_STATUSES.filter((s) => s === "ready_for_scan" || !ACTIVE_STATUSES.includes(s));
  return requeueAndDispatch(job, rescannable, deps, () =>
    fail(409, "already_scanning", "A scan is already queued or in progress for this repository."),
  );
}

/** POST /api/scans/:id/retry */
export async function retryScan(id: string, deps: ScanDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const job = await deps.store.get(id).catch(() => undefined);
  if (job === undefined) return fail(503, "service_unavailable", "The service is temporarily unavailable.");
  if (!job) return fail(404, "not_found", "Scan job not found.");
  return requeueAndDispatch(job, [...RETRYABLE_STATUSES], deps, () =>
    fail(409, "not_retryable", "This job cannot be retried."),
  );
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

/** POST /api/scans/:id/findings/:findingId/explain */
export async function explainScanFinding(
  id: string,
  findingId: string,
  req: Request,
  deps: ScanDeps
): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  if (!findingId || findingId.length > 50 || !/^[A-Za-z0-9_-]+$/.test(findingId)) {
    return fail(400, "invalid_id", "Invalid finding identifier.");
  }

  const job = await deps.store.get(id).catch(() => undefined);
  if (!job) return fail(404, "not_found", "Scan job not found.");

  // Rate limit check for AI requests
  const aiHeaders = new Headers(req.headers);
  aiHeaders.set("x-vibeshield-context", "ai");
  const limit = await deps.rateLimit(aiHeaders).catch(() => ({ allowed: true, retryAfterSeconds: 0 }));
  if (!limit.allowed) {
    return fail(429, "rate_limited", "Too many AI analysis requests. Please wait before trying again.", {
      "Retry-After": String(limit.retryAfterSeconds),
    });
  }

  const finding = await deps.store.getFinding(id, findingId).catch(() => null);
  if (!finding) return fail(404, "not_found", "Finding not found.");

  const provider = deps.llmProvider || getLlmProvider();
  const modelName = provider.getModelName();
  const contextHash = computeContextHash(finding, AI_PROMPT_VERSION, modelName);
  const cacheKey = `${finding.fingerprint}:${contextHash}:${AI_PROMPT_VERSION}:${modelName}`;

  // 1. Return cached explanation immediately if available
  const existingCache = finding.aiExplanation as CachedAiExplanation | undefined;
  if (
    existingCache &&
    existingCache.cacheKey === cacheKey &&
    existingCache.explanation
  ) {
    const parseResult = AiExplanationSchema.safeParse(existingCache.explanation);
    if (parseResult.success) {
      return ok({
        available: true,
        cached: true,
        model: existingCache.model,
        explanation: parseResult.data,
        generatedAt: existingCache.generatedAt,
      });
    }
  }

  if (!provider.isConfigured()) {
    return ok({
      available: false,
      code: "ai_not_configured",
      message: "AI Security Analyst is currently unavailable or disabled on the server.",
    });
  }

  // 2. Database-backed circuit breaker and atomic per-IP/global quota checks
  const ipHash = clientKey(req.headers);
  const quotaCheck: AiQuotaCheckResult = deps.checkAiQuota
    ? await deps.checkAiQuota(ipHash)
    : await checkAiQuotaAndCircuitBreaker(ipHash).catch(() => ({ allowed: true }));
  if (!quotaCheck.allowed) {
    return fail(429, quotaCheck.reason || "rate_limited", quotaCheck.message || "Too many AI analysis requests. Please wait before trying again.", {
      "Retry-After": String(quotaCheck.retryAfterSeconds || 60),
    });
  }

  try {
    const result = await explainFinding(id, findingId, {
      store: deps.store,
      provider,
      clientIpHash: ipHash,
      finding,
    });
    return ok(result);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("Finding not found")) {
      return fail(404, "not_found", "Finding not found.");
    }
    log("warn", "ai_explain_error", { jobId: id, findingId, error: message });
    return fail(500, "ai_error", "An error occurred during AI analysis. Please retry.");
  }
}
