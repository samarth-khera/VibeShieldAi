import { after } from "next/server";
import { getConfig, type ServerConfig } from "./config";
import { prisma, prismaJobStore } from "./db";
import { enqueueRetrieval, getRedis, isWorkerOnline } from "./queue";
import { checkDatabaseQuotas, checkRateLimit, clientKey } from "./rate-limit";
import { dispatchRemediationVerification, dispatchScanJob } from "./dispatch";
import { fetchRepoMetadata } from "./github";
import { RetrievalError } from "./errors";
import type { ScanDeps } from "./scans-service";
import { getLlmProvider } from "./ai/client";
import { checkAiQuotaAndCircuitBreaker } from "./ai/circuit-breaker";
import type { RemediationDeps } from "./remediation/service";
import { createPrismaAuthStore } from "./auth/store";
import { repositoryUrlForWorker } from "./auth/private-source";
import { resolveRepositoryForScan } from "./auth/scan-gate";
import type { AuthDeps } from "./auth/service";

/** GitHub App user authorization. `app` is undefined until the operator configures it. */
export function getAuthDeps(config: ServerConfig = getConfig()): AuthDeps {
  return { store: createPrismaAuthStore(prisma), app: config.githubApp, fetchImpl: fetch };
}

/** Production wiring for the route handlers. */
export function getScanDeps(): ScanDeps {
  const config = getConfig();
  const isGithubBackend = config.scanDispatchBackend === "github-actions";

  const rateLimitFn = async (headers: Headers) => {
    // AI analysis requests have their own dedicated circuit breaker and per-IP/global quota checks.
    if (headers.get("x-vibeshield-context") === "ai") {
      return { allowed: true, retryAfterSeconds: 0 };
    }
    const key = clientKey(headers);
    if (isGithubBackend) {
      return checkDatabaseQuotas(prisma, key, config);
    }
    try {
      return await checkRateLimit(getRedis(), key, config.rateLimitMax, config.rateLimitWindowSeconds);
    } catch {
      // Fallback to database quotas if Redis is unavailable
      return checkDatabaseQuotas(prisma, key, config);
    }
  };

  const enqueueFn = async (jobId: string, attempt: number, repoUrl?: string) => {
    if (isGithubBackend) {
      if (!repoUrl) {
        const job = await prismaJobStore.get(jobId);
        repoUrl = job?.repositoryUrl;
      }
      if (!repoUrl) throw new Error("Missing repository URL for workflow dispatch");
      repoUrl = await repositoryUrlForWorker(jobId, repoUrl, getAuthDeps(config));
      const res = await dispatchScanJob(jobId, repoUrl, config);
      if (!res.success) {
        throw new Error(res.error);
      }
    } else {
      await enqueueRetrieval(jobId, attempt);
    }
  };

  const workerOnlineFn = async () => {
    if (isGithubBackend) {
      return Boolean(config.githubDispatchToken);
    }
    try {
      return await isWorkerOnline();
    } catch {
      return false;
    }
  };

  const verifyRepoFn = async (owner: string, repo: string) => {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), config.githubApiTimeoutMs);
      const meta = await fetchRepoMetadata(fetch, owner, repo, config, controller.signal);
      clearTimeout(timer);
      return { ok: true, repoId: meta.id || null };
    } catch (err: unknown) {
      if (err instanceof RetrievalError) {
        return { ok: false, code: err.category, error: err.publicMessage };
      }
      return { ok: false, code: "invalid_repository", error: "Repository is not accessible." };
    }
  };

  const deps: ScanDeps = {
    store: prismaJobStore,
    config,
    enqueue: enqueueFn,
    rateLimit: rateLimitFn,
    workerOnline: workerOnlineFn,
    verifyRepo: verifyRepoFn,
    checkAiQuota: (clientIpHash: string) => checkAiQuotaAndCircuitBreaker(clientIpHash),
  };
  if (config.githubApp) {
    const auth = getAuthDeps(config);
    deps.resolveRepository = (req, owner, repo) => resolveRepositoryForScan(req, owner, repo, auth, verifyRepoFn);
    deps.recordScanAccess = (rec) => auth.store.setScanAccess(rec);
  }
  return deps;
}

/**
 * Production wiring for Auto-Fix. Verification never runs against injected files: with the GitHub
 * Actions backend it is dispatched to the scanner worker (which rebuilds the scanned commit and has
 * the scanner binaries); otherwise it rebuilds the snapshot and scans in this process.
 */
export function getRemediationDeps(config: ServerConfig = getConfig()): RemediationDeps {
  const deps: RemediationDeps = {
    store: prismaJobStore,
    auth: getAuthDeps(config),
    llmProvider: getLlmProvider(),
    fetchImpl: fetch,
    config,
    // Publishing and Safe Auto-Fix run after the response so worker callbacks and page polls stay fast.
    defer: runAfterResponse,
  };
  if (config.scanDispatchBackend === "github-actions") {
    deps.dispatchVerification = async (job, remediation) => {
      const repoUrl = await repositoryUrlForWorker(job.id, job.repositoryUrl, getAuthDeps(config));
      const res = await dispatchRemediationVerification(job.id, remediation.id, repoUrl, config);
      if (!res.success) throw new Error(res.error);
    };
  }
  if (config.warmWorkerEnabled) {
    deps.warmWorkerHealthy = () =>
      prismaJobStore.warmWorkerHealthy?.(new Date(), config.warmWorkerHealthyMs) ?? Promise.resolve(false);
  }
  return deps;
}

/**
 * Runs `task` after the HTTP response (Next's `after`). Outside a request scope (scripts, direct
 * handler calls) `after` throws; the task then runs detached instead, so a deferred side task can
 * never fail the request that scheduled it.
 */
export function runAfterResponse(task: () => Promise<unknown>): void {
  const safe = () => task().then(() => undefined, () => undefined);
  try {
    after(safe);
  } catch {
    void safe();
  }
}

