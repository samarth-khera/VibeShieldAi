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
      await fetchRepoMetadata(fetch, owner, repo, config, controller.signal);
      clearTimeout(timer);
      return { ok: true };
    } catch (err: unknown) {
      if (err instanceof RetrievalError) {
        return { ok: false, code: err.category, error: err.publicMessage };
      }
      return { ok: false, code: "invalid_repository", error: "Repository is not accessible." };
    }
  };

  return {
    store: prismaJobStore,
    config,
    enqueue: enqueueFn,
    rateLimit: rateLimitFn,
    workerOnline: workerOnlineFn,
    verifyRepo: verifyRepoFn,
    checkAiQuota: (clientIpHash: string) => checkAiQuotaAndCircuitBreaker(clientIpHash),
  };
}

/**
 * Production wiring for Auto-Fix. Verification never runs against injected files: with the GitHub
 * Actions backend it is dispatched to the scanner worker (which rebuilds the scanned commit and has
 * the scanner binaries); otherwise it rebuilds the snapshot and scans in this process.
 */
export function getRemediationDeps(config: ServerConfig = getConfig()): RemediationDeps {
  const deps: RemediationDeps = {
    store: prismaJobStore,
    llmProvider: getLlmProvider(),
    fetchImpl: fetch,
    config,
  };
  if (config.scanDispatchBackend === "github-actions") {
    deps.dispatchVerification = async (job, remediation) => {
      const res = await dispatchRemediationVerification(job.id, remediation.id, job.repositoryUrl, config);
      if (!res.success) throw new Error(res.error);
    };
  }
  if (config.warmWorkerEnabled) {
    deps.warmWorkerHealthy = () =>
      prismaJobStore.warmWorkerHealthy?.(new Date(), config.warmWorkerHealthyMs) ?? Promise.resolve(false);
  }
  return deps;
}

