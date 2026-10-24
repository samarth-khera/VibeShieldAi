import { getConfig } from "./config";
import { prismaJobStore } from "./db";
import { enqueueRetrieval, getRedis, isWorkerOnline } from "./queue";
import { checkRateLimit, clientKey } from "./rate-limit";
import type { ScanDeps } from "./scans-service";

/** Production wiring for the route handlers. */
export function getScanDeps(): ScanDeps {
  const config = getConfig();
  return {
    store: prismaJobStore,
    config,
    enqueue: enqueueRetrieval,
    rateLimit: (headers) => checkRateLimit(getRedis(), clientKey(headers), config.rateLimitMax, config.rateLimitWindowSeconds),
    workerOnline: isWorkerOnline,
  };
}

import { AnthropicProvider } from "./ai/client";
import type { RemediationDeps } from "./remediation/service";

export function getRemediationDeps(): RemediationDeps {
  return {
    store: prismaJobStore,
    llmProvider: new AnthropicProvider(),
    fetchImpl: fetch,
  };
}
