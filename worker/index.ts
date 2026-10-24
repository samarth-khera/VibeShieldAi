/**
 * Retrieval worker. Run with: npm run worker
 * Downloads repository archives from approved GitHub hosts with hard limits and verifies safe
 * extraction. It never executes, installs or builds repository code, and performs no security scanning.
 */
import { readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import IORedis from "ioredis";
import { Worker } from "bullmq";
import { getConfig } from "../src/server/config";
import { prismaJobStore, prisma } from "../src/server/db";
import { log } from "../src/server/errors";
import { QUEUE_NAME, type RetrievalPayload } from "../src/server/queue";
import { runScanPipeline } from "../src/server/scan-pipeline";
import { JOB_ID_RE } from "../src/server/job-store";

const config = getConfig();

// BullMQ workers require maxRetriesPerRequest: null.
const connection = new IORedis(process.env.REDIS_URL || "redis://127.0.0.1:6389", { maxRetriesPerRequest: null });
connection.on("error", () => log("warn", "redis_connection_error"));

const worker = new Worker<RetrievalPayload>(
  QUEUE_NAME,
  async (job) => {
    const { jobId } = job.data;
    if (!JOB_ID_RE.test(jobId)) return "ignored";
    return runScanPipeline(jobId, { store: prismaJobStore, config, fetchImpl: fetch });
  },
  { connection, concurrency: config.workerConcurrency, lockDuration: config.retrievalTimeoutMs + 30_000 },
);
worker.on("failed", (job, err) => log("error", "worker_job_failed", { queueJobId: job?.id, cause: err.name }));
worker.on("error", (err) => log("error", "worker_error", { cause: err.name }));

async function cleanup() {
  try {
    const removed = await prismaJobStore.deleteExpired(new Date());
    if (removed) log("info", "expired_jobs_deleted", { removed });
    // Leftover workspaces from crashed runs (older than 1h).
    for (const name of await readdir(tmpdir())) {
      if (!name.startsWith("vibeshield-")) continue;
      const p = path.join(tmpdir(), name);
      const s = await stat(p).catch(() => null);
      if (s && Date.now() - s.mtimeMs > 3600_000) await rm(p, { recursive: true, force: true });
    }
  } catch {
    log("warn", "cleanup_failed");
  }
}
void cleanup();
const cleanupTimer = setInterval(cleanup, 3600_000);

async function shutdown() {
  clearInterval(cleanupTimer);
  await worker.close();
  await prisma.$disconnect();
  connection.disconnect();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
log("info", "worker_started", { concurrency: config.workerConcurrency });
