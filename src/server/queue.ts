import { Queue } from "bullmq";
import IORedis from "ioredis";

export const QUEUE_NAME = "scan-retrieval";
export type RetrievalPayload = { jobId: string };

function redisUrl(): string {
  return process.env.REDIS_URL || "redis://127.0.0.1:6389";
}

/** Fail-fast connection for the web process: if Redis is down, commands error instead of hanging. */
export function createApiRedis(): IORedis {
  const r = new IORedis(redisUrl(), {
    maxRetriesPerRequest: null,
    connectTimeout: 5000,
  });
  r.on("error", () => undefined); // surfaced via command failures; never log URLs/credentials
  return r;
}

const g = globalThis as unknown as { __redis?: IORedis; __queue?: Queue<RetrievalPayload> };

export function getRedis(): IORedis {
  return (g.__redis ??= createApiRedis());
}

export function getQueue(): Queue<RetrievalPayload> {
  return (g.__queue ??= new Queue<RetrievalPayload>(QUEUE_NAME, { connection: getRedis() }));
}

const withTimeout = <T>(p: Promise<T>, ms = 4000): Promise<T> =>
  Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error("queue_timeout")), ms))]);

/** Enqueues retrieval. `attempt` makes the BullMQ job id unique per retry so a retained failed job can't block it. */
export async function enqueueRetrieval(jobId: string, attempt: number): Promise<void> {
  await withTimeout(
    getQueue().add(
      "retrieve",
      { jobId },
      { jobId: `${jobId}-${attempt}`, attempts: 1, removeOnComplete: { age: 3600 }, removeOnFail: { age: 86400 } },
    ),
  );
}

/** True if at least one worker is currently connected to the queue. */
export async function isWorkerOnline(): Promise<boolean> {
  try {
    const workers = await withTimeout(getQueue().getWorkers(), 2500);
    return workers.length > 0;
  } catch {
    return false;
  }
}
