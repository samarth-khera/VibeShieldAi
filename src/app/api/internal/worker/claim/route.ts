import { getConfig } from "@/server/config";
import { prismaJobStore } from "@/server/db";
import { handleWorkerClaim } from "@/server/worker-api";

/** Warm-worker only (signed). Returns 404 unless WARM_WORKER_ENABLED=true. */
export async function POST(req: Request) {
  return handleWorkerClaim(req, { store: prismaJobStore, config: getConfig() });
}
