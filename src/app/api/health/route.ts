import { prisma } from "@/server/db";
import { getRedis, isWorkerOnline } from "@/server/queue";
import { getPlatformIsolationInfo } from "@/server/scanners/isolation-spec";

export async function GET() {
  const startTime = Date.now();
  let dbStatus = "healthy";
  let redisStatus = "healthy";
  let workerStatus = "offline";
  let overallHealthy = true;

  // 1. Database check
  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch {
    dbStatus = "unhealthy";
    overallHealthy = false;
  }

  // 2. Redis queue check
  try {
    const pong = await getRedis().ping();
    if (pong !== "PONG") {
      redisStatus = "degraded";
      overallHealthy = false;
    }
  } catch {
    redisStatus = "unhealthy";
    overallHealthy = false;
  }

  // 3. Background worker check
  try {
    const online = await isWorkerOnline();
    workerStatus = online ? "online" : "offline";
  } catch {
    workerStatus = "unknown";
  }

  // 4. Isolation specs
  const isolation = getPlatformIsolationInfo();

  const status = overallHealthy ? (workerStatus === "online" ? "healthy" : "degraded") : "unhealthy";
  const httpStatus = overallHealthy ? 200 : 503;

  return Response.json(
    {
      status,
      timestamp: new Date().toISOString(),
      latencyMs: Date.now() - startTime,
      services: {
        database: dbStatus,
        redis: redisStatus,
        worker: workerStatus,
      },
      isolation: {
        mode: isolation.isolationMode,
        isLinuxContainer: isolation.isLinuxContainer,
        controls: isolation.controls,
      },
    },
    {
      status: httpStatus,
      headers: {
        "Cache-Control": "no-store, max-age=0",
        "Content-Type": "application/json",
      },
    },
  );
}
