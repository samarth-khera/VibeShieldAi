import { getConfig } from "@/server/config";
import { prisma } from "@/server/db";
import { getRedis, isWorkerOnline } from "@/server/queue";
import { getPlatformIsolationInfo } from "@/server/scanners/isolation-spec";

export async function GET() {
  const startTime = Date.now();
  const config = getConfig();
  const isGithubBackend = config.scanDispatchBackend === "github-actions";

  let dbStatus: "healthy" | "unhealthy" = "healthy";
  let dispatchStatus: "ready" | "unconfigured" = "ready";
  let redisStatus: "healthy" | "unhealthy" | undefined;
  let workerStatus: "online" | "offline" | "unknown" | undefined;
  let overallHealthy = true;

  // 1. Database check (PostgreSQL / Neon)
  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch {
    dbStatus = "unhealthy";
    overallHealthy = false;
  }

  // 2. Execution backend readiness check
  if (isGithubBackend) {
    const hasToken = Boolean(config.githubDispatchToken);
    const hasRepo = Boolean(config.githubRepository);
    const hasSecret = Boolean(config.scanCallbackSecret);

    if (hasToken && hasRepo && hasSecret) {
      dispatchStatus = "ready";
    } else {
      dispatchStatus = "unconfigured";
      overallHealthy = false;
    }
  } else {
    try {
      const pong = await getRedis().ping();
      redisStatus = pong === "PONG" ? "healthy" : "unhealthy";
      if (redisStatus !== "healthy") overallHealthy = false;
    } catch {
      redisStatus = "unhealthy";
      overallHealthy = false;
    }

    try {
      const online = await isWorkerOnline();
      workerStatus = online ? "online" : "offline";
    } catch {
      workerStatus = "unknown";
    }
  }

  // 3. Persistent warm worker (optional). GitHub Actions remains the fallback executor either way.
  let warmWorker: { status: "healthy" | "unavailable" | "disabled"; lastSeenSecondsAgo: number | null; fallback: string };
  if (config.warmWorkerEnabled) {
    const latest = await prisma.workerHeartbeat
      .findFirst({ orderBy: { lastSeenAt: "desc" }, select: { lastSeenAt: true } })
      .catch(() => null);
    const age = latest ? Math.round((Date.now() - latest.lastSeenAt.getTime()) / 1000) : null;
    warmWorker = {
      status: age !== null && age * 1000 <= config.warmWorkerHealthyMs ? "healthy" : "unavailable",
      lastSeenSecondsAgo: age,
      fallback: "github-actions",
    };
  } else {
    warmWorker = { status: "disabled", lastSeenSecondsAgo: null, fallback: "github-actions" };
  }

  // 4. Platform isolation specifications
  const isolation = getPlatformIsolationInfo();

  const status = overallHealthy
    ? isGithubBackend || workerStatus === "online"
      ? "healthy"
      : "degraded"
    : "unhealthy";
  const httpStatus = overallHealthy ? 200 : 503;

  return Response.json(
    {
      status,
      mode: isGithubBackend ? "github-actions" : "bullmq",
      timestamp: new Date().toISOString(),
      latencyMs: Date.now() - startTime,
      services: {
        database: dbStatus,
        dispatcher: isGithubBackend ? dispatchStatus : undefined,
        redis: redisStatus,
        worker: workerStatus,
        warmWorker,
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
