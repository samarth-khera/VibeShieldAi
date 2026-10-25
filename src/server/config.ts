export type ServerConfig = {
  maxArchiveBytes: number;
  maxUnpackedBytes: number;
  maxFileCount: number;
  maxRepoSizeKb: number;
  retrievalTimeoutMs: number;
  githubApiTimeoutMs: number;
  rateLimitMax: number;
  rateLimitWindowSeconds: number;
  workerConcurrency: number;
  jobTtlHours: number;
  githubToken?: string;

  // Free-tier Quota and Anti-Abuse Guardrails (Rule 8)
  maxScansPerIpHourly: number;
  maxScansPerIpDaily: number;
  globalDailyScanCap: number;
  maxConcurrentHeavyScans: number;
  jobTimeoutMs: number;

  // Zero-cost Scan Execution Dispatch (Rule 4)
  scanDispatchBackend: "github-actions" | "bullmq";
  githubDispatchToken?: string;
  githubRepository: string;
  githubWorkflowRef: string;
  scanCallbackSecret?: string;
  appUrl: string;
};

function int(name: string, fallback: number): number {
  const raw = process.env[name];
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const MB = 1024 * 1024;

export function getConfig(): ServerConfig {
  const isVercel = Boolean(process.env.VERCEL || process.env.VERCEL_ENV);
  const defaultDispatchBackend =
    process.env.SCAN_DISPATCH_BACKEND === "bullmq"
      ? "bullmq"
      : process.env.SCAN_DISPATCH_BACKEND === "github-actions" || isVercel || !process.env.REDIS_URL
        ? "github-actions"
        : "bullmq";

  const rawUrl =
    process.env.APP_URL?.trim() ||
    process.env.VERCEL_PROJECT_PRODUCTION_URL?.trim() ||
    process.env.VERCEL_URL?.trim() ||
    "http://localhost:3000";

  const appUrl = rawUrl.startsWith("http://") || rawUrl.startsWith("https://") ? rawUrl : `https://${rawUrl}`;

  return {
    maxArchiveBytes: int("MAX_ARCHIVE_MB", 25) * MB,
    maxUnpackedBytes: int("MAX_UNPACKED_MB", 200) * MB,
    maxFileCount: int("MAX_FILE_COUNT", 10000),
    maxRepoSizeKb: int("MAX_REPO_SIZE_MB", 200) * 1024,
    retrievalTimeoutMs: int("RETRIEVAL_TIMEOUT_MS", 120_000),
    githubApiTimeoutMs: int("GITHUB_API_TIMEOUT_MS", 15_000),
    rateLimitMax: int("RATE_LIMIT_MAX", 10),
    rateLimitWindowSeconds: int("RATE_LIMIT_WINDOW_SECONDS", 3600),
    workerConcurrency: int("WORKER_CONCURRENCY", 1),
    jobTtlHours: int("JOB_TTL_HOURS", 24 * 7), // 7-day retention period (Rule 3)
    githubToken: process.env.GITHUB_TOKEN?.trim() || undefined,

    // Free-tier quotas
    maxScansPerIpHourly: int("MAX_SCANS_PER_IP_HOURLY", 3),
    maxScansPerIpDaily: int("MAX_SCANS_PER_IP_DAILY", 5),
    globalDailyScanCap: int("GLOBAL_DAILY_SCAN_CAP", 20),
    maxConcurrentHeavyScans: int("MAX_CONCURRENT_HEAVY_SCANS", 1),
    jobTimeoutMs: int("JOB_TIMEOUT_MS", 900_000), // 15 minutes

    // Dispatch backend
    scanDispatchBackend: defaultDispatchBackend,
    githubDispatchToken:
      process.env.GITHUB_DISPATCH_TOKEN?.trim() || process.env.GITHUB_TOKEN?.trim() || undefined,
    githubRepository: process.env.GITHUB_REPOSITORY?.trim() || "samarth-khera/VibeShieldAi",
    githubWorkflowRef: process.env.GITHUB_WORKFLOW_REF?.trim() || "main",
    scanCallbackSecret: process.env.SCAN_CALLBACK_SECRET?.trim() || undefined,
    appUrl,
  };
}

