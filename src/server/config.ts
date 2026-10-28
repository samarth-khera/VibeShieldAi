import { parseEncryptionKey } from "./auth/crypto";
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
  /**
   * GitHub App used for per-user authorization (private scans, Auto-Fix pull requests). Present
   * only when every required value is set; otherwise those features report "not configured".
   */
  githubApp?: GithubAppConfig;

  // Free-tier Quota and Anti-Abuse Guardrails (Rule 8)
  maxScansPerIpHourly: number;
  maxScansPerIpDaily: number;
  globalDailyScanCap: number;
  maxConcurrentHeavyScans: number;
  /** Scans allowed to wait for a free slot; beyond this, submissions are rejected as queue_full. */
  maxQueuedScans: number;
  jobTimeoutMs: number;
  /** A scan still waiting for a slot after this long is failed as queue_timeout. */
  queueTimeoutMs: number;

  // Persistent warm worker (optional; GitHub Actions remains the fallback executor)
  warmWorkerEnabled: boolean;
  warmWorkerSecret?: string;
  /** A warm-worker job whose lease is not renewed within this window is re-queued or failed. */
  warmLeaseMs: number;
  /** A worker is considered healthy if it polled for work within this window. */
  warmWorkerHealthyMs: number;
  /** How long a waiting job is left for a healthy warm worker before falling back to GitHub Actions. */
  warmWorkerGraceMs: number;

  // Zero-cost Scan Execution Dispatch (Rule 4)
  scanDispatchBackend: "github-actions" | "bullmq";
  githubDispatchToken?: string;
  githubRepository: string;
  githubWorkflowRef: string;
  scanCallbackSecret?: string;
  appUrl: string;

  // Gemini AI Free-Tier Guardrails & Circuit Breaker
  geminiApiKey?: string;
  geminiModel?: string;
  aiGeminiEnabled?: boolean;
  aiProvider?: string;
  aiMaxRequestsPerIpHourly?: number;
  aiMaxRequestsPerIpDaily?: number;
  aiGlobalDailyCap?: number;
  aiMaxTokens?: number;
  aiCircuitBreakerCooldownHours?: number;
  adminSecret?: string;
};

export type GithubAppConfig = {
  clientId: string;
  clientSecret: string;
  /** App URL slug, for https://github.com/apps/<slug>/installations/new. */
  slug: string;
  /** 32-byte key for encrypting stored user tokens and PKCE verifiers. */
  encryptionKey: Buffer;
  /** OAuth callback and installation setup URLs registered on the GitHub App. */
  callbackUrl: string;
  setupUrl: string;
  appOrigin: string;
};

function githubAppConfig(appUrl: string): GithubAppConfig | undefined {
  const clientId = process.env.GITHUB_APP_CLIENT_ID?.trim();
  const clientSecret = process.env.GITHUB_APP_CLIENT_SECRET?.trim();
  const slug = process.env.GITHUB_APP_SLUG?.trim();
  const encryptionKey = parseEncryptionKey(process.env.GITHUB_APP_TOKEN_ENCRYPTION_KEY);
  if (!clientId || !clientSecret || !slug || !/^[a-z0-9-]{1,100}$/i.test(slug) || !encryptionKey) return undefined;
  const base = appUrl.replace(/\/+$/, "");
  return {
    clientId,
    clientSecret,
    slug,
    encryptionKey,
    callbackUrl: `${base}/api/auth/github/callback`,
    setupUrl: `${base}/api/auth/github/setup`,
    appOrigin: new URL(base).origin,
  };
}

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
    githubApp: githubAppConfig(appUrl),

    // Free-tier quotas. Raised 2x (from 3/5/20): execution stays capped by MAX_CONCURRENT_HEAVY_SCANS,
    // standard Actions runners are free for this public repo, and ~40 scans/day is a small share of
    // the Vercel Hobby invocation and Neon free compute budgets.
    maxScansPerIpHourly: int("MAX_SCANS_PER_IP_HOURLY", 6),
    maxScansPerIpDaily: int("MAX_SCANS_PER_IP_DAILY", 10),
    globalDailyScanCap: int("GLOBAL_DAILY_SCAN_CAP", 40),
    // Shared by scans and Auto-Fix verifications. Standard runners are free for this public repo
    // (20 concurrent jobs per account); the database reservation enforces this cap atomically.
    maxConcurrentHeavyScans: int("MAX_CONCURRENT_HEAVY_SCANS", 2),
    // Waiting is cheap (one row, no runner); raised from 10 without raising concurrency.
    maxQueuedScans: int("MAX_QUEUED_SCANS", 20),
    jobTimeoutMs: int("JOB_TIMEOUT_MS", 900_000), // 15 minutes
    queueTimeoutMs: int("QUEUE_TIMEOUT_MS", 1_800_000), // 30 minutes

    warmWorkerEnabled: process.env.WARM_WORKER_ENABLED === "true",
    warmWorkerSecret: process.env.WARM_WORKER_SECRET?.trim() || undefined,
    warmLeaseMs: int("WARM_LEASE_MS", 60_000),
    warmWorkerHealthyMs: int("WARM_WORKER_HEALTHY_MS", 30_000),
    warmWorkerGraceMs: int("WARM_WORKER_GRACE_MS", 10_000),

    // Dispatch backend
    scanDispatchBackend: defaultDispatchBackend,
    githubDispatchToken:
      process.env.GITHUB_DISPATCH_TOKEN?.trim() || process.env.GITHUB_TOKEN?.trim() || undefined,
    githubRepository: process.env.GITHUB_REPOSITORY?.trim() || "samarth-khera/VibeShieldAi",
    githubWorkflowRef: process.env.GITHUB_WORKFLOW_REF?.trim() || "main",
    scanCallbackSecret: process.env.SCAN_CALLBACK_SECRET?.trim() || undefined,
    appUrl,

    // Gemini AI Free-Tier Guardrails & Circuit Breaker
    geminiApiKey: process.env.GEMINI_API_KEY?.trim() || undefined,
    geminiModel: process.env.GEMINI_MODEL?.trim() || "gemini-2.5-flash",
    aiGeminiEnabled: process.env.AI_GEMINI_ENABLED !== "false",
    aiProvider: (process.env.AI_PROVIDER?.trim() || "gemini").toLowerCase(),
    // Per-IP AI limits raised (from 5/15); cache hits never count. The global cap stays at 50 because
    // it guards the Gemini free-tier daily quota, which this deployment cannot raise.
    aiMaxRequestsPerIpHourly: int("AI_MAX_REQUESTS_PER_IP_HOURLY", 8),
    aiMaxRequestsPerIpDaily: int("AI_MAX_REQUESTS_PER_IP_DAILY", 25),
    aiGlobalDailyCap: int("AI_GLOBAL_DAILY_CAP", 50),
    aiMaxTokens: int("AI_MAX_OUTPUT_TOKENS", 1500), // same default the explain service applies
    aiCircuitBreakerCooldownHours: int("AI_CIRCUIT_BREAKER_COOLDOWN_HOURS", 24),
    adminSecret: process.env.ADMIN_SECRET?.trim() || process.env.SCAN_CALLBACK_SECRET?.trim() || undefined,
  };
}

