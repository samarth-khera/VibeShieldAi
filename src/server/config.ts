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
};

function int(name: string, fallback: number): number {
  const raw = process.env[name];
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const MB = 1024 * 1024;

export function getConfig(): ServerConfig {
  return {
    maxArchiveBytes: int("MAX_ARCHIVE_MB", 50) * MB,
    maxUnpackedBytes: int("MAX_UNPACKED_MB", 200) * MB,
    maxFileCount: int("MAX_FILE_COUNT", 10000),
    maxRepoSizeKb: int("MAX_REPO_SIZE_MB", 200) * 1024,
    retrievalTimeoutMs: int("RETRIEVAL_TIMEOUT_MS", 120_000),
    githubApiTimeoutMs: int("GITHUB_API_TIMEOUT_MS", 15_000),
    rateLimitMax: int("RATE_LIMIT_MAX", 10),
    rateLimitWindowSeconds: int("RATE_LIMIT_WINDOW_SECONDS", 3600),
    workerConcurrency: int("WORKER_CONCURRENCY", 2),
    jobTtlHours: int("JOB_TTL_HOURS", 24),
    githubToken: process.env.GITHUB_TOKEN?.trim() || undefined,
  };
}
