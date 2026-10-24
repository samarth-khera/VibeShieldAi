import type { JobRecord } from "./job-store";
import { RETRYABLE_STATUSES } from "./job-store";

export type ApiErrorBody = { error: { code: string; message: string } };

const baseHeaders = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

export function ok<T>(data: T, status = 200): Response {
  return Response.json({ data }, { status, headers: baseHeaders });
}

export function fail(status: number, code: string, message: string, extra?: Record<string, string>): Response {
  return Response.json({ error: { code, message } } satisfies ApiErrorBody, { status, headers: { ...baseHeaders, ...extra } });
}

/** Whitelisted public projection. Never includes internal fields, error text beyond the sanitized message, or env. */
export function toPublicJob(job: JobRecord, workerOnline?: boolean) {
  return {
    id: job.id,
    status: job.status,
    repository: {
      owner: job.owner,
      name: job.repo,
      url: job.repositoryUrl,
      defaultBranch: job.defaultBranch,
      commitSha: job.commitSha,
      description: job.description,
      sizeKb: job.repoSizeKb,
      stars: job.stars,
      language: job.primaryLanguage,
    },
    retrieval:
      job.status === "ready_for_scan"
        ? { fileCount: job.fileCount, unpackedBytes: job.unpackedBytes, archiveBytes: job.archiveBytes }
        : null,
    failure: job.errorMessage ? { category: job.failureCategory, message: job.errorMessage } : null,
    retryable: RETRYABLE_STATUSES.has(job.status),
    /** Explicit: retrieval is not a security scan. Phase 3 adds scanning. */
    scanPerformed: false,
    workerOnline: job.status === "queued" ? (workerOnline ?? null) : null,
    createdAt: job.createdAt.toISOString(),
    updatedAt: job.updatedAt.toISOString(),
    completedAt: job.completedAt?.toISOString() ?? null,
    expiresAt: job.expiresAt.toISOString(),
  };
}
