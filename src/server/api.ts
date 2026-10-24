import type { FindingRecord, JobRecord } from "./job-store";
import { RETRYABLE_STATUSES } from "./job-store";

export type ApiErrorBody = { error: { code: string; message: string } };

const baseHeaders = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

export function ok<T>(data: T, status = 200): Response {
  return Response.json({ data }, { status, headers: baseHeaders });
}

export function fail(status: number, code: string, message: string, extra?: Record<string, string>): Response {
  return Response.json({ error: { code, message } } satisfies ApiErrorBody, { status, headers: { ...baseHeaders, ...extra } });
}

export function toPublicFinding(f: FindingRecord) {
  return {
    id: f.id,
    fingerprint: f.fingerprint,
    scanner: f.scanner,
    ruleId: f.ruleId,
    category: f.category,
    severity: f.severity,
    originalSeverity: f.originalSeverity,
    title: f.title,
    description: f.description,
    filePath: f.filePath,
    startLine: f.startLine,
    endLine: f.endLine,
    redactedEvidence: f.redactedEvidence,
    vulnerabilityId: f.vulnerabilityId,
    remediation: f.remediation,
    packageInfo: f.packageInfo,
    metadata: f.metadata,
    createdAt: f.createdAt.toISOString(),
  };
}

/** Whitelisted public projection. Never includes internal fields, error text beyond the sanitized message, or raw secrets. */
export function toPublicJob(job: JobRecord, workerOnline?: boolean) {
  const scanPerformed = ["completed", "completed_with_warnings"].includes(job.status);
  const totalFindings =
    (job.criticalCount ?? 0) +
    (job.highCount ?? 0) +
    (job.mediumCount ?? 0) +
    (job.lowCount ?? 0) +
    (job.infoCount ?? 0);

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
      job.fileCount != null
        ? { fileCount: job.fileCount, unpackedBytes: job.unpackedBytes, archiveBytes: job.archiveBytes }
        : null,
    scanners: {
      gitleaks: {
        status: job.gitleaksStatus ?? (job.status === "scanning" ? "running" : null),
        durationMs: job.gitleaksDurationMs ?? null,
        error: job.gitleaksError ?? null,
      },
      semgrep: {
        status: job.semgrepStatus ?? (job.status === "scanning" ? "running" : null),
        durationMs: job.semgrepDurationMs ?? null,
        error: job.semgrepError ?? null,
      },
      osvScanner: {
        status: job.osvStatus ?? (job.status === "scanning" ? "running" : null),
        durationMs: job.osvDurationMs ?? null,
        error: job.osvError ?? null,
      },
    },
    scannerVersions: job.scannerVersions ?? null,
    scanCoverage: job.scanCoverage ?? null,
    summary: scanPerformed
      ? {
          critical: job.criticalCount ?? 0,
          high: job.highCount ?? 0,
          medium: job.mediumCount ?? 0,
          low: job.lowCount ?? 0,
          info: job.infoCount ?? 0,
          total: totalFindings,
        }
      : null,
    failure: job.errorMessage ? { category: job.failureCategory, message: job.errorMessage } : null,
    retryable: RETRYABLE_STATUSES.has(job.status),
    scanPerformed,
    workerOnline: job.status === "queued" ? (workerOnline ?? null) : null,
    createdAt: job.createdAt.toISOString(),
    updatedAt: job.updatedAt.toISOString(),
    completedAt: job.completedAt?.toISOString() ?? null,
    expiresAt: job.expiresAt.toISOString(),
  };
}
