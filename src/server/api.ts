import type { FindingRecord, JobRecord } from "./job-store";
import { RETRYABLE_STATUSES } from "./job-store";

export type ApiErrorBody = { error: { code: string; message: string } };

const baseHeaders = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
};

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
    aiExplanation: f.aiExplanation ?? null,
    createdAt: f.createdAt.toISOString(),
  };
}

/**
 * What a report may claim. Only `complete` (every scanner finished) may be shown as a verified result;
 * zero findings mean "clean" only then. `partial` lists the scanners that did not finish, and
 * `failed`/`cancelled` mean nothing was (fully) scanned, whatever the finding counts say.
 */
export type ReportState = "in_progress" | "complete" | "partial" | "failed" | "cancelled";

const SCANNER_NAMES = { gitleaks: "gitleaks", semgrep: "semgrep", osvScanner: "osv-scanner" } as const;

export function reportStateOf(job: JobRecord): { state: ReportState; incompleteScanners: string[] } {
  const statuses = { gitleaks: job.gitleaksStatus, semgrep: job.semgrepStatus, osvScanner: job.osvStatus };
  const incomplete = (Object.keys(statuses) as (keyof typeof statuses)[])
    .filter((k) => statuses[k] !== "completed")
    .map((k) => SCANNER_NAMES[k]);
  switch (job.status) {
    case "queued":
    case "retrieving":
    case "ready_for_scan":
    case "scanning":
      return { state: "in_progress", incompleteScanners: [] };
    case "completed":
      return { state: incomplete.length === 0 ? "complete" : "partial", incompleteScanners: incomplete };
    case "completed_with_warnings":
      return { state: "partial", incompleteScanners: incomplete };
    case "cancelled":
      return { state: "cancelled", incompleteScanners: incomplete };
    default:
      return { state: "failed", incompleteScanners: incomplete };
  }
}

/** Safe, user-facing reasons for retrieval and limit failures, keyed by RetrievalError category. */
const FAILURE_MESSAGES: Record<string, string> = {
  archive_too_large: "The repository archive is larger than the scan size limit, so no scanner ran.",
  repo_too_large: "The repository is larger than the supported size limit, so no scanner ran.",
  file_count: "The repository has more files than the scan limit allows, so no scanner ran.",
  unpacked_size: "The repository is too large once unpacked, so no scanner ran.",
  unsafe_entry: "The repository archive contains an unsupported entry type, so it was not scanned.",
  unsafe_path: "The repository archive contains an unsafe path, so it was not scanned.",
  timeout: "Retrieving the repository timed out before scanning.",
  network_error: "GitHub could not be reached, so the repository was not scanned.",
  github_rate_limited: "GitHub's rate limit was reached, so the repository was not scanned. Try again later.",
};

// Failures reported before structured categories existed: "<status>:<category>" in the message.
const LEGACY_FAILURE = /^(?:rejected_by_limits|download_failed|invalid_repository|failed):([a-z_]{1,40})$/;

function publicFailure(job: JobRecord): { category: string | null; message: string } | null {
  if (!job.errorMessage) return null;
  const legacy = job.failureCategory === "scan_failed" ? LEGACY_FAILURE.exec(job.errorMessage) : null;
  if (legacy) {
    return { category: legacy[1], message: FAILURE_MESSAGES[legacy[1]] ?? "The scan failed before the scanners completed." };
  }
  return { category: job.failureCategory, message: job.errorMessage };
}

/** Whitelisted public projection. Never includes internal fields, error text beyond the sanitized message, or raw secrets. */
/** Public executor label; lease tokens stored in workflowRunId are never exposed. */
function executorOf(job: JobRecord): "warm-worker" | "github-actions" | null {
  if (!job.startedAt || !job.workflowRunId) return null;
  return job.workflowRunId.startsWith("warm:") ? "warm-worker" : "github-actions";
}

export function toPublicJob(job: JobRecord, workerOnline?: boolean, extra?: { queuePosition?: number | null }) {
  const scanPerformed = ["completed", "completed_with_warnings"].includes(job.status);
  const { state: reportState, incompleteScanners } = reportStateOf(job);
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
    failure: publicFailure(job),
    retryable: RETRYABLE_STATUSES.has(job.status),
    scanPerformed,
    reportState,
    incompleteScanners,
    workerOnline: job.status === "queued" ? (workerOnline ?? null) : null,
    // Waiting for a free worker slot (accepted, not yet claimed by an executor).
    queue:
      job.status === "queued" && !job.startedAt
        ? { waitingForSlot: true, position: extra?.queuePosition ?? null }
        : null,
    executor: executorOf(job),
    createdAt: job.createdAt.toISOString(),
    updatedAt: job.updatedAt.toISOString(),
    startedAt: job.startedAt?.toISOString() ?? null,
    completedAt: job.completedAt?.toISOString() ?? null,
    expiresAt: job.expiresAt.toISOString(),
  };
}
