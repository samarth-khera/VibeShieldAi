import { randomBytes } from "node:crypto";
import type { ScanStatus } from "@prisma/client";
import type { NormalizedFinding } from "./scanners/types";
import type { ServerConfig } from "./config";
import type { RateLimitResult } from "./rate-limit";
import type { NewRemediation, RemediationRecord, RemediationStatus } from "./remediation/types";

export type FindingRecord = {
  id: string;
  scanJobId: string;
  fingerprint: string;
  scanner: string;
  ruleId: string;
  category: string;
  severity: string;
  originalSeverity: string | null;
  title: string;
  description: string;
  filePath: string;
  startLine: number | null;
  endLine: number | null;
  redactedEvidence: string | null;
  vulnerabilityId: string | null;
  remediation: string | null;
  packageInfo: unknown;
  metadata: unknown;
  aiExplanation?: unknown;
  createdAt: Date;
};

export type JobRecord = {
  id: string;
  status: ScanStatus;
  owner: string;
  repo: string;
  repositoryUrl: string;
  defaultBranch: string | null;
  commitSha: string | null;
  description: string | null;
  repoSizeKb: number | null;
  stars: number | null;
  primaryLanguage: string | null;
  archiveBytes: number | null;
  fileCount: number | null;
  unpackedBytes: number | null;
  failureCategory: string | null;
  errorMessage: string | null;

  gitleaksStatus: string | null;
  gitleaksDurationMs: number | null;
  gitleaksError: string | null;

  semgrepStatus: string | null;
  semgrepDurationMs: number | null;
  semgrepError: string | null;

  osvStatus: string | null;
  osvDurationMs: number | null;
  osvError: string | null;

  scannerVersions: unknown;
  scanCoverage: unknown;

  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  clientIpHash: string | null;
  workflowRunId: string | null;
  workflowRunUrl: string | null;

  attempts: number;
  createdAt: Date;
  updatedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  expiresAt: Date;
};

export type NewJob = Pick<JobRecord, "owner" | "repo" | "repositoryUrl" | "expiresAt"> & {
  clientIpHash?: string | null;
  /** Pre-generated ID, used when access records must exist before the job can be claimed. */
  id?: string;
};
export type JobPatch = Partial<Omit<JobRecord, "id" | "createdAt" | "updatedAt">>;

export type FindingsFilter = {
  severity?: string;
  category?: string;
  query?: string;
  limit?: number;
  offset?: number;
};

export type CreateJobWithQuotaResult =
  | { ok: true; job: JobRecord }
  | { ok: false; rateLimit: RateLimitResult };

export type QuotaConfig = Pick<
  ServerConfig,
  | "maxScansPerIpHourly"
  | "maxScansPerIpDaily"
  | "globalDailyScanCap"
  | "maxConcurrentHeavyScans"
  | "maxQueuedScans"
  | "jobTimeoutMs"
  | "queueTimeoutMs"
  | "warmLeaseMs"
>;

/** Who executes a claimed job. */
export type ScanExecutor = { kind: "github-actions" } | { kind: "warm"; workerId: string };

export type ClaimedScan = { job: JobRecord; lease: string };
export type ClaimedVerification = { job: JobRecord; remediation: RemediationRecord; lease: string };

export type WorkerHeartbeatInput = {
  workerId: string;
  requestMs: number;
  capacity: number;
  activeJobs: number;
  version?: string;
  arch?: string;
  scannerVersions?: Record<string, unknown>;
};

/** Warm-worker jobs are re-queued this many times after a lost lease before failing. */
export const MAX_WARM_ATTEMPTS = 3;

/** Outcome of reserving one of the `maxConcurrentHeavyScans` slots. `rateLimit` is absent when the status did not allow it. */
export type SlotReservation =
  | { ok: true }
  | { ok: false; rateLimit?: RateLimitResult };

export type VerificationReservation =
  | { ok: true; remediation: RemediationRecord }
  | { ok: false; rateLimit?: RateLimitResult };

/** Statuses that hold a heavy-work slot (scan dispatched or running). */
export const ACTIVE_STATUSES: readonly ScanStatus[] = ["queued", "retrieving", "ready_for_scan", "scanning"];

/** Sanitized state written when an active job stops reporting progress for longer than `jobTimeoutMs`. */
export const STALE_JOB_PATCH = {
  status: "failed",
  failureCategory: "worker_timeout",
  errorMessage: "The scan worker stopped reporting progress before finishing. Please retry the scan.",
} as const;

/** Persistence port. Implemented by Prisma in production and in-memory in tests. */
export interface JobStore {
  create(data: NewJob): Promise<JobRecord>;
  createWithQuota?(data: NewJob, config: QuotaConfig, now?: Date): Promise<CreateJobWithQuotaResult>;
  /**
   * Atomically re-queues an existing job (retry or explicit rescan) only if its status is in `from`,
   * it has attempts left, and a heavy-work slot is free under the same lock as `createWithQuota`.
   */
  requeueWithQuota?(
    id: string,
    from: readonly ScanStatus[],
    maxAttempts: number,
    config: QuotaConfig,
    now?: Date,
  ): Promise<SlotReservation>;
  /** Moves a job from one of `from` to `patch.status` (or just applies `patch`). Returns false if it was not in `from`. */
  transition(id: string, from: readonly ScanStatus[], patch: JobPatch): Promise<boolean>;
  /**
   * Releases work that stopped making progress: expired warm-worker leases are re-queued (up to
   * MAX_WARM_ATTEMPTS), other claimed jobs fail after `jobTimeoutMs`, and scans waiting longer than
   * `queueTimeoutMs` fail. Returns the number of rows changed.
   */
  reapStale(now: Date, config: QuotaConfig): Promise<number>;
  /**
   * Atomically claims the oldest waiting scan for `executor` if a slot is free (same advisory lock
   * as every other reservation). `minWaitMs` leaves younger jobs for a healthy warm worker.
   */
  claimNextScan?(executor: ScanExecutor, config: QuotaConfig, now?: Date, opts?: { minWaitMs?: number }): Promise<ClaimedScan | null>;
  /** 1-based position among waiting scans, or null if the job is not waiting. */
  queuePosition?(jobId: string): Promise<number | null>;
  /** Extends the lease on whatever this lease owns (scan or verification). */
  renewLease?(lease: string, now?: Date): Promise<number>;
  /** Records a signed worker poll. Returns false for a replayed or out-of-order request timestamp. */
  recordWorkerHeartbeat?(input: WorkerHeartbeatInput, now?: Date): Promise<boolean>;
  /** True if any warm worker polled within `healthyMs`. */
  warmWorkerHealthy?(now: Date, healthyMs: number): Promise<boolean>;
  get(id: string): Promise<JobRecord | null>;
  /** Atomically moves queued (or a stale `retrieving`) job to `retrieving`. Returns false if not claimable. */
  claim(id: string, staleBefore: Date): Promise<boolean>;
  /** Atomically moves ready_for_scan or completed_with_warnings or stale scanning job to `scanning`. */
  claimForScan(id: string, staleBefore: Date): Promise<boolean>;
  update(id: string, patch: JobPatch): Promise<void>;
  /** Moves a retryable failed job back to `queued`. Returns false if its status is not retryable. */
  requeue(id: string, maxAttempts: number): Promise<boolean>;
  deleteExpired(now: Date): Promise<number>;

  saveFindings(jobId: string, findings: NormalizedFinding[]): Promise<void>;
  getFindings(jobId: string, filter?: FindingsFilter): Promise<{ findings: FindingRecord[]; total: number }>;
  getFinding(jobId: string, findingId: string): Promise<FindingRecord | null>;
  saveFindingAiExplanation(jobId: string, findingId: string, aiExplanation: unknown): Promise<void>;

  createRemediation(data: NewRemediation): Promise<RemediationRecord>;
  getRemediation(scanJobId: string, remediationId: string): Promise<RemediationRecord | null>;
  listRemediations(scanJobId: string): Promise<RemediationRecord[]>;
  updateRemediation(scanJobId: string, remediationId: string, patch: Partial<RemediationRecord>): Promise<RemediationRecord>;
  /** Applies `patch` only if the remediation's status is in `from`; returns null otherwise. */
  transitionRemediation(
    scanJobId: string,
    remediationId: string,
    from: readonly RemediationStatus[],
    patch: Partial<RemediationRecord>,
  ): Promise<RemediationRecord | null>;
  /**
   * Atomically moves an approved remediation to `applied` (verification pending) if a heavy-work
   * slot is free, counting both active scans and in-flight verifications.
   */
  beginRemediationVerification?(
    scanJobId: string,
    remediationId: string,
    config: QuotaConfig,
    now?: Date,
  ): Promise<VerificationReservation>;
  /** Assigns an in-flight (`applied`) verification to an executor lease if it has none yet. */
  assignVerification?(scanJobId: string, remediationId: string, lease: string): Promise<boolean>;
  /** Claims the oldest unassigned in-flight verification for a warm worker. */
  claimNextVerification?(workerId: string, config: QuotaConfig, now?: Date): Promise<ClaimedVerification | null>;
}

/** 192 bits of CSPRNG output → 32 URL-safe chars. Unguessable; acts as the access capability. */
export function newJobId(): string {
  return randomBytes(24).toString("base64url");
}
export const JOB_ID_RE = /^[A-Za-z0-9_-]{32}$/;

export const RETRYABLE_STATUSES: ReadonlySet<ScanStatus> = new Set([
  "download_failed",
  "failed",
  "completed_with_warnings",
]);
export const MAX_ATTEMPTS = 5;
