import { randomBytes } from "node:crypto";
import type { ScanStatus } from "@prisma/client";
import type { NormalizedFinding } from "./scanners/types";

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

  attempts: number;
  createdAt: Date;
  updatedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  expiresAt: Date;
};

export type NewJob = Pick<JobRecord, "owner" | "repo" | "repositoryUrl" | "expiresAt">;
export type JobPatch = Partial<Omit<JobRecord, "id" | "createdAt" | "updatedAt">>;

export type FindingsFilter = {
  severity?: string;
  category?: string;
  query?: string;
  limit?: number;
  offset?: number;
};

/** Persistence port. Implemented by Prisma in production and in-memory in tests. */
export interface JobStore {
  create(data: NewJob): Promise<JobRecord>;
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
