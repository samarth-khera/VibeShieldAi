import type { AuthDeps } from "./auth/service";
import { loadScanAccess } from "./auth/repository-access";
import { resolvePrivateSource } from "./auth/private-source";
import { z } from "zod";
import { Prisma, type ScanStatus } from "@prisma/client";
import { getConfig } from "./config";
import { prisma, withDbRetry } from "./db";
import { verifyCallbackSignature } from "./callback-auth";
import { redactText } from "./scanners/redact";
import { fail, ok } from "./api";
import { ACTIVE_STATUSES, JOB_ID_RE, type JobRecord } from "./job-store";
import { isWarmLease } from "./quota";
import { log } from "./errors";

// Signed callbacks from scan executors (GitHub Actions worker and warm worker). Three kinds:
// progress heartbeats, per-scanner results (published as each scanner finishes), and the final
// aggregate. Every kind is forward-only and idempotent, and a warm-worker callback must carry the
// lease that currently owns the job, so a superseded run can never write results.

const MAX_CALLBACK_BYTES = 5 * 1024 * 1024; // 5 MB max body size

const CallbackFindingSchema = z.object({
  fingerprint: z.string().max(64),
  scanner: z.string().max(30),
  ruleId: z.string().max(120),
  category: z.string().max(50),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  originalSeverity: z.string().max(50).nullable().optional(),
  title: z.string().max(250),
  description: z.string(),
  filePath: z.string().max(500),
  startLine: z.number().int().positive().nullable().optional(),
  endLine: z.number().int().positive().nullable().optional(),
  redactedEvidence: z.string().nullable().optional(),
  vulnerabilityId: z.string().max(100).nullable().optional(),
  remediation: z.string().nullable().optional(),
  packageInfo: z.record(z.string(), z.unknown()).nullable().optional(),
  metadata: z.record(z.string(), z.unknown()).nullable().optional(),
  aiExplanation: z.record(z.string(), z.unknown()).nullable().optional(),
});

const CallbackPayloadSchema = z.object({
  jobId: z.string().max(32),
  status: z.enum(["completed", "completed_with_warnings", "failed"]),
  workflowRunId: z.string().max(100).optional(),
  workflowRunUrl: z.string().max(300).optional(),
  lease: z.string().max(100).optional(),
  commitSha: z.string().max(40).optional(),
  archiveBytes: z.number().int().nonnegative().nullable().optional(),
  fileCount: z.number().int().nonnegative().nullable().optional(),
  unpackedBytes: z.number().int().nonnegative().nullable().optional(),

  gitleaksStatus: z.string().max(30).optional(),
  gitleaksDurationMs: z.number().int().nonnegative().optional(),
  gitleaksError: z.string().max(300).nullable().optional(),

  semgrepStatus: z.string().max(30).optional(),
  semgrepDurationMs: z.number().int().nonnegative().optional(),
  semgrepError: z.string().max(300).nullable().optional(),

  osvStatus: z.string().max(30).optional(),
  osvDurationMs: z.number().int().nonnegative().optional(),
  osvError: z.string().max(300).nullable().optional(),

  scannerVersions: z.record(z.string(), z.unknown()).nullable().optional(),
  scanCoverage: z.record(z.string(), z.unknown()).nullable().optional(),

  counts: z
    .object({
      critical: z.number().int().nonnegative().optional(),
      high: z.number().int().nonnegative().optional(),
      medium: z.number().int().nonnegative().optional(),
      low: z.number().int().nonnegative().optional(),
      info: z.number().int().nonnegative().optional(),
    })
    .optional(),

  failureCategory: z.string().max(40).nullable().optional(),
  errorMessage: z.string().max(300).nullable().optional(),

  findings: z.array(CallbackFindingSchema).max(1000),
  remediations: z
    .array(
      z.object({
        id: z.string().max(36),
        findingFingerprints: z.array(z.string()),
        commitSha: z.string().max(40),
        patchSummary: z.string().max(500),
        unifiedDiff: z.string(),
        affectedFiles: z.array(z.string()),
        eligibility: z.enum(["safe", "potentially_breaking", "unsuitable"]),
        eligibilityReason: z.string().max(500),
        requiresRotation: z.boolean().default(false),
        warnings: z.array(z.string()).optional(),
      })
    )
    .optional(),
});

const PROGRESS_PHASES = ["worker_started", "retrieving", "extracting", "scanning"] as const;

/** Non-terminal heartbeat from the worker. Timestamps are ISO strings recorded on the runner. */
const ProgressPayloadSchema = z.object({
  type: z.literal("progress"),
  jobId: z.string().max(32),
  lease: z.string().max(100).optional(),
  phase: z.enum(PROGRESS_PHASES),
  at: z.string().max(40),
  workflowRunId: z.string().max(100).optional(),
  workflowRunUrl: z.string().max(300).optional(),
  commitSha: z.string().regex(/^[0-9a-f]{40}$/).optional(),
  defaultBranch: z.string().max(255).optional(),
});

const SCANNER_FIELDS = {
  gitleaks: { status: "gitleaksStatus", duration: "gitleaksDurationMs", error: "gitleaksError" },
  semgrep: { status: "semgrepStatus", duration: "semgrepDurationMs", error: "semgrepError" },
  "osv-scanner": { status: "osvStatus", duration: "osvDurationMs", error: "osvError" },
} as const;

/** One scanner's finished result, published before the other scanners complete. */
const ScannerResultSchema = z.object({
  type: z.literal("scanner_result"),
  jobId: z.string().max(32),
  lease: z.string().max(100).optional(),
  scanner: z.enum(["gitleaks", "semgrep", "osv-scanner"]),
  status: z.enum(["completed", "failed"]),
  durationMs: z.number().int().nonnegative(),
  error: z.string().max(300).nullable().optional(),
  at: z.string().max(40),
  findings: z.array(CallbackFindingSchema).max(1000).default([]),
  workflowRunId: z.string().max(100).optional(),
  workflowRunUrl: z.string().max(300).optional(),
});

/** Job status for each phase, and the statuses a job may be in to move forward to it. */
const PHASE_TRANSITIONS: Record<(typeof PROGRESS_PHASES)[number], { status: "queued" | "retrieving" | "scanning"; from: ScanStatus[] }> = {
  worker_started: { status: "queued", from: ["queued"] },
  retrieving: { status: "retrieving", from: ["queued"] },
  extracting: { status: "retrieving", from: ["queued", "retrieving"] },
  scanning: { status: "scanning", from: ["queued", "retrieving", "ready_for_scan"] },
};

const TERMINAL: ScanStatus[] = ["completed", "completed_with_warnings", "failed", "cancelled", "invalid_repository", "download_failed", "rejected_by_limits"];

type Progress = Record<string, unknown> & { revision?: number; firstFindingAt?: string };
const progressOf = (coverage: unknown): Progress => ({ ...((coverage as { progress?: Progress } | null)?.progress ?? {}) });

/** Keeps heartbeat timestamps recorded earlier when the final payload replaces scan coverage. */
function mergeProgress(existing: unknown, next: Record<string, unknown> | null | undefined, extra: Progress) {
  const earlier = progressOf(existing);
  if (!next) return { progress: { ...earlier, ...extra } } as Prisma.InputJsonValue;
  const later = (next.progress as Record<string, unknown> | undefined) ?? {};
  return { ...next, progress: { ...earlier, ...later, ...extra } } as Prisma.InputJsonValue;
}

function findingRows(scanJobId: string, findings: z.infer<typeof CallbackFindingSchema>[]) {
  return findings.map((f) => ({
    scanJobId,
    fingerprint: f.fingerprint,
    scanner: f.scanner,
    ruleId: f.ruleId,
    category: f.category,
    severity: f.severity,
    originalSeverity: f.originalSeverity ?? null,
    title: f.title,
    description: f.description,
    filePath: f.filePath,
    startLine: f.startLine ?? null,
    endLine: f.endLine ?? null,
    redactedEvidence: f.redactedEvidence ? redactText(f.redactedEvidence) : null,
    vulnerabilityId: f.vulnerabilityId ?? null,
    remediation: f.remediation ?? null,
    packageInfo: (f.packageInfo ?? Prisma.DbNull) as Prisma.InputJsonValue,
    metadata: (f.metadata ?? Prisma.DbNull) as Prisma.InputJsonValue,
    aiExplanation: (f.aiExplanation ?? Prisma.DbNull) as Prisma.InputJsonValue,
  }));
}

/**
 * Warm-worker leases are exclusive: the callback must carry exactly the lease stored on the job.
 * Anything signed with the warm-worker secret, or carrying a lease, may only touch a warm-owned job.
 */
function leaseRejection(job: JobRecord, lease: string | undefined, signedBy: "callback" | "warm"): Response | null {
  if (isWarmLease(job.workflowRunId)) {
    if (lease !== job.workflowRunId) return fail(409, "stale_lease", "This worker no longer owns the scan job.");
    return null;
  }
  if (signedBy === "warm" || lease) return fail(409, "stale_lease", "This worker no longer owns the scan job.");
  return null;
}

async function handleProgress(job: JobRecord, payload: z.infer<typeof ProgressPayloadSchema>): Promise<Response> {
  const step = PHASE_TRANSITIONS[payload.phase];
  const progress = { ...progressOf(job.scanCoverage), phase: payload.phase, [`${payload.phase}At`]: payload.at };
  const startScanners = payload.phase === "scanning";

  // Forward-only: a late or replayed heartbeat can never move a job backwards or out of a final state.
  const moved = await withDbRetry(() =>
    prisma.scanJob.updateMany({
      where: { id: job.id, status: { in: step.from } },
      data: {
        status: step.status,
        startedAt: job.startedAt ?? new Date(),
        // A warm lease stays the owner; only the Actions worker reports a run ID here.
        workflowRunId: isWarmLease(job.workflowRunId) ? job.workflowRunId : (payload.workflowRunId ?? job.workflowRunId),
        workflowRunUrl: payload.workflowRunUrl ?? job.workflowRunUrl,
        commitSha: payload.commitSha ?? job.commitSha,
        defaultBranch: payload.defaultBranch ?? job.defaultBranch,
        scanCoverage: { ...((job.scanCoverage as object | null) ?? {}), progress } as Prisma.InputJsonValue,
        ...(startScanners
          ? {
              gitleaksStatus: job.gitleaksStatus ?? "running",
              semgrepStatus: job.semgrepStatus ?? "running",
              osvStatus: job.osvStatus ?? "running",
            }
          : {}),
      },
    }),
  );
  return ok({ accepted: moved.count === 1, phase: payload.phase });
}

/**
 * Persists one scanner's findings as soon as it finishes. Idempotent: a repeated event replaces
 * that scanner's rows with the same set, and never touches other scanners' results.
 */
async function handleScannerResult(job: JobRecord, payload: z.infer<typeof ScannerResultSchema>): Promise<Response> {
  if (!ACTIVE_STATUSES.includes(job.status)) return ok({ accepted: false, message: "Job is not running." });
  const fields = SCANNER_FIELDS[payload.scanner];
  const rows = findingRows(job.id, payload.findings);

  const accepted = await withDbRetry(() =>
    prisma.$transaction(async (tx) => {
      // Re-read inside the transaction so a final callback that already landed wins.
      const current = await tx.scanJob.findUnique({ where: { id: job.id } });
      if (!current || !ACTIVE_STATUSES.includes(current.status) || current.workflowRunId !== job.workflowRunId) return false;
      const progress = progressOf(current.scanCoverage);
      const fingerprints = rows.map((r) => r.fingerprint);
      await tx.finding.deleteMany({ where: { scanJobId: job.id, scanner: payload.scanner, fingerprint: { notIn: fingerprints } } });
      if (rows.length > 0) await tx.finding.createMany({ data: rows, skipDuplicates: true });

      progress.revision = (progress.revision ?? 0) + 1;
      progress[`${payload.scanner}CompletedAt`] = payload.at;
      if (rows.length > 0 && !progress.firstFindingAt) progress.firstFindingAt = new Date().toISOString();
      await tx.scanJob.update({
        where: { id: job.id },
        data: {
          status: current.status === "scanning" ? undefined : "scanning",
          [fields.status]: payload.status,
          [fields.duration]: payload.durationMs,
          [fields.error]: payload.error ? redactText(payload.error) : null,
          scanCoverage: { ...((current.scanCoverage as object | null) ?? {}), progress } as Prisma.InputJsonValue,
        },
      });
      return true;
    }),
  );
  return ok({ accepted, scanner: payload.scanner });
}

async function handleFinal(job: JobRecord, payload: z.infer<typeof CallbackPayloadSchema>): Promise<Response> {
  if (TERMINAL.includes(job.status)) return ok({ message: "Job is already completed." }, 200);

  const now = new Date();
  const rows = findingRows(job.id, payload.findings);
  const fingerprints = rows.map((r) => r.fingerprint);
  const revision = (progressOf(job.scanCoverage).revision ?? 0) + 1;

  const applied = await withDbRetry(() =>
    prisma.$transaction(async (tx) => {
      // Single writer: only a still-active job owned by the same lease can be finalized.
      const claimed = await tx.scanJob.updateMany({
        where: { id: job.id, status: { in: [...ACTIVE_STATUSES] }, workflowRunId: job.workflowRunId },
        data: { status: payload.status, completedAt: now },
      });
      if (claimed.count !== 1) return false;

      // Upsert by fingerprint so rows already shown as partial results keep their IDs (and AI caches).
      await tx.finding.deleteMany({ where: { scanJobId: job.id, fingerprint: { notIn: fingerprints } } });
      if (rows.length > 0) await tx.finding.createMany({ data: rows, skipDuplicates: true });

      if (payload.remediations && payload.remediations.length > 0) {
        for (const rem of payload.remediations) {
          await tx.remediation.upsert({
            where: { id: rem.id },
            create: {
              id: rem.id,
              scanJobId: job.id,
              status: "preview",
              findingFingerprints: rem.findingFingerprints as Prisma.InputJsonValue,
              commitSha: rem.commitSha,
              patchSummary: rem.patchSummary,
              unifiedDiff: rem.unifiedDiff,
              affectedFiles: rem.affectedFiles as Prisma.InputJsonValue,
              eligibility: rem.eligibility,
              eligibilityReason: rem.eligibilityReason,
              requiresRotation: rem.requiresRotation,
              warnings: (rem.warnings || []) as Prisma.InputJsonValue,
            },
            update: {
              patchSummary: rem.patchSummary,
              unifiedDiff: rem.unifiedDiff,
              affectedFiles: rem.affectedFiles as Prisma.InputJsonValue,
              eligibility: rem.eligibility,
              eligibilityReason: rem.eligibilityReason,
              requiresRotation: rem.requiresRotation,
            },
          });
        }
      }

      await tx.scanJob.update({
        where: { id: job.id },
        data: {
          workflowRunId: isWarmLease(job.workflowRunId) ? job.workflowRunId : (payload.workflowRunId ?? job.workflowRunId),
          workflowRunUrl: payload.workflowRunUrl ?? job.workflowRunUrl,
          commitSha: payload.commitSha ?? job.commitSha,
          archiveBytes: payload.archiveBytes ?? job.archiveBytes,
          fileCount: payload.fileCount ?? job.fileCount,
          unpackedBytes: payload.unpackedBytes ?? job.unpackedBytes,

          gitleaksStatus: payload.gitleaksStatus ?? (payload.status === "failed" ? null : job.gitleaksStatus),
          gitleaksDurationMs: payload.gitleaksDurationMs ?? job.gitleaksDurationMs,
          gitleaksError: payload.gitleaksError ?? null,
          semgrepStatus: payload.semgrepStatus ?? (payload.status === "failed" ? null : job.semgrepStatus),
          semgrepDurationMs: payload.semgrepDurationMs ?? job.semgrepDurationMs,
          semgrepError: payload.semgrepError ?? null,
          osvStatus: payload.osvStatus ?? (payload.status === "failed" ? null : job.osvStatus),
          osvDurationMs: payload.osvDurationMs ?? job.osvDurationMs,
          osvError: payload.osvError ?? null,

          scannerVersions: (payload.scannerVersions ?? Prisma.DbNull) as Prisma.InputJsonValue,
          scanCoverage: mergeProgress(job.scanCoverage, payload.scanCoverage, { revision, finalAt: now.toISOString() }),

          criticalCount: payload.counts?.critical ?? 0,
          highCount: payload.counts?.high ?? 0,
          mediumCount: payload.counts?.medium ?? 0,
          lowCount: payload.counts?.low ?? 0,
          infoCount: payload.counts?.info ?? 0,

          failureCategory: payload.failureCategory ?? null,
          errorMessage: payload.errorMessage ?? null,
        },
      });
      return true;
    }),
  );
  if (!applied) return ok({ message: "Job is already completed." }, 200);
  return ok({ success: true, jobId: job.id, status: payload.status });
}

/**
 * POST /api/scans/:id/callback. `onSlotFreed` runs after a final result so waiting scans start
 * immediately instead of waiting for the next poll.
 */
export async function handleScanCallback(
  req: Request,
  id: string,
  onSlotFreed?: () => Promise<unknown>,
): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");

  const config = getConfig();
  const callbackSecret = config.scanCallbackSecret || process.env.SCAN_CALLBACK_SECRET;
  if (!callbackSecret) return fail(500, "callback_misconfigured", "Callback authentication secret is not configured.");

  const declaredLength = Number.parseInt(req.headers.get("content-length") ?? "0", 10);
  if (declaredLength > MAX_CALLBACK_BYTES) return fail(413, "payload_too_large", "Callback payload exceeds maximum size limit.");
  const rawBody = await req.text();
  if (rawBody.length > MAX_CALLBACK_BYTES) return fail(413, "payload_too_large", "Callback payload exceeds maximum size limit.");

  // Either executor's secret is accepted; which one signed decides what the caller may touch.
  const signatureHeader = req.headers.get("x-vibeshield-signature");
  let signedBy: "callback" | "warm" = "callback";
  let authResult = verifyCallbackSignature(rawBody, signatureHeader, callbackSecret);
  if (!authResult.valid && config.warmWorkerSecret) {
    const warm = verifyCallbackSignature(rawBody, signatureHeader, config.warmWorkerSecret);
    if (warm.valid) {
      authResult = warm;
      signedBy = "warm";
    }
  }
  if (!authResult.valid) {
    if (authResult.reason === "timestamp_expired") return fail(401, "timestamp_expired", "Callback signature expired or invalid timestamp.");
    return fail(401, "unauthorized", "Invalid or missing callback signature.");
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(rawBody);
  } catch {
    return fail(400, "invalid_json", "Callback body must be valid JSON.");
  }
  const kind = (parsedJson as { type?: unknown } | null)?.type;
  const schema = kind === "progress" ? ProgressPayloadSchema : kind === "scanner_result" ? ScannerResultSchema : CallbackPayloadSchema;
  const parsed = schema.safeParse(parsedJson);
  if (!parsed.success) return fail(400, "validation_failed", "Callback payload does not match schema.");
  const payload = parsed.data as { jobId: string; lease?: string };
  if (payload.jobId !== id) return fail(400, "job_id_mismatch", "Payload job ID does not match route parameter.");

  const job = (await withDbRetry(() => prisma.scanJob.findUnique({ where: { id } }))) as JobRecord | null;
  if (!job) return fail(404, "not_found", "Scan job not found.");
  if (TERMINAL.includes(job.status)) return ok({ accepted: false, message: "Job is already completed." }, 200);
  const rejected = leaseRejection(job, payload.lease, signedBy);
  if (rejected) return rejected;

  if (kind === "progress") return handleProgress(job, parsed.data as z.infer<typeof ProgressPayloadSchema>);
  if (kind === "scanner_result") return handleScannerResult(job, parsed.data as z.infer<typeof ScannerResultSchema>);

  const res = await handleFinal(job, parsed.data as z.infer<typeof CallbackPayloadSchema>);
  if (onSlotFreed) {
    await onSlotFreed().catch((err) => log("warn", "queue_pump_after_callback_failed", { cause: err instanceof Error ? err.name : "unknown" }));
  }
  return res;
}

const SourceRequestSchema = z.object({ jobId: z.string(), lease: z.string().max(100).optional() }).strict();

/**
 * POST /api/scans/:id/source — called only by a scan worker holding the job, for private
 * repositories. Same signature and lease checks as callbacks. Returns the scanned repository's
 * identity and a short-lived archive URL; never the user's token.
 */
export async function handleScanSource(req: Request, id: string, auth: AuthDeps): Promise<Response> {
  if (!JOB_ID_RE.test(id)) return fail(404, "not_found", "Scan job not found.");
  const config = getConfig();
  const callbackSecret = config.scanCallbackSecret || process.env.SCAN_CALLBACK_SECRET;
  if (!callbackSecret) return fail(500, "callback_misconfigured", "Callback authentication secret is not configured.");
  const rawBody = await req.text();
  if (rawBody.length > 4096) return fail(413, "payload_too_large", "Request too large.");
  const signatureHeader = req.headers.get("x-vibeshield-signature");
  let signedBy: "callback" | "warm" = "callback";
  let authResult = verifyCallbackSignature(rawBody, signatureHeader, callbackSecret);
  if (!authResult.valid && config.warmWorkerSecret) {
    const warm = verifyCallbackSignature(rawBody, signatureHeader, config.warmWorkerSecret);
    if (warm.valid) {
      authResult = warm;
      signedBy = "warm";
    }
  }
  if (!authResult.valid) return fail(401, "unauthorized", "Invalid or missing signature.");
  let parsed;
  try {
    parsed = SourceRequestSchema.parse(JSON.parse(rawBody));
  } catch {
    return fail(400, "validation_failed", "Request does not match schema.");
  }
  if (parsed.jobId !== id) return fail(400, "job_id_mismatch", "Payload job ID does not match route parameter.");

  const job = (await withDbRetry(() => prisma.scanJob.findUnique({ where: { id } }))) as JobRecord | null;
  if (!job) return fail(404, "not_found", "Scan job not found.");
  if (TERMINAL.includes(job.status)) return fail(409, "job_finished", "Job is already finished.");
  const rejected = leaseRejection(job, parsed.lease, signedBy);
  if (rejected) return rejected;

  const source = await resolvePrivateSource(job, await loadScanAccess(auth, id), "scan", auth, config);
  if ("code" in source) {
    log("warn", "private_source_unavailable", { jobId: id, code: source.code });
    return fail(source.code === "not_private" ? 404 : 403, source.code, "The private repository source is not available to this job.");
  }
  return Response.json({ data: source }, { status: 200, headers: { "Cache-Control": "no-store" } });
}
