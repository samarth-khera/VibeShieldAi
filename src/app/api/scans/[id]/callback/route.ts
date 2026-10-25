import { z } from "zod";
import { getConfig } from "@/server/config";
import { prisma, withDbRetry } from "@/server/db";
import { verifyCallbackSignature } from "@/server/callback-auth";
import { redactText } from "@/server/scanners/redact";
import { fail, ok } from "@/server/api";
import { JOB_ID_RE } from "@/server/job-store";
import { Prisma } from "@prisma/client";

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

export async function POST(
  req: Request,
  props: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await props.params;

  if (!JOB_ID_RE.test(id)) {
    return fail(404, "not_found", "Scan job not found.");
  }

  const config = getConfig();
  const secret = config.scanCallbackSecret || process.env.SCAN_CALLBACK_SECRET;
  if (!secret) {
    return fail(500, "callback_misconfigured", "Callback authentication secret is not configured.");
  }

  // Enforce body size limit (5 MB)
  const declaredLength = Number.parseInt(req.headers.get("content-length") ?? "0", 10);
  if (declaredLength > MAX_CALLBACK_BYTES) {
    return fail(413, "payload_too_large", "Callback payload exceeds maximum size limit.");
  }

  const rawBody = await req.text();
  if (rawBody.length > MAX_CALLBACK_BYTES) {
    return fail(413, "payload_too_large", "Callback payload exceeds maximum size limit.");
  }

  // Verify HMAC signature and timestamp
  const signatureHeader = req.headers.get("x-vibeshield-signature");
  const authResult = verifyCallbackSignature(rawBody, signatureHeader, secret);
  if (!authResult.valid) {
    if (authResult.reason === "timestamp_expired") {
      return fail(401, "timestamp_expired", "Callback signature expired or invalid timestamp.");
    }
    return fail(401, "unauthorized", "Invalid or missing callback signature.");
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(rawBody);
  } catch {
    return fail(400, "invalid_json", "Callback body must be valid JSON.");
  }

  const validation = CallbackPayloadSchema.safeParse(parsedJson);
  if (!validation.success) {
    return fail(400, "validation_failed", "Callback payload does not match schema.");
  }

  const payload = validation.data;
  if (payload.jobId !== id) {
    return fail(400, "job_id_mismatch", "Payload job ID does not match route parameter.");
  }

  // Fetch current job from database
  const existingJob = await withDbRetry(() => prisma.scanJob.findUnique({ where: { id } }));
  if (!existingJob) {
    return fail(404, "not_found", "Scan job not found.");
  }

  // Prevent replaying callbacks onto already completed jobs
  if (
    existingJob.status === "completed" ||
    existingJob.status === "completed_with_warnings" ||
    existingJob.status === "failed"
  ) {
    return ok({ message: "Job is already completed." }, 200);
  }

  const now = new Date();

  // Atomically persist findings, metrics, and completion state in a single transaction
  await withDbRetry(() =>
    prisma.$transaction(async (tx) => {
      // 1. Delete previous findings if any
      await tx.finding.deleteMany({ where: { scanJobId: id } });

      // 2. Insert sanitized findings
      if (payload.findings.length > 0) {
        await tx.finding.createMany({
          data: payload.findings.map((f) => ({
            scanJobId: id,
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
          })),
          skipDuplicates: true,
        });
      }

      // 3. Insert precomputed remediations if provided
      if (payload.remediations && payload.remediations.length > 0) {
        for (const rem of payload.remediations) {
          await tx.remediation.upsert({
            where: { id: rem.id },
            create: {
              id: rem.id,
              scanJobId: id,
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

      // 4. Update scan job status and summary counts
      await tx.scanJob.update({
        where: { id },
        data: {
          status: payload.status,
          workflowRunId: payload.workflowRunId ?? existingJob.workflowRunId,
          workflowRunUrl: payload.workflowRunUrl ?? existingJob.workflowRunUrl,
          commitSha: payload.commitSha ?? existingJob.commitSha,
          archiveBytes: payload.archiveBytes ?? existingJob.archiveBytes,
          fileCount: payload.fileCount ?? existingJob.fileCount,
          unpackedBytes: payload.unpackedBytes ?? existingJob.unpackedBytes,

          gitleaksStatus: payload.gitleaksStatus ?? null,
          gitleaksDurationMs: payload.gitleaksDurationMs ?? null,
          gitleaksError: payload.gitleaksError ?? null,

          semgrepStatus: payload.semgrepStatus ?? null,
          semgrepDurationMs: payload.semgrepDurationMs ?? null,
          semgrepError: payload.semgrepError ?? null,

          osvStatus: payload.osvStatus ?? null,
          osvDurationMs: payload.osvDurationMs ?? null,
          osvError: payload.osvError ?? null,

          scannerVersions: (payload.scannerVersions ?? Prisma.DbNull) as Prisma.InputJsonValue,
          scanCoverage: (payload.scanCoverage ?? Prisma.DbNull) as Prisma.InputJsonValue,

          criticalCount: payload.counts?.critical ?? 0,
          highCount: payload.counts?.high ?? 0,
          mediumCount: payload.counts?.medium ?? 0,
          lowCount: payload.counts?.low ?? 0,
          infoCount: payload.counts?.info ?? 0,

          failureCategory: payload.failureCategory ?? null,
          errorMessage: payload.errorMessage ?? null,

          completedAt: now,
        },
      });
    })
  );

  return ok({ success: true, jobId: id, status: payload.status });
}
