import { Prisma, PrismaClient } from "@prisma/client";
import {
  newJobId,
  RETRYABLE_STATUSES,
  type FindingRecord,
  type FindingsFilter,
  type JobPatch,
  type JobRecord,
  type JobStore,
  type NewJob,
} from "./job-store";
import type { NormalizedFinding } from "./scanners/types";

const g = globalThis as unknown as { __prisma?: PrismaClient };
export const prisma = g.__prisma ?? new PrismaClient({ log: ["error"] });
if (process.env.NODE_ENV !== "production") g.__prisma = prisma;

export const prismaJobStore: JobStore = {
  create: (data: NewJob) => prisma.scanJob.create({ data: { id: newJobId(), ...data } }) as Promise<JobRecord>,
  get: (id) => prisma.scanJob.findUnique({ where: { id } }) as Promise<JobRecord | null>,
  async claim(id, staleBefore) {
    const r = await prisma.scanJob.updateMany({
      where: {
        id,
        OR: [{ status: "queued" }, { status: "retrieving", startedAt: { lt: staleBefore } }],
      },
      data: { status: "retrieving", startedAt: new Date(), attempts: { increment: 1 }, failureCategory: null, errorMessage: null },
    });
    return r.count === 1;
  },
  async claimForScan(id, staleBefore) {
    const r = await prisma.scanJob.updateMany({
      where: {
        id,
        OR: [
          { status: "ready_for_scan" },
          { status: "retrieving" },
          { status: "scanning", startedAt: { lt: staleBefore } },
        ],
      },
      data: { status: "scanning", failureCategory: null, errorMessage: null },
    });
    return r.count === 1;
  },
  async update(id, patch: JobPatch) {
    await prisma.scanJob.update({ where: { id }, data: patch as Prisma.ScanJobUpdateInput });
  },
  async requeue(id, maxAttempts) {
    const r = await prisma.scanJob.updateMany({
      where: { id, status: { in: [...RETRYABLE_STATUSES] }, attempts: { lt: maxAttempts } },
      data: { status: "queued", failureCategory: null, errorMessage: null, completedAt: null },
    });
    return r.count === 1;
  },
  async deleteExpired(now) {
    return (await prisma.scanJob.deleteMany({ where: { expiresAt: { lt: now } } })).count;
  },

  async saveFindings(jobId: string, findings: NormalizedFinding[]) {
    await prisma.$transaction(async (tx) => {
      // Remove old findings if re-scanning
      await tx.finding.deleteMany({ where: { scanJobId: jobId } });

      if (findings.length === 0) return;

      await tx.finding.createMany({
        data: findings.map((f) => ({
          scanJobId: jobId,
          fingerprint: f.fingerprint,
          scanner: f.scanner,
          ruleId: f.ruleId,
          category: f.category,
          severity: f.severity,
          originalSeverity: f.originalSeverity ?? null,
          title: f.title,
          description: f.description,
          filePath: f.filePath,
          startLine: f.startLine,
          endLine: f.endLine,
          redactedEvidence: f.redactedEvidence,
          vulnerabilityId: f.vulnerabilityId,
          remediation: f.remediation,
          packageInfo: (f.packageInfo ?? Prisma.DbNull) as Prisma.InputJsonValue,
          metadata: (f.metadata ?? Prisma.DbNull) as Prisma.InputJsonValue,
        })),
        skipDuplicates: true,
      });
    });
  },

  async getFindings(jobId: string, filter?: FindingsFilter) {
    const where: Prisma.FindingWhereInput = { scanJobId: jobId };

    if (filter?.severity && filter.severity !== "all") {
      where.severity = filter.severity;
    }
    if (filter?.category && filter.category !== "all") {
      where.category = filter.category;
    }
    if (filter?.query) {
      const q = filter.query.trim();
      where.OR = [
        { title: { contains: q, mode: "insensitive" } },
        { description: { contains: q, mode: "insensitive" } },
        { filePath: { contains: q, mode: "insensitive" } },
        { ruleId: { contains: q, mode: "insensitive" } },
        { vulnerabilityId: { contains: q, mode: "insensitive" } },
      ];
    }

    const [total, findings] = await Promise.all([
      prisma.finding.count({ where }),
      prisma.finding.findMany({
        where,
        take: filter?.limit ?? 100,
        skip: filter?.offset ?? 0,
        orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
      }),
    ]);

    return { findings: findings as FindingRecord[], total };
  },

  async getFinding(jobId: string, findingId: string) {
    const finding = await prisma.finding.findFirst({
      where: { id: findingId, scanJobId: jobId },
    });
    return (finding as FindingRecord) || null;
  },

  async saveFindingAiExplanation(jobId: string, findingId: string, aiExplanation: unknown) {
    await prisma.finding.updateMany({
      where: { id: findingId, scanJobId: jobId },
      data: { aiExplanation: aiExplanation as Prisma.InputJsonValue },
    });
  },

  async createRemediation(data) {
    const created = await prisma.remediation.create({
      data: {
        id: data.id,
        scanJobId: data.scanJobId,
        status: data.status,
        findingFingerprints: data.findingFingerprints as Prisma.InputJsonValue,
        commitSha: data.commitSha,
        patchSummary: data.patchSummary,
        unifiedDiff: data.unifiedDiff,
        affectedFiles: data.affectedFiles as Prisma.InputJsonValue,
        eligibility: data.eligibility,
        eligibilityReason: data.eligibilityReason,
        requiresRotation: data.requiresRotation,
        warnings: (data.warnings || []) as Prisma.InputJsonValue,
        approvedAt: data.approvedAt,
        approvedOperations: data.approvedOperations as Prisma.InputJsonValue,
        rescanStatus: data.rescanStatus,
        rescanSummary: data.rescanSummary as Prisma.InputJsonValue,
        branchName: data.branchName,
        pullRequestUrl: data.pullRequestUrl,
      },
    });
    return created as unknown as import("./remediation/types").RemediationRecord;
  },

  async getRemediation(scanJobId, remediationId) {
    const r = await prisma.remediation.findFirst({
      where: { id: remediationId, scanJobId },
    });
    return (r as unknown as import("./remediation/types").RemediationRecord) || null;
  },

  async listRemediations(scanJobId) {
    const list = await prisma.remediation.findMany({
      where: { scanJobId },
      orderBy: { createdAt: "desc" },
    });
    return list as unknown as import("./remediation/types").RemediationRecord[];
  },

  async updateRemediation(scanJobId, remediationId, patch) {
    const updated = await prisma.remediation.update({
      where: { id: remediationId },
      data: {
        ...patch,
        findingFingerprints: patch.findingFingerprints ? (patch.findingFingerprints as Prisma.InputJsonValue) : undefined,
        affectedFiles: patch.affectedFiles ? (patch.affectedFiles as Prisma.InputJsonValue) : undefined,
        warnings: patch.warnings ? (patch.warnings as Prisma.InputJsonValue) : undefined,
        approvedOperations: patch.approvedOperations ? (patch.approvedOperations as Prisma.InputJsonValue) : undefined,
        rescanSummary: patch.rescanSummary ? (patch.rescanSummary as Prisma.InputJsonValue) : undefined,
      } as Prisma.RemediationUpdateInput,
    });
    return updated as unknown as import("./remediation/types").RemediationRecord;
  },
};
