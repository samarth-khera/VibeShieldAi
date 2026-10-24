import { PrismaClient } from "@prisma/client";
import { newJobId, RETRYABLE_STATUSES, type JobRecord, type JobStore, type NewJob, type JobPatch } from "./job-store";

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
  async update(id, patch: JobPatch) {
    await prisma.scanJob.update({ where: { id }, data: patch });
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
};
