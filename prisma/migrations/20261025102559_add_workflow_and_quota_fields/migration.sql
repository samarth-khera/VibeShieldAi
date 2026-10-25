-- AlterTable
ALTER TABLE "ScanJob" ADD COLUMN     "clientIpHash" VARCHAR(64),
ADD COLUMN     "workflowRunId" VARCHAR(100),
ADD COLUMN     "workflowRunUrl" VARCHAR(300);

-- CreateIndex
CREATE INDEX "ScanJob_clientIpHash_createdAt_idx" ON "ScanJob"("clientIpHash", "createdAt");
