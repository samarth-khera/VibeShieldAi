-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanStatus" ADD VALUE 'scanning';
ALTER TYPE "ScanStatus" ADD VALUE 'completed';
ALTER TYPE "ScanStatus" ADD VALUE 'completed_with_warnings';
ALTER TYPE "ScanStatus" ADD VALUE 'cancelled';

-- AlterTable
ALTER TABLE "ScanJob" ADD COLUMN     "criticalCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "gitleaksDurationMs" INTEGER,
ADD COLUMN     "gitleaksError" VARCHAR(300),
ADD COLUMN     "gitleaksStatus" VARCHAR(30),
ADD COLUMN     "highCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "infoCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lowCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "mediumCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "osvDurationMs" INTEGER,
ADD COLUMN     "osvError" VARCHAR(300),
ADD COLUMN     "osvStatus" VARCHAR(30),
ADD COLUMN     "scanCoverage" JSONB,
ADD COLUMN     "scannerVersions" JSONB,
ADD COLUMN     "semgrepDurationMs" INTEGER,
ADD COLUMN     "semgrepError" VARCHAR(300),
ADD COLUMN     "semgrepStatus" VARCHAR(30);

-- CreateTable
CREATE TABLE "Finding" (
    "id" VARCHAR(36) NOT NULL,
    "scanJobId" VARCHAR(32) NOT NULL,
    "fingerprint" VARCHAR(64) NOT NULL,
    "scanner" VARCHAR(30) NOT NULL,
    "ruleId" VARCHAR(120) NOT NULL,
    "category" VARCHAR(50) NOT NULL,
    "severity" VARCHAR(20) NOT NULL,
    "originalSeverity" VARCHAR(50),
    "title" VARCHAR(250) NOT NULL,
    "description" TEXT NOT NULL,
    "filePath" VARCHAR(500) NOT NULL,
    "startLine" INTEGER,
    "endLine" INTEGER,
    "redactedEvidence" TEXT,
    "vulnerabilityId" VARCHAR(100),
    "remediation" TEXT,
    "packageInfo" JSONB,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Finding_scanJobId_idx" ON "Finding"("scanJobId");

-- CreateIndex
CREATE INDEX "Finding_scanJobId_severity_idx" ON "Finding"("scanJobId", "severity");

-- CreateIndex
CREATE INDEX "Finding_scanJobId_category_idx" ON "Finding"("scanJobId", "category");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_scanJobId_fingerprint_key" ON "Finding"("scanJobId", "fingerprint");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanJobId_fkey" FOREIGN KEY ("scanJobId") REFERENCES "ScanJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;
