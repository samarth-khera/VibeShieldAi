-- CreateEnum
CREATE TYPE "RemediationStatus" AS ENUM ('preview', 'approved', 'applied', 'verified', 'needs_review', 'failed', 'rejected');

-- CreateTable
CREATE TABLE "Remediation" (
    "id" VARCHAR(36) NOT NULL,
    "scanJobId" VARCHAR(32) NOT NULL,
    "status" "RemediationStatus" NOT NULL DEFAULT 'preview',
    "findingFingerprints" JSONB NOT NULL,
    "commitSha" VARCHAR(40) NOT NULL,
    "patchSummary" VARCHAR(500) NOT NULL,
    "unifiedDiff" TEXT NOT NULL,
    "affectedFiles" JSONB NOT NULL,
    "eligibility" VARCHAR(30) NOT NULL,
    "eligibilityReason" VARCHAR(500) NOT NULL,
    "requiresRotation" BOOLEAN NOT NULL DEFAULT false,
    "warnings" JSONB,
    "approvedAt" TIMESTAMP(3),
    "approvedOperations" JSONB,
    "rescanStatus" VARCHAR(30),
    "rescanSummary" JSONB,
    "branchName" VARCHAR(120),
    "pullRequestUrl" VARCHAR(300),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Remediation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Remediation_scanJobId_idx" ON "Remediation"("scanJobId");

-- CreateIndex
CREATE INDEX "Remediation_status_idx" ON "Remediation"("status");

-- AddForeignKey
ALTER TABLE "Remediation" ADD CONSTRAINT "Remediation_scanJobId_fkey" FOREIGN KEY ("scanJobId") REFERENCES "ScanJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;
