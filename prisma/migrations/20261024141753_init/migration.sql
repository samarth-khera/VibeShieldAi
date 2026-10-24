-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('queued', 'retrieving', 'ready_for_scan', 'invalid_repository', 'download_failed', 'rejected_by_limits', 'failed');

-- CreateTable
CREATE TABLE "ScanJob" (
    "id" VARCHAR(32) NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'queued',
    "owner" VARCHAR(39) NOT NULL,
    "repo" VARCHAR(100) NOT NULL,
    "repositoryUrl" VARCHAR(200) NOT NULL,
    "defaultBranch" VARCHAR(255),
    "commitSha" VARCHAR(40),
    "description" VARCHAR(500),
    "repoSizeKb" INTEGER,
    "stars" INTEGER,
    "primaryLanguage" VARCHAR(100),
    "archiveBytes" INTEGER,
    "fileCount" INTEGER,
    "unpackedBytes" INTEGER,
    "failureCategory" VARCHAR(40),
    "errorMessage" VARCHAR(300),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ScanJob_status_idx" ON "ScanJob"("status");

-- CreateIndex
CREATE INDEX "ScanJob_expiresAt_idx" ON "ScanJob"("expiresAt");

-- CreateIndex
CREATE INDEX "ScanJob_owner_repo_idx" ON "ScanJob"("owner", "repo");

-- CreateIndex
CREATE INDEX "ScanJob_createdAt_idx" ON "ScanJob"("createdAt");
