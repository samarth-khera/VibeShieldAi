-- Additive: persistent warm worker liveness. Safe to apply before or after deploying the app.
CREATE TABLE "WorkerHeartbeat" (
    "id" VARCHAR(64) NOT NULL,
    "lastRequestMs" BIGINT NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "capacity" INTEGER NOT NULL DEFAULT 1,
    "activeJobs" INTEGER NOT NULL DEFAULT 0,
    "version" VARCHAR(40),
    "arch" VARCHAR(40),
    "scannerVersions" JSONB,

    CONSTRAINT "WorkerHeartbeat_pkey" PRIMARY KEY ("id")
);
