-- CreateTable
CREATE TABLE "AiCircuitBreaker" (
    "id" VARCHAR(32) NOT NULL,
    "isOpen" BOOLEAN NOT NULL DEFAULT false,
    "openedAt" TIMESTAMP(3),
    "reason" VARCHAR(50),
    "message" VARCHAR(500),
    "cooldownUntil" TIMESTAMP(3),
    "consecutiveFailures" INTEGER NOT NULL DEFAULT 0,
    "lastFailureAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AiCircuitBreaker_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AiRequestLog" (
    "id" VARCHAR(36) NOT NULL,
    "clientIpHash" VARCHAR(64) NOT NULL,
    "scanJobId" VARCHAR(32),
    "findingId" VARCHAR(36),
    "action" VARCHAR(30) NOT NULL,
    "success" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AiRequestLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AiRequestLog_clientIpHash_createdAt_idx" ON "AiRequestLog"("clientIpHash", "createdAt");

-- CreateIndex
CREATE INDEX "AiRequestLog_createdAt_idx" ON "AiRequestLog"("createdAt");
