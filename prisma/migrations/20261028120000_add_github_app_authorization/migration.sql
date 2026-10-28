-- Additive: GitHub App user authorization (sessions, accounts, OAuth state, scan access, audit).
-- Apply before setting the GITHUB_APP_* variables. Nothing reads these tables until then.
CREATE TABLE "GithubAccount" (
    "id" VARCHAR(36) NOT NULL,
    "githubUserId" BIGINT NOT NULL,
    "login" VARCHAR(39) NOT NULL,
    "avatarUrl" VARCHAR(300),
    "accessTokenEnc" TEXT NOT NULL,
    "accessTokenExpiresAt" TIMESTAMP(3),
    "refreshTokenEnc" TEXT,
    "refreshTokenExpiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GithubAccount_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "GithubAccount_githubUserId_key" ON "GithubAccount"("githubUserId");

CREATE TABLE "AuthSession" (
    "id" VARCHAR(64) NOT NULL,
    "githubAccountId" VARCHAR(36),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "AuthSession_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "AuthSession_githubAccountId_idx" ON "AuthSession"("githubAccountId");
CREATE INDEX "AuthSession_expiresAt_idx" ON "AuthSession"("expiresAt");
ALTER TABLE "AuthSession" ADD CONSTRAINT "AuthSession_githubAccountId_fkey" FOREIGN KEY ("githubAccountId") REFERENCES "GithubAccount"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "OAuthState" (
    "id" VARCHAR(64) NOT NULL,
    "sessionId" VARCHAR(64) NOT NULL,
    "purpose" VARCHAR(20) NOT NULL,
    "returnTo" VARCHAR(300) NOT NULL,
    "codeVerifierEnc" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OAuthState_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "OAuthState_expiresAt_idx" ON "OAuthState"("expiresAt");

CREATE TABLE "ScanAccess" (
    "scanJobId" VARCHAR(32) NOT NULL,
    "githubRepoId" BIGINT NOT NULL,
    "isPrivate" BOOLEAN NOT NULL DEFAULT false,
    "githubUserId" BIGINT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanAccess_pkey" PRIMARY KEY ("scanJobId")
);
CREATE INDEX "ScanAccess_githubUserId_idx" ON "ScanAccess"("githubUserId");

CREATE TABLE "AuditEvent" (
    "id" VARCHAR(36) NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "action" VARCHAR(40) NOT NULL,
    "outcome" VARCHAR(30) NOT NULL,
    "githubUserId" BIGINT,
    "githubLogin" VARCHAR(39),
    "scanJobId" VARCHAR(32),
    "remediationId" VARCHAR(36),
    "repository" VARCHAR(140),
    "detail" VARCHAR(300),

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "AuditEvent_at_idx" ON "AuditEvent"("at");
CREATE INDEX "AuditEvent_githubUserId_at_idx" ON "AuditEvent"("githubUserId", "at");
