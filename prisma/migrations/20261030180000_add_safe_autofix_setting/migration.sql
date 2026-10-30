-- CreateTable
CREATE TABLE "SafeAutoFixSetting" (
    "githubRepoId" BIGINT NOT NULL,
    "enabledByGithubUserId" BIGINT NOT NULL,
    "enabledByLogin" VARCHAR(39) NOT NULL,
    "scope" VARCHAR(40) NOT NULL DEFAULT 'safe_dependency_patch',
    "enabledAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SafeAutoFixSetting_pkey" PRIMARY KEY ("githubRepoId")
);

