import type { ServerConfig } from "../config";
import { fetchCommitSha, resolveArchiveUrl } from "../github";
import { RetrievalError } from "../errors";
import type { JobRecord } from "../job-store";
import { checkRepositoryAccess } from "./github-app";
import { getUserToken, markRevoked, type AuthDeps } from "./service";
import type { ScanAccessRecord } from "./store";
import { loadScanAccess } from "./repository-access";
import { PRIVATE_REPOSITORY } from "../worker/private-repository";

export type PrivateSource = {
  owner: string;
  repo: string;
  defaultBranch: string;
  commitSha: string;
  /** Short-lived, single-archive download URL. A credential: never log or persist it. */
  archiveUrl: string;
};

export type PrivateSourceFailure = {
  code: "not_private" | "authorization_lost" | "access_lost" | "repository_changed" | "github_unavailable";
};

/**
 * Produces the download for a private scan using the authorizing user's own GitHub token, after
 * re-checking that the user can still read the same repository (same immutable ID). `commitSha`
 * pins verification to the scanned commit; scans resolve the current default-branch commit.
 */
export async function resolvePrivateSource(
  job: Pick<JobRecord, "id" | "owner" | "repo" | "commitSha">,
  scanAccess: ScanAccessRecord | null,
  purpose: "scan" | "verify",
  deps: AuthDeps,
  config: ServerConfig,
): Promise<PrivateSource | PrivateSourceFailure> {
  if (!scanAccess?.isPrivate || scanAccess.githubUserId === null) return { code: "not_private" };
  const account = await deps.store.getAccountByGithubUserId(scanAccess.githubUserId);
  if (!account) return { code: "authorization_lost" };
  const t = await getUserToken(account, deps);
  if ("error" in t) return { code: "authorization_lost" };

  const access = await checkRepositoryAccess(t.token, job.owner, job.repo, deps.fetchImpl);
  if (access.status === "unauthorized") {
    await markRevoked(account, deps, "token_rejected");
    return { code: "authorization_lost" };
  }
  if (access.status !== "ok") return { code: access.status === "not_found" ? "access_lost" : "github_unavailable" };
  if (access.repoId !== scanAccess.githubRepoId) return { code: "repository_changed" };
  if (!access.canRead || !access.defaultBranch) return { code: "access_lost" };

  const asUser = { ...config, githubToken: t.token };
  const signal = AbortSignal.timeout(config.githubApiTimeoutMs);
  try {
    const commitSha =
      purpose === "verify" && job.commitSha
        ? job.commitSha
        : await fetchCommitSha(deps.fetchImpl, job.owner, job.repo, access.defaultBranch, asUser, signal);
    const archiveUrl = await resolveArchiveUrl(deps.fetchImpl, job.owner, job.repo, commitSha, asUser, signal);
    return { owner: job.owner, repo: job.repo, defaultBranch: access.defaultBranch, commitSha, archiveUrl };
  } catch (err) {
    return { code: err instanceof RetrievalError && err.category === "not_found_or_private" ? "access_lost" : "github_unavailable" };
  }
}

/**
 * The repository value a worker may see in workflow inputs or claim responses. Private scans get a
 * placeholder so their name never reaches the public Actions UI. A lookup failure throws, so a
 * private name is never sent by mistake.
 */
export async function repositoryUrlForWorker(jobId: string, repositoryUrl: string, deps: AuthDeps): Promise<string> {
  if (!deps.app) return repositoryUrl;
  const access = await loadScanAccess(deps, jobId);
  return access?.isPrivate ? PRIVATE_REPOSITORY : repositoryUrl;
}
