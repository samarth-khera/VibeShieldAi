import type { RepositoryGate } from "../scans-service";
import { checkRepositoryAccess } from "./github-app";
import { isMissingTable } from "./repository-access";
import { markRevoked, resolveAuthorizedUser, type AuthDeps } from "./service";
import { PRIVATE_SCANNING_AVAILABLE } from "./private-source";

const PRIVATE_NOT_SCANNABLE = "Repository not found or not public. Private repository scanning is currently unavailable.";

type PublicCheck = (owner: string, repo: string) => Promise<{ ok: boolean; repoId?: number | null; code?: string; error?: string }>;

const PRIVATE_HINT =
  "Repository not found, or it is private. To scan a private repository, connect GitHub and authorize the repository for the VibeShield app.";

/**
 * Public repositories need no authorization. Anything else is scanned only if the current
 * session's own GitHub user can read it through the app installation; the repository ID is
 * resolved from GitHub, never taken from the request.
 */
export async function resolveRepositoryForScan(
  req: Request,
  owner: string,
  repo: string,
  auth: AuthDeps,
  publicCheck: PublicCheck,
): Promise<RepositoryGate> {
  const pub = await publicCheck(owner, repo);
  if (pub.ok) return { ok: true, repoId: pub.repoId ?? null, isPrivate: false, githubUserId: null };
  const fail = (status: number, code: string, error: string): RepositoryGate => ({ ok: false, status, code, error });
  if (pub.code !== "not_found_or_private") return fail(400, pub.code ?? "invalid_repository", pub.error ?? "Repository is not accessible.");
  // Fail closed before any job, access record or dispatch exists: with no private worker, anything
  // not confirmed public is refused (without revealing whether a private repository exists).
  if (!PRIVATE_SCANNING_AVAILABLE) return fail(400, "not_found_or_private", PRIVATE_NOT_SCANNABLE);

  let user;
  try {
    user = await resolveAuthorizedUser(req, auth);
  } catch (err) {
    if (isMissingTable(err)) return fail(400, "not_found_or_private", "Repository not found, or it is not public.");
    throw err;
  }
  if (!user.ok) {
    if (user.code === "not_configured") return fail(400, "not_found_or_private", "Repository not found, or it is not public.");
    if (user.code === "not_connected") return fail(403, "authorization_required", PRIVATE_HINT);
    return fail(401, user.code, "Your GitHub authorization expired or was revoked. Connect GitHub again to scan private repositories.");
  }
  const access = await checkRepositoryAccess(user.token, owner, repo, auth.fetchImpl);
  if (access.status === "unauthorized") {
    await markRevoked(user.account, auth, "token_rejected");
    return fail(401, "authorization_revoked", "Your GitHub authorization was revoked. Connect GitHub again.");
  }
  if (access.status === "rate_limited") return fail(429, "github_rate_limited", "GitHub rate limit reached. Try again later.");
  if (access.status === "error") return fail(502, "github_unavailable", "Could not reach GitHub. Try again shortly.");
  if (access.status !== "ok" || !access.canRead || access.repoId === undefined) {
    return fail(
      400,
      "not_found_or_private",
      "This repository is not visible to your GitHub authorization. Authorize it for the VibeShield app on GitHub, then try again.",
    );
  }
  await auth.store.audit({
    action: "private_scan_submitted",
    outcome: "authorized",
    githubUserId: user.account.githubUserId,
    githubLogin: user.account.login,
    repository: access.fullName ?? `${owner}/${repo}`,
  });
  return { ok: true, repoId: access.repoId, isPrivate: Boolean(access.isPrivate), githubUserId: access.isPrivate ? user.account.githubUserId : null };
}
