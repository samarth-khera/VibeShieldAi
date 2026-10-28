import type { JobRecord } from "../job-store";
import { checkRepositoryAccess, type RepoAccess } from "./github-app";
import { markRevoked, resolveAuthorizedUser, type AuthDeps } from "./service";
import type { AccountRecord, ScanAccessRecord } from "./store";

export type AuthFailureCode =
  | "not_configured"
  | "not_connected"
  | "authorization_expired"
  | "authorization_revoked"
  | "repository_not_found"
  | "repository_changed"
  | "not_installed"
  | "no_push_permission"
  | "app_lacks_permission"
  | "rate_limited"
  | "github_unavailable";

export const AUTH_FAILURE: Record<AuthFailureCode, { status: number; message: string }> = {
  not_configured: { status: 503, message: "GitHub authorization is not configured on this deployment yet." },
  not_connected: { status: 401, message: "Connect your GitHub account first." },
  authorization_expired: { status: 401, message: "Your GitHub authorization expired. Connect GitHub again." },
  authorization_revoked: { status: 401, message: "Your GitHub authorization was revoked. Connect GitHub again." },
  repository_not_found: { status: 403, message: "Your GitHub account cannot see this repository." },
  repository_changed: {
    status: 409,
    message: "The repository on GitHub is no longer the one that was scanned (renamed, transferred or recreated).",
  },
  not_installed: {
    status: 403,
    message: "The VibeShield GitHub App is not installed on this repository. Authorize this repository on GitHub first.",
  },
  no_push_permission: { status: 403, message: "Your GitHub account does not have write access to this repository." },
  app_lacks_permission: {
    status: 403,
    message: "The app installation lacks Contents or Pull requests write permission. An administrator must approve the updated permissions.",
  },
  rate_limited: { status: 429, message: "GitHub API rate limit reached. Try again later." },
  github_unavailable: { status: 502, message: "Could not verify access with GitHub. Nothing was changed; retrying is safe." },
};

export type RepositoryAuthorization =
  | { ok: true; account: AccountRecord; token: string; access: RepoAccess }
  | { ok: false; code: AuthFailureCode; account?: AccountRecord; access?: RepoAccess };

/**
 * Live check, on every call, that the current session's own GitHub user may write to the exact
 * repository of this scan through the app installation. Nothing from an earlier page state is reused.
 */
export async function authorizeRepository(
  req: Request,
  deps: AuthDeps,
  job: Pick<JobRecord, "owner" | "repo">,
  scanAccess: ScanAccessRecord | null,
  need: "read" | "write",
): Promise<RepositoryAuthorization> {
  const user = await resolveAuthorizedUser(req, deps);
  if (!user.ok) return { ok: false, code: user.code };
  const access = await checkRepositoryAccess(user.token, job.owner, job.repo, deps.fetchImpl);
  const fail = (code: AuthFailureCode) => ({ ok: false as const, code, account: user.account, access });
  if (access.status === "unauthorized") {
    await markRevoked(user.account, deps, "token_rejected");
    return { ok: false, code: "authorization_revoked" };
  }
  if (access.status === "rate_limited") return fail("rate_limited");
  if (access.status === "error") return fail("github_unavailable");
  if (access.status === "not_found") return fail("repository_not_found");
  if (scanAccess && access.repoId !== scanAccess.githubRepoId) return fail("repository_changed");
  if (!access.canRead) return fail("repository_not_found");
  if (need === "write") {
    if (!access.installed) return fail("not_installed");
    if (!access.canPush) return fail("no_push_permission");
    if (!access.appCanWrite) return fail("app_lacks_permission");
  }
  return { ok: true, account: user.account, token: user.token, access };
}

/** Prisma's "table does not exist": the authorization migration has not been applied yet. */
export function isMissingTable(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "P2021";
}

export async function loadScanAccess(deps: AuthDeps, jobId: string): Promise<ScanAccessRecord | null> {
  if (!deps.app) return null;
  try {
    return await deps.store.getScanAccess(jobId);
  } catch (err) {
    if (isMissingTable(err)) return null; // no private scans can exist without the table
    throw err;
  }
}

/**
 * Private scans are visible only to the GitHub user who authorized them, and only while that user
 * still has access. Returns a Response to send instead, or null when access is allowed. Public
 * scans keep the existing capability model (the unguessable job ID).
 */
export async function checkJobAccess(
  req: Request,
  deps: AuthDeps,
  job: Pick<JobRecord, "id" | "owner" | "repo">,
  opts: { live?: boolean } = {},
): Promise<{ denied: Response } | { denied: null; privateToken?: string; scanAccess: ScanAccessRecord | null }> {
  const scanAccess = await loadScanAccess(deps, job.id);
  if (!scanAccess?.isPrivate) return { denied: null, scanAccess };
  const notFound = Response.json(
    { error: { code: "not_found", message: "Scan job not found." } },
    { status: 404, headers: { "Cache-Control": "no-store" } },
  );
  const user = await resolveAuthorizedUser(req, deps);
  if (!user.ok || user.account.githubUserId !== scanAccess.githubUserId) return { denied: notFound };
  if (!opts.live) return { denied: null, privateToken: user.token, scanAccess };
  const auth = await authorizeRepository(req, deps, job, scanAccess, "read");
  if (!auth.ok) {
    const f = AUTH_FAILURE[auth.code];
    return {
      denied: Response.json({ error: { code: auth.code, message: f.message } }, { status: f.status, headers: { "Cache-Control": "no-store" } }),
    };
  }
  return { denied: null, privateToken: auth.token, scanAccess };
}
