import type { JobRecord } from "../job-store";
import { AUTH_FAILURE, authorizeRepository, isMissingTable, loadScanAccess, type AuthFailureCode } from "./repository-access";
import {
  installationSettingsUrl,
  repositoryAuthorizationState,
  STATE_MESSAGES,
  type RepositoryAuthorizationState,
} from "./repository-authorization";
import { loadSession, safeReturnTo, type AuthDeps } from "./service";

export type GithubStatus = {
  configured: boolean;
  /** Why the feature is unavailable on this deployment, when it is. */
  unavailableReason?: "not_configured" | "setup_incomplete";
  connected: boolean;
  user?: { login: string; avatarUrl: string | null };
  repository?: {
    fullName: string;
    defaultBranch?: string;
    isPrivate?: boolean;
    canRead: boolean;
    canPush: boolean;
    installed: boolean;
    appCanWrite: boolean;
    readyToWrite: boolean;
    reason?: AuthFailureCode;
    message?: string;
    /** Canonical GitHub repository ID, read live from GitHub for this user. */
    id?: number;
    ownerType?: "User" | "Organization";
    canAdmin?: boolean;
    /** Per-repository authorization: what is missing and whether it can be granted from VibeShield. */
    authorization?: {
      state: RepositoryAuthorizationState;
      message: string;
      installationId?: number;
      installationAccount?: string;
      installationSettingsUrl?: string;
    };
  };
  /** Set when a stored authorization stopped working (expired, revoked). */
  authorizationProblem?: AuthFailureCode;
  links: { connect: string; install: string; manageInstallations: string };
};

/** Read-only view of the current session's GitHub authorization for one scan's repository. */
export async function githubStatus(
  req: Request,
  deps: AuthDeps,
  job: Pick<JobRecord, "id" | "owner" | "repo"> | null,
): Promise<GithubStatus> {
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo") ?? (job ? `/report/${job.id}` : "/"));
  const links = {
    connect: `/api/auth/github/start?returnTo=${encodeURIComponent(returnTo)}`,
    install: `/api/auth/github/install?returnTo=${encodeURIComponent(returnTo)}`,
    manageInstallations: "https://github.com/settings/installations",
  };
  if (!deps.app) return { configured: false, unavailableReason: "not_configured", connected: false, links };
  try {
    const session = await loadSession(req, deps);
    if (!session?.account) return { configured: true, connected: false, links };
    const user = { login: session.account.login, avatarUrl: session.account.avatarUrl };
    if (!job) return { configured: true, connected: true, user, links };

    const scanAccess = await loadScanAccess(deps, job.id);
    const auth = await authorizeRepository(req, deps, job, scanAccess, "write");
    if (!auth.ok && (auth.code === "authorization_expired" || auth.code === "authorization_revoked" || auth.code === "not_connected")) {
      return { configured: true, connected: false, authorizationProblem: auth.code, links };
    }
    const a = auth.access;
    return {
      configured: true,
      connected: true,
      user,
      repository: {
        fullName: a?.fullName ?? `${job.owner}/${job.repo}`,
        defaultBranch: a?.defaultBranch,
        isPrivate: a?.isPrivate,
        canRead: Boolean(a?.canRead) && (auth.ok || auth.code !== "repository_changed"),
        canPush: Boolean(a?.canPush),
        installed: Boolean(a?.installed),
        appCanWrite: Boolean(a?.appCanWrite),
        readyToWrite: auth.ok,
        ...(auth.ok ? {} : { reason: auth.code, message: AUTH_FAILURE[auth.code].message }),
        ...(a?.status === "ok" && (auth.ok || auth.code !== "repository_changed")
          ? (() => {
              const state = repositoryAuthorizationState(a);
              return {
                id: a.repoId,
                ownerType: a.ownerType,
                canAdmin: Boolean(a.canAdmin),
                authorization: {
                  state,
                  message: STATE_MESSAGES[state],
                  installationId: a.ownerInstallation?.id,
                  installationAccount: a.ownerInstallation?.accountLogin,
                  installationSettingsUrl: installationSettingsUrl(a) ?? undefined,
                },
              };
            })()
          : {}),
      },
      links,
    };
  } catch (err) {
    if (isMissingTable(err)) return { configured: false, unavailableReason: "setup_incomplete", connected: false, links };
    throw err;
  }
}
