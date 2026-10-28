import type { GithubAppConfig } from "../config";
import type { FetchLike } from "../github";

/**
 * GitHub App user-to-server client. VibeShield acts only with the user's own token, which GitHub
 * limits to the intersection of the user's permissions and the repositories the user selected for
 * the app installation. No app private key or installation token is used, so the app can never
 * grant a user more access than they personally have.
 */

const API = "https://api.github.com";
const OAUTH = "https://github.com/login/oauth";

export type TokenSet = {
  accessToken: string;
  accessTokenExpiresAt: Date | null;
  refreshToken: string | null;
  refreshTokenExpiresAt: Date | null;
};

export type GithubUser = { id: number; login: string; avatarUrl: string | null };

export type RepoAccess = {
  /** "ok" when the repository is visible to the user's token. */
  status: "ok" | "not_found" | "unauthorized" | "rate_limited" | "error";
  repoId?: number;
  fullName?: string;
  isPrivate?: boolean;
  defaultBranch?: string;
  /** The user's own role on the repository, as GitHub reports it for this token. */
  canRead?: boolean;
  canPush?: boolean;
  /** The repository is selected in an installation of this app that the user can access. */
  installed?: boolean;
  installationId?: number;
  installationAccount?: string;
  /** That installation grants Contents and Pull requests write. */
  appCanWrite?: boolean;
};

export class GithubAuthError extends Error {
  constructor(
    readonly code:
      | "bad_verification_code"
      | "bad_refresh_token"
      | "unauthorized"
      | "rate_limited"
      | "oauth_error"
      | "network_error",
  ) {
    super(code);
  }
}

const userHeaders = (token: string) => ({
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "VibeShield-AI-GitHub-App",
  "X-GitHub-Api-Version": "2022-11-28",
});

export function authorizeUrl(cfg: GithubAppConfig, state: string, codeChallenge: string): string {
  const q = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.callbackUrl,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    allow_signup: "true",
  });
  return `https://github.com/login/oauth/authorize?${q}`;
}

/** GitHub returns `state` to the app's Setup URL after the installation flow. */
export function installUrl(cfg: GithubAppConfig, state: string): string {
  return `https://github.com/apps/${encodeURIComponent(cfg.slug)}/installations/new?state=${encodeURIComponent(state)}`;
}

function toTokenSet(body: Record<string, unknown>, now: Date): TokenSet {
  const at = (secs: unknown) => (typeof secs === "number" && secs > 0 ? new Date(now.getTime() + secs * 1000) : null);
  if (typeof body.access_token !== "string" || !body.access_token) throw new GithubAuthError("oauth_error");
  return {
    accessToken: body.access_token,
    accessTokenExpiresAt: at(body.expires_in),
    refreshToken: typeof body.refresh_token === "string" ? body.refresh_token : null,
    refreshTokenExpiresAt: at(body.refresh_token_expires_in),
  };
}

async function oauthPost(fetchImpl: FetchLike, params: Record<string, string>): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetchImpl(`${OAUTH}/access_token`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "VibeShield-AI-GitHub-App" },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw new GithubAuthError("network_error");
  }
  const body = ((await res.json().catch(() => null)) ?? {}) as Record<string, unknown>;
  if (!res.ok) throw new GithubAuthError(res.status === 429 ? "rate_limited" : "oauth_error");
  return body;
}

export async function exchangeCode(
  cfg: GithubAppConfig,
  code: string,
  codeVerifier: string,
  fetchImpl: FetchLike,
  now = new Date(),
): Promise<TokenSet> {
  const body = await oauthPost(fetchImpl, {
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    code,
    redirect_uri: cfg.callbackUrl,
    code_verifier: codeVerifier,
  });
  if (body.error) throw new GithubAuthError(body.error === "bad_verification_code" ? "bad_verification_code" : "oauth_error");
  return toTokenSet(body, now);
}

export async function refreshUserToken(
  cfg: GithubAppConfig,
  refreshToken: string,
  fetchImpl: FetchLike,
  now = new Date(),
): Promise<TokenSet> {
  const body = await oauthPost(fetchImpl, {
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  if (body.error) throw new GithubAuthError(body.error === "bad_refresh_token" ? "bad_refresh_token" : "oauth_error");
  return toTokenSet(body, now);
}

/** Revokes the user's whole authorization of this app (all of its tokens). Best effort. */
export async function revokeGrant(cfg: GithubAppConfig, accessToken: string, fetchImpl: FetchLike): Promise<boolean> {
  try {
    const res = await fetchImpl(`${API}/applications/${encodeURIComponent(cfg.clientId)}/grant`, {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64")}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "VibeShield-AI-GitHub-App",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({ access_token: accessToken }),
      signal: AbortSignal.timeout(15_000),
    });
    return res.status === 204 || res.status === 404;
  } catch {
    return false;
  }
}

async function apiGet(fetchImpl: FetchLike, token: string, path: string): Promise<{ status: number; body: unknown }> {
  let res: Response;
  try {
    res = await fetchImpl(`${API}${path}`, { headers: userHeaders(token), signal: AbortSignal.timeout(15_000) });
  } catch {
    throw new GithubAuthError("network_error");
  }
  if (res.status === 401) throw new GithubAuthError("unauthorized");
  if (res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0")) {
    throw new GithubAuthError("rate_limited");
  }
  return { status: res.status, body: await res.json().catch(() => null) };
}

export async function getUser(token: string, fetchImpl: FetchLike): Promise<GithubUser> {
  const r = await apiGet(fetchImpl, token, "/user");
  const b = r.body as { id?: number; login?: string; avatar_url?: string } | null;
  if (r.status !== 200 || typeof b?.id !== "number" || typeof b.login !== "string") throw new GithubAuthError("oauth_error");
  return { id: b.id, login: b.login, avatarUrl: typeof b.avatar_url === "string" ? b.avatar_url.slice(0, 300) : null };
}

type Installation = {
  id: number;
  account?: { login?: string };
  permissions?: Record<string, string>;
};

export async function listUserInstallations(token: string, fetchImpl: FetchLike): Promise<Installation[]> {
  const out: Installation[] = [];
  for (let page = 1; page <= 5; page++) {
    const r = await apiGet(fetchImpl, token, `/user/installations?per_page=100&page=${page}`);
    const list = (r.body as { installations?: Installation[] } | null)?.installations ?? [];
    if (r.status !== 200) break;
    out.push(...list);
    if (list.length < 100) break;
  }
  return out;
}

async function installationHasRepo(token: string, installationId: number, repoId: number, fetchImpl: FetchLike) {
  for (let page = 1; page <= 10; page++) {
    const r = await apiGet(fetchImpl, token, `/user/installations/${installationId}/repositories?per_page=100&page=${page}`);
    const repos = (r.body as { repositories?: { id: number }[] } | null)?.repositories ?? [];
    if (r.status !== 200) return false;
    if (repos.some((x) => x.id === repoId)) return true;
    if (repos.length < 100) return false;
  }
  return false;
}

/**
 * What the user's token can do with one repository, read live from GitHub. Owner/name come from
 * the stored scan, never from the browser; callers compare `repoId` with the scan's stored ID.
 */
export async function checkRepositoryAccess(
  token: string,
  owner: string,
  repo: string,
  fetchImpl: FetchLike,
): Promise<RepoAccess> {
  try {
    const r = await apiGet(fetchImpl, token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
    if (r.status === 404 || r.status === 403) return { status: "not_found" };
    if (r.status !== 200) return { status: "error" };
    const b = r.body as {
      id: number;
      full_name: string;
      private: boolean;
      default_branch: string;
      permissions?: { pull?: boolean; push?: boolean };
    };
    const access: RepoAccess = {
      status: "ok",
      repoId: b.id,
      fullName: b.full_name,
      isPrivate: b.private,
      defaultBranch: b.default_branch,
      canRead: b.permissions?.pull ?? !b.private,
      canPush: b.permissions?.push === true,
      installed: false,
      appCanWrite: false,
    };
    const accountLogin = b.full_name.split("/")[0].toLowerCase();
    for (const inst of await listUserInstallations(token, fetchImpl)) {
      if (inst.account?.login?.toLowerCase() !== accountLogin) continue;
      if (!(await installationHasRepo(token, inst.id, b.id, fetchImpl))) continue;
      access.installed = true;
      access.installationId = inst.id;
      access.installationAccount = inst.account.login;
      access.appCanWrite = inst.permissions?.contents === "write" && inst.permissions?.pull_requests === "write";
      break;
    }
    return access;
  } catch (err) {
    if (err instanceof GithubAuthError) {
      return { status: err.code === "unauthorized" ? "unauthorized" : err.code === "rate_limited" ? "rate_limited" : "error" };
    }
    return { status: "error" };
  }
}
