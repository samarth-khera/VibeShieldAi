import type { GithubAppConfig } from "../config";
import type { FetchLike } from "../github";
import { log } from "../errors";
import { decryptSecret, encryptSecret, pkceChallenge, randomToken, sha256Hex } from "./crypto";
import {
  authorizeUrl,
  exchangeCode,
  getUser,
  GithubAuthError,
  installUrl,
  listUserInstallations,
  refreshUserToken,
  revokeGrant,
  type TokenSet,
} from "./github-app";
import type { AccountRecord, AuthStore, SessionRecord } from "./store";

export type AuthDeps = {
  store: AuthStore;
  /** Undefined when the operator has not configured the GitHub App. */
  app: GithubAppConfig | undefined;
  fetchImpl: FetchLike;
  now?: () => Date;
};

const SESSION_TTL_MS = 30 * 24 * 3600_000;
const STATE_TTL_MS = 10 * 60_000;
/** Refresh a little before GitHub's 8-hour user-token expiry. */
const REFRESH_SKEW_MS = 2 * 60_000;
const RETURN_TO_RE = /^\/(report\/[A-Za-z0-9_-]{1,64})?(\?[A-Za-z0-9_=&%.-]{0,200})?$/;

const nowOf = (deps: AuthDeps) => (deps.now ?? (() => new Date()))();

export function cookieName(app: GithubAppConfig): string {
  // __Host- requires Secure, Path=/ and no Domain: the cookie can't be set or shadowed by a subdomain.
  return app.appOrigin.startsWith("https://") ? "__Host-vibeshield_session" : "vibeshield_session";
}

function sessionCookie(app: GithubAppConfig, value: string, maxAgeSeconds: number): string {
  const secure = app.appOrigin.startsWith("https://") ? "; Secure" : "";
  return `${cookieName(app)}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`;
}

function readCookie(req: Request, name: string): string | null {
  for (const part of (req.headers.get("cookie") ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) {
      const value = v.join("=");
      return /^[A-Za-z0-9_-]{20,100}$/.test(value) ? value : null;
    }
  }
  return null;
}

export function safeReturnTo(raw: string | null | undefined): string {
  return raw && RETURN_TO_RE.test(raw) ? raw : "/";
}

function withParam(path: string, key: string, value: string): string {
  return `${path}${path.includes("?") ? "&" : "?"}${key}=${encodeURIComponent(value)}`;
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ Location: location, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
  for (const c of cookies) headers.append("Set-Cookie", c);
  return new Response(null, { status: 302, headers });
}

export async function loadSession(req: Request, deps: AuthDeps): Promise<SessionRecord | null> {
  if (!deps.app) return null;
  const token = readCookie(req, cookieName(deps.app));
  return token ? deps.store.getSession(sha256Hex(token), nowOf(deps)) : null;
}

async function newSession(deps: AuthDeps & { app: GithubAppConfig }): Promise<{ id: string; cookie: string }> {
  const token = randomToken();
  const id = sha256Hex(token);
  await deps.store.createSession(id, new Date(nowOf(deps).getTime() + SESSION_TTL_MS));
  return { id, cookie: sessionCookie(deps.app, token, SESSION_TTL_MS / 1000) };
}

/**
 * Checks that a state-changing request was sent by this site's own pages (SameSite=Lax already
 * withholds the cookie from cross-site POSTs; this also rejects same-site sibling origins).
 */
export function isSameOrigin(req: Request, app: GithubAppConfig): boolean {
  const origin = req.headers.get("origin");
  if (origin) return origin === app.appOrigin;
  return req.headers.get("sec-fetch-site") === "same-origin";
}

/** GET /api/auth/github/start: begins the real GitHub user-authorization flow. */
export async function startConnect(req: Request, deps: AuthDeps): Promise<Response> {
  if (!deps.app) return redirect("/?github=not_configured");
  const app = deps.app;
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  const cookies: string[] = [];
  const session = await loadSession(req, deps);
  let sessionId = session?.id;
  if (!sessionId) {
    const created = await newSession({ ...deps, app });
    sessionId = created.id;
    cookies.push(created.cookie);
  }
  const state = randomToken();
  const verifier = randomToken(48);
  await deps.store.createState({
    id: sha256Hex(state),
    sessionId,
    purpose: "connect",
    returnTo,
    codeVerifierEnc: encryptSecret(verifier, app.encryptionKey),
    expiresAt: new Date(nowOf(deps).getTime() + STATE_TTL_MS),
  });
  return redirect(authorizeUrl(app, state, pkceChallenge(verifier)), cookies);
}

/** GET /api/auth/github/callback: GitHub's redirect after the user authorizes (or declines). */
export async function handleCallback(req: Request, deps: AuthDeps): Promise<Response> {
  if (!deps.app) return redirect("/?github=not_configured");
  const app = deps.app;
  const url = new URL(req.url);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  const session = await loadSession(req, deps);
  if (!state || !session) return redirect("/?github=error&reason=state_invalid");

  // Single use and bound to the browser session that started the flow: blocks CSRF, replay and
  // "log the victim into the attacker's GitHub account" session swapping.
  const st = await deps.store.consumeState(sha256Hex(state), session.id, "connect", nowOf(deps));
  if (!st) {
    await deps.store.audit({ action: "github_connect", outcome: "rejected", detail: "state_invalid" });
    return redirect("/?github=error&reason=state_invalid");
  }
  if (url.searchParams.get("error")) return redirect(withParam(st.returnTo, "github", "cancelled"));
  if (!code || !st.codeVerifierEnc) return redirect(withParam(st.returnTo, "github", "error"));

  let tokens: TokenSet;
  let user;
  try {
    tokens = await exchangeCode(app, code, decryptSecret(st.codeVerifierEnc, app.encryptionKey), deps.fetchImpl, nowOf(deps));
    user = await getUser(tokens.accessToken, deps.fetchImpl);
  } catch (err) {
    const reason = err instanceof GithubAuthError ? err.code : "oauth_error";
    log("warn", "github_connect_failed", { reason });
    await deps.store.audit({ action: "github_connect", outcome: "failed", detail: reason });
    return redirect(withParam(withParam(st.returnTo, "github", "error"), "reason", reason));
  }

  const account = await deps.store.upsertAccount({
    githubUserId: user.id,
    login: user.login,
    avatarUrl: user.avatarUrl,
    ...encryptTokens(tokens, app),
  });
  // Rotate the session on privilege change so a pre-auth session ID can't be fixated.
  const rotated = await newSession({ ...deps, app });
  await deps.store.linkSession(rotated.id, account.id);
  await deps.store.revokeSession(session.id, nowOf(deps));
  await deps.store.audit({ action: "github_connect", outcome: "success", githubUserId: user.id, githubLogin: user.login });
  return redirect(withParam(st.returnTo, "github", "connected"), [rotated.cookie]);
}

function encryptTokens(t: TokenSet, app: GithubAppConfig) {
  return {
    accessTokenEnc: encryptSecret(t.accessToken, app.encryptionKey),
    accessTokenExpiresAt: t.accessTokenExpiresAt,
    refreshTokenEnc: t.refreshToken ? encryptSecret(t.refreshToken, app.encryptionKey) : null,
    refreshTokenExpiresAt: t.refreshTokenExpiresAt,
  };
}

/** GET /api/auth/github/install: sends a connected user to the app's real installation page. */
export async function startInstall(req: Request, deps: AuthDeps): Promise<Response> {
  if (!deps.app) return redirect("/?github=not_configured");
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  const session = await loadSession(req, deps);
  if (!session?.account) return redirect(withParam(returnTo, "github", "connect_first"));
  const state = randomToken();
  await deps.store.createState({
    id: sha256Hex(state),
    sessionId: session.id,
    purpose: "install",
    returnTo,
    codeVerifierEnc: null,
    expiresAt: new Date(nowOf(deps).getTime() + STATE_TTL_MS),
  });
  return redirect(installUrl(deps.app, state));
}

/**
 * GET /api/auth/github/setup: GitHub's redirect after installing or changing the app. The
 * `installation_id` in the URL is never trusted: it must appear in the installations GitHub lists
 * for this user's own token.
 */
export async function handleSetup(req: Request, deps: AuthDeps): Promise<Response> {
  if (!deps.app) return redirect("/?github=not_configured");
  const url = new URL(req.url);
  const state = url.searchParams.get("state");
  const action = url.searchParams.get("setup_action");
  const installationId = Number(url.searchParams.get("installation_id"));
  const session = await loadSession(req, deps);
  // Changes made from GitHub's settings page arrive without our state; acknowledge without trusting.
  if (!state || !session) return redirect("/?github=installation_updated");
  const st = await deps.store.consumeState(sha256Hex(state), session.id, "install", nowOf(deps));
  if (!st) return redirect("/?github=error&reason=state_invalid");
  const account = session.account;
  if (!account) return redirect(withParam(st.returnTo, "github", "connect_first"));
  if (action === "request") {
    await deps.store.audit({ action: "github_install", outcome: "requested", githubUserId: account.githubUserId, githubLogin: account.login });
    return redirect(withParam(st.returnTo, "github", "install_requested"));
  }
  const token = await getUserToken(account, deps);
  if ("error" in token) return redirect(withParam(st.returnTo, "github", token.error));
  try {
    const installations = await listUserInstallations(token.token, deps.fetchImpl);
    const verified = Number.isSafeInteger(installationId) && installations.some((i) => i.id === installationId);
    await deps.store.audit({
      action: "github_install",
      outcome: verified ? "verified" : "unverified",
      githubUserId: account.githubUserId,
      githubLogin: account.login,
      detail: verified ? `installation ${installationId}` : "installation not visible to user",
    });
    return redirect(withParam(st.returnTo, "github", verified ? "installed" : "installation_not_verified"));
  } catch (err) {
    if (err instanceof GithubAuthError && err.code === "unauthorized") await markRevoked(account, deps, "token_rejected");
    return redirect(withParam(st.returnTo, "github", "error"));
  }
}

/** POST /api/auth/github/disconnect: revokes the app authorization at GitHub and forgets the tokens. */
export async function disconnect(req: Request, deps: AuthDeps): Promise<Response> {
  const json = (status: number, body: unknown) =>
    Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
  if (!deps.app) return json(404, { error: { code: "not_configured", message: "GitHub authorization is not configured." } });
  if (!isSameOrigin(req, deps.app)) return json(403, { error: { code: "forbidden_origin", message: "Cross-site request refused." } });
  const session = await loadSession(req, deps);
  const account = session?.account;
  if (!account) return json(200, { data: { connected: false } });
  let revoked = false;
  try {
    revoked = await revokeGrant(deps.app, decryptSecret(account.accessTokenEnc, deps.app.encryptionKey), deps.fetchImpl);
  } catch {
    revoked = false;
  }
  await deps.store.deleteAccount(account.id);
  await deps.store.audit({
    action: "github_disconnect",
    outcome: revoked ? "revoked" : "local_only",
    githubUserId: account.githubUserId,
    githubLogin: account.login,
  });
  return json(200, { data: { connected: false, revokedAtGitHub: revoked } });
}

export async function markRevoked(account: AccountRecord, deps: AuthDeps, reason: string): Promise<void> {
  await deps.store.deleteAccount(account.id);
  await deps.store.audit({
    action: "github_authorization_lost",
    outcome: reason,
    githubUserId: account.githubUserId,
    githubLogin: account.login,
  });
}

export type UserTokenResult = { token: string } | { error: "authorization_expired" | "authorization_revoked" };

/** Returns a currently valid user token, refreshing it if needed. Never returns an expired token. */
export async function getUserToken(account: AccountRecord, deps: AuthDeps): Promise<UserTokenResult> {
  const app = deps.app;
  if (!app) return { error: "authorization_revoked" };
  const now = nowOf(deps);
  // Tokens encrypted under a rotated key can't be read: treat as expired and ask to reconnect.
  const open = (enc: string) => {
    try {
      return decryptSecret(enc, app.encryptionKey);
    } catch {
      return null;
    }
  };
  const expired = account.accessTokenExpiresAt && account.accessTokenExpiresAt.getTime() - REFRESH_SKEW_MS <= now.getTime();
  if (!expired) {
    const token = open(account.accessTokenEnc);
    if (token) return { token };
    await markRevoked(account, deps, "undecryptable");
    return { error: "authorization_expired" };
  }

  const refreshUsable =
    account.refreshTokenEnc && (!account.refreshTokenExpiresAt || account.refreshTokenExpiresAt.getTime() > now.getTime());
  if (!refreshUsable) {
    await markRevoked(account, deps, "token_expired");
    return { error: "authorization_expired" };
  }
  try {
    const refresh = open(account.refreshTokenEnc!);
    if (!refresh) {
      await markRevoked(account, deps, "undecryptable");
      return { error: "authorization_expired" };
    }
    const t = await refreshUserToken(app, refresh, deps.fetchImpl, now);
    const saved = await deps.store.updateTokens(account.id, encryptTokens(t, app), account.updatedAt);
    if (!saved) {
      // Another request refreshed first; GitHub refresh tokens are single use, so use its result.
      const fresh = await deps.store.getAccount(account.id);
      const token = fresh ? open(fresh.accessTokenEnc) : null;
      return token ? { token } : { error: "authorization_revoked" };
    }
    return { token: t.accessToken };
  } catch (err) {
    if (err instanceof GithubAuthError && err.code === "bad_refresh_token") {
      const fresh = await deps.store.getAccount(account.id);
      const token = fresh && fresh.updatedAt.getTime() !== account.updatedAt.getTime() ? open(fresh.accessTokenEnc) : null;
      if (token) return { token };
      await markRevoked(account, deps, "refresh_rejected");
      return { error: "authorization_expired" };
    }
    // Transient failure: report expired for this request without discarding the account.
    return { error: "authorization_expired" };
  }
}

export type AuthorizedUser =
  | { ok: true; account: AccountRecord; token: string; sessionId: string }
  | { ok: false; code: "not_configured" | "not_connected" | "authorization_expired" | "authorization_revoked" };

/** The current browser session's GitHub user with a valid token, or why there is none. */
export async function resolveAuthorizedUser(req: Request, deps: AuthDeps): Promise<AuthorizedUser> {
  if (!deps.app) return { ok: false, code: "not_configured" };
  const session = await loadSession(req, deps);
  if (!session?.account) return { ok: false, code: "not_connected" };
  const t = await getUserToken(session.account, deps);
  if ("error" in t) return { ok: false, code: t.error };
  return { ok: true, account: session.account, token: t.token, sessionId: session.id };
}
