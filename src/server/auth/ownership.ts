import { createHmac, randomBytes } from "node:crypto";
import { sha256Hex, safeEqual } from "./crypto";

/**
 * Scan ownership for anonymous users.
 *
 * Job IDs are read capabilities and are visible in public workflow logs, so they never authorize
 * changes. The browser that submitted a scan receives an HttpOnly owner grant: a random session ID
 * plus the job IDs it created, HMAC-signed by the server. Only the response that creates a job adds
 * it to the grant, so a grant can't be forged, extended to another job, or obtained from a URL.
 * Nothing is stored server-side, so this needs no database migration.
 */

const VERSION = "v1";
const MAX_JOBS = 30;

export type OwnerGrant = {
  /** Random 128-bit session identifier; its SHA-256 is the owner subject recorded on approvals. */
  sid: string;
  /** [jobId, issuedAtEpochSeconds] */
  jobs: [string, number][];
};

export type OwnershipConfig = {
  /** HMAC key for grants; null disables ownership (all changes are then refused). */
  key: Buffer | null;
  /** https origin → __Host- cookie with Secure. */
  appOrigin: string;
  /** Grant entries older than this are dropped (matches job retention). */
  ttlSeconds: number;
};

/**
 * Grant key: OWNER_SESSION_SECRET if set, else derived from SCAN_CALLBACK_SECRET with domain
 * separation (an HMAC under a fixed label), so the raw callback secret is never used as-is.
 */
export function ownerKeyFrom(env: { OWNER_SESSION_SECRET?: string; SCAN_CALLBACK_SECRET?: string }): Buffer | null {
  const dedicated = env.OWNER_SESSION_SECRET?.trim();
  if (dedicated && dedicated.length >= 32) return createHmac("sha256", dedicated).update("vibeshield/owner-grant/v1").digest();
  const base = env.SCAN_CALLBACK_SECRET?.trim();
  return base ? createHmac("sha256", base).update("vibeshield/owner-grant/v1").digest() : null;
}

export const ownerCookieName = (appOrigin: string) =>
  appOrigin.startsWith("https://") ? "__Host-vibeshield_owner" : "vibeshield_owner";

const sign = (payload: string, key: Buffer) => createHmac("sha256", key).update(`${VERSION}.${payload}`).digest("base64url");

export function encodeGrant(grant: OwnerGrant, key: Buffer): string {
  const payload = Buffer.from(JSON.stringify(grant)).toString("base64url");
  return `${payload}.${sign(payload, key)}`;
}

export function decodeGrant(value: string, key: Buffer, now: Date, ttlSeconds: number): OwnerGrant | null {
  const [payload, mac, extra] = value.split(".");
  if (!payload || !mac || extra !== undefined || !safeEqual(mac, sign(payload, key))) return null;
  try {
    const g = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as OwnerGrant;
    if (typeof g.sid !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(g.sid) || !Array.isArray(g.jobs)) return null;
    const cutoff = now.getTime() / 1000 - ttlSeconds;
    return {
      sid: g.sid,
      jobs: g.jobs.filter((j) => Array.isArray(j) && typeof j[0] === "string" && typeof j[1] === "number" && j[1] >= cutoff),
    };
  } catch {
    return null;
  }
}

function readCookie(req: Request, name: string): string | null {
  for (const part of (req.headers.get("cookie") ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=") || null;
  }
  return null;
}

export function readGrant(req: Request, cfg: OwnershipConfig, now = new Date()): OwnerGrant | null {
  if (!cfg.key) return null;
  const raw = readCookie(req, ownerCookieName(cfg.appOrigin));
  return raw ? decodeGrant(raw, cfg.key, now, cfg.ttlSeconds) : null;
}

/** Adds a newly created job to the requesting browser's grant (creating the grant if needed). */
export function grantCookieForNewJob(req: Request, jobId: string, cfg: OwnershipConfig, now = new Date()): string | null {
  if (!cfg.key) return null;
  const current = readGrant(req, cfg, now);
  const grant: OwnerGrant = {
    sid: current?.sid ?? randomBytes(16).toString("base64url"),
    jobs: [...(current?.jobs ?? []).filter(([id]) => id !== jobId), [jobId, Math.floor(now.getTime() / 1000)] as [string, number]].slice(-MAX_JOBS),
  };
  const secure = cfg.appOrigin.startsWith("https://") ? "; Secure" : "";
  return `${ownerCookieName(cfg.appOrigin)}=${encodeGrant(grant, cfg.key)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${cfg.ttlSeconds}${secure}`;
}

export type OwnerCheck = { owner: true; subject: string } | { owner: false; reason: "no_grant" | "not_owner" | "unavailable" };

/** Whether this request comes from the browser that created `jobId`. */
export function checkOwner(req: Request, jobId: string, cfg: OwnershipConfig, now = new Date()): OwnerCheck {
  if (!cfg.key) return { owner: false, reason: "unavailable" };
  const grant = readGrant(req, cfg, now);
  if (!grant) return { owner: false, reason: "no_grant" };
  return grant.jobs.some(([id]) => id === jobId) ? { owner: true, subject: sha256Hex(grant.sid) } : { owner: false, reason: "not_owner" };
}

/**
 * CSRF defence for cookie-authorized changes (in addition to SameSite=Lax): the browser-set
 * Sec-Fetch-Site must be same-origin, or the Origin must be this app's origin.
 */
export function isSameOriginMutation(req: Request, appOrigin: string): boolean {
  const site = req.headers.get("sec-fetch-site");
  if (site) return site === "same-origin";
  const origin = req.headers.get("origin");
  return origin === appOrigin;
}
