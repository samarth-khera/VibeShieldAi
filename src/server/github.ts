import path from "node:path";
import { RetrievalError } from "./errors";
import type { ServerConfig } from "./config";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** The only hosts the server is ever allowed to contact. */
export const API_HOST = "api.github.com";
export const ARCHIVE_HOST = "codeload.github.com";
export const ALLOWED_HOSTS: ReadonlySet<string> = new Set([API_HOST, ARCHIVE_HOST]);
const MAX_REDIRECTS = 3;

export type RepoMetadata = {
  /** GitHub's immutable repository ID. */
  id: number;
  fullName: string;
  defaultBranch: string;
  description: string | null;
  sizeKb: number;
  stars: number;
  language: string | null;
};

/** Throws unless `url` is https, on an approved GitHub host, without credentials or a custom port. */
export function assertApprovedUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new RetrievalError("download_failed", "redirect_rejected", "GitHub returned an unexpected redirect.");
  }
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname) || u.username || u.password || u.port) {
    throw new RetrievalError("download_failed", "redirect_rejected", "GitHub returned an unexpected redirect.");
  }
  return u;
}

/** fetch() wrapper that follows redirects manually, re-validating every hop against the allow-list. */
export async function safeFetch(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  let current = assertApprovedUrl(url).toString();
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let res: Response;
    try {
      res = await fetchImpl(current, { ...init, redirect: "manual", signal });
    } catch {
      throw new RetrievalError("download_failed", signal.aborted ? "timeout" : "network_error", signal.aborted ? "Retrieval timed out." : "Could not reach GitHub.");
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      await res.body?.cancel().catch(() => undefined);
      if (!loc) throw new RetrievalError("download_failed", "redirect_rejected", "GitHub returned an unexpected redirect.");
      current = assertApprovedUrl(new URL(loc, current).toString()).toString();
      continue;
    }
    return res;
  }
  throw new RetrievalError("download_failed", "too_many_redirects", "GitHub returned too many redirects.");
}

function headers(config: ServerConfig, accept: string): Record<string, string> {
  const h: Record<string, string> = {
    Accept: accept,
    "User-Agent": "VibeShieldAI-Retriever/0.1",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  // The token is only ever sent to approved GitHub hosts (enforced by safeFetch).
  if (config.githubToken) h.Authorization = `Bearer ${config.githubToken}`;
  return h;
}

function mapHttpFailure(res: Response): RetrievalError {
  const remaining = res.headers.get("x-ratelimit-remaining");
  if (res.status === 404 || res.status === 451) {
    return new RetrievalError("invalid_repository", "not_found_or_private", "Repository not found, or it is not public.");
  }
  if (res.status === 409) {
    return new RetrievalError("invalid_repository", "empty_repository", "The repository is empty.");
  }
  if (res.status === 429 || (res.status === 403 && remaining === "0")) {
    return new RetrievalError("download_failed", "github_rate_limited", "GitHub rate limit reached. Try again later.");
  }
  if (res.status === 403) {
    return new RetrievalError("invalid_repository", "access_denied", "Repository is not accessible.");
  }
  return new RetrievalError("download_failed", "github_error", "GitHub returned an error. Try again later.");
}

export async function fetchRepoMetadata(
  fetchImpl: FetchLike,
  owner: string,
  repo: string,
  config: ServerConfig,
  signal: AbortSignal,
): Promise<RepoMetadata> {
  const url = `https://${API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const res = await safeFetch(fetchImpl, url, { headers: headers(config, "application/vnd.github+json") }, signal);
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    throw mapHttpFailure(res);
  }
  let body: Record<string, unknown>;
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    throw new RetrievalError("download_failed", "github_error", "GitHub returned an unreadable response.");
  }
  if (body.private === true || (typeof body.visibility === "string" && body.visibility !== "public")) {
    throw new RetrievalError("invalid_repository", "not_found_or_private", "Repository not found, or it is not public.");
  }
  if (body.disabled === true) {
    throw new RetrievalError("invalid_repository", "disabled", "This repository is disabled.");
  }
  const defaultBranch = typeof body.default_branch === "string" ? body.default_branch : "";
  if (!defaultBranch || typeof body.full_name !== "string") {
    throw new RetrievalError("download_failed", "github_error", "GitHub returned an unexpected response.");
  }
  const sizeKb = typeof body.size === "number" ? body.size : 0;
  if (sizeKb > config.maxRepoSizeKb) {
    throw new RetrievalError("rejected_by_limits", "repo_too_large", "Repository is larger than the supported size limit.");
  }
  return {
    id: typeof body.id === "number" ? body.id : 0,
    fullName: body.full_name,
    defaultBranch,
    description: typeof body.description === "string" ? body.description.slice(0, 500) : null,
    sizeKb,
    stars: typeof body.stargazers_count === "number" ? body.stargazers_count : 0,
    language: typeof body.language === "string" ? body.language.slice(0, 100) : null,
  };
}

export async function fetchCommitSha(
  fetchImpl: FetchLike,
  owner: string,
  repo: string,
  branch: string,
  config: ServerConfig,
  signal: AbortSignal,
): Promise<string> {
  const url = `https://${API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits/${encodeURIComponent(branch)}`;
  const res = await safeFetch(fetchImpl, url, { headers: headers(config, "application/vnd.github.sha") }, signal);
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    throw mapHttpFailure(res);
  }
  const sha = (await res.text()).trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new RetrievalError("download_failed", "github_error", "GitHub returned an unexpected commit identifier.");
  }
  return sha;
}

/** Opens the source tarball for an exact commit. The caller must consume or cancel the body. */
export async function openArchive(
  fetchImpl: FetchLike,
  owner: string,
  repo: string,
  sha: string,
  config: ServerConfig,
  signal: AbortSignal,
): Promise<Response> {
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new RetrievalError("failed", "internal_error", "Retrieval failed unexpectedly.");
  const url = `https://${API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tarball/${sha}`;
  const res = await safeFetch(fetchImpl, url, { headers: headers(config, "application/vnd.github+json") }, signal);
  if (!res.ok || !res.body) {
    await res.body?.cancel().catch(() => undefined);
    throw mapHttpFailure(res);
  }
  const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > config.maxArchiveBytes) {
    await res.body.cancel().catch(() => undefined);
    throw new RetrievalError("rejected_by_limits", "archive_too_large", "Repository archive exceeds the size limit.");
  }
  return res;
}

/**
 * Safely fetches raw file content for a validated file path at an immutable commit SHA.
 * Validates path traversal, repository boundaries, and file size.
 */
export async function fetchFileAtCommit(
  fetchImpl: FetchLike,
  owner: string,
  repo: string,
  filePath: string,
  commitSha: string,
  config: ServerConfig,
  signal: AbortSignal,
): Promise<string> {
  if (!/^[a-zA-Z0-9_.-]+$/.test(owner) || !/^[a-zA-Z0-9_.-]+$/.test(repo)) {
    throw new RetrievalError("download_failed", "invalid_repository", "Invalid repository coordinates.");
  }
  if (!/^[a-zA-Z0-9_./-]+$/.test(commitSha) || commitSha.includes("..")) {
    throw new RetrievalError("download_failed", "invalid_commit", "Invalid commit identifier.");
  }

  const normalized = path.normalize(filePath).replace(/\\/g, "/");
  if (
    path.isAbsolute(normalized) ||
    normalized.startsWith("../") ||
    normalized.includes("/../") ||
    normalized.startsWith(".git")
  ) {
    throw new RetrievalError("download_failed", "path_traversal", "Forbidden file path.");
  }

  const encodedPath = normalized
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  const url = `https://${API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}?ref=${encodeURIComponent(commitSha)}`;

  const res = await safeFetch(
    fetchImpl,
    url,
    { headers: headers(config, "application/vnd.github.raw+json") },
    signal,
  );

  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    throw mapHttpFailure(res);
  }

  return await res.text();
}

/**
 * Resolves the short-lived, archive-scoped download URL GitHub issues for a private repository
 * tarball (the `Location` of the API redirect). The URL embeds a temporary token that only grants
 * this one archive, so a worker can download the snapshot without ever holding the user's token.
 * Treat the result as a secret: never log it.
 */
export async function resolveArchiveUrl(
  fetchImpl: FetchLike,
  owner: string,
  repo: string,
  sha: string,
  config: ServerConfig,
  signal: AbortSignal,
): Promise<string> {
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new RetrievalError("failed", "internal_error", "Retrieval failed unexpectedly.");
  const url = `https://${API_HOST}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tarball/${sha}`;
  let res: Response;
  try {
    res = await fetchImpl(url, { headers: headers(config, "application/vnd.github+json"), redirect: "manual", signal });
  } catch {
    throw new RetrievalError("download_failed", "network_error", "Could not reach GitHub.");
  }
  await res.body?.cancel().catch(() => undefined);
  const loc = res.headers.get("location");
  if (res.status < 300 || res.status >= 400 || !loc) throw mapHttpFailure(res);
  const target = assertApprovedUrl(new URL(loc, url).toString());
  if (target.hostname !== ARCHIVE_HOST) throw new RetrievalError("download_failed", "redirect_rejected", "GitHub returned an unexpected redirect.");
  return target.toString();
}

/** Downloads an archive from a URL produced by `resolveArchiveUrl`, with the usual size limit. */
export async function openArchiveUrl(
  fetchImpl: FetchLike,
  archiveUrl: string,
  config: Pick<ServerConfig, "maxArchiveBytes">,
  signal: AbortSignal,
): Promise<Response> {
  const target = assertApprovedUrl(archiveUrl);
  if (target.hostname !== ARCHIVE_HOST) throw new RetrievalError("download_failed", "redirect_rejected", "Unexpected archive host.");
  const res = await safeFetch(fetchImpl, target.toString(), { headers: { "User-Agent": "VibeShieldAI-Retriever/0.1" } }, signal);
  if (!res.ok || !res.body) {
    await res.body?.cancel().catch(() => undefined);
    throw mapHttpFailure(res);
  }
  const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > config.maxArchiveBytes) {
    await res.body.cancel().catch(() => undefined);
    throw new RetrievalError("rejected_by_limits", "archive_too_large", "Repository archive exceeds the size limit.");
  }
  return res;
}
