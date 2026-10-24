/**
 * Strict GitHub repository URL parsing. Shared by the browser (early feedback) and the
 * server (authoritative validation). Pure: no Node-only APIs.
 *
 * Accepted: https://github.com/<owner>/<repo>[.git][/]   (also www.github.com)
 * Everything else (other hosts/protocols, credentials, ports, query, fragment, extra
 * path segments, encoded/traversal characters) is rejected.
 */
export type ParsedRepo = {
  owner: string;
  repo: string;
  /** Canonical form: https://github.com/owner/repo */
  url: string;
};
export type ParseResult = ({ ok: true } & ParsedRepo) | { ok: false; code: string; error: string };

const MAX_INPUT_LENGTH = 200;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const ALLOWED_HOSTS = new Set(["github.com", "www.github.com"]);

const fail = (code: string, error: string): ParseResult => ({ ok: false, code, error });

export function parseGithubRepoUrl(input: unknown): ParseResult {
  if (typeof input !== "string") return fail("invalid_url", "Enter a GitHub repository URL.");
  const value = input.trim();
  if (!value) return fail("invalid_url", "Enter a GitHub repository URL.");
  if (value.length > MAX_INPUT_LENGTH) return fail("invalid_url", "That URL is too long.");
  // Control characters, whitespace, backslashes, percent-encoding and traversal dots have no place in a repo URL.
  if (/[\u0000-\u0020\u007f\\%]|\.\./.test(value)) {
    return fail("invalid_url", "The URL contains unsupported characters.");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fail("invalid_url", "That doesn't look like a URL. Try https://github.com/owner/repo");
  }

  if (url.protocol !== "https:") return fail("unsupported_protocol", "Only https:// GitHub URLs are supported.");
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    return fail("unsupported_host", "Only public repositories on github.com are supported.");
  }
  if (url.username || url.password) return fail("invalid_url", "URLs with credentials are not allowed.");
  if (url.port) return fail("invalid_url", "URLs with a custom port are not allowed.");
  if (url.search || url.hash) return fail("invalid_url", "Remove query strings and fragments from the URL.");

  const segments = url.pathname.replace(/\/$/, "").split("/").slice(1);
  if (segments.length !== 2) {
    return fail("invalid_url", "Use the form https://github.com/owner/repository");
  }
  const [owner, rawRepo] = segments;
  const repo = rawRepo.endsWith(".git") ? rawRepo.slice(0, -4) : rawRepo;
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo) || repo === "." || repo === ".." || repo.startsWith("..")) {
    return fail("invalid_url", "That owner or repository name is not valid.");
  }
  return { ok: true, owner, repo, url: `https://github.com/${owner}/${repo}` };
}
