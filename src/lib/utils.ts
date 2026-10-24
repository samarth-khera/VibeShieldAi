import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Accepts https://github.com/owner/repo (optional .git, trailing slash, /tree/...). */
export function parseGithubUrl(
  input: string,
): { ok: true; owner: string; repo: string } | { ok: false; error: string } {
  const value = input.trim();
  if (!value) return { ok: false, error: "Enter a GitHub repository URL." };
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return {
      ok: false,
      error: "That doesn't look like a URL. Try https://github.com/owner/repo",
    };
  }
  if (url.protocol !== "https:" || !["github.com", "www.github.com"].includes(url.hostname)) {
    return { ok: false, error: "Only https://github.com repository URLs are supported." };
  }
  const [owner, rawRepo] = url.pathname.split("/").filter(Boolean);
  const repo = rawRepo?.replace(/\.git$/, "");
  const valid = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner ?? "");
  if (!owner || !repo || !valid || !/^[A-Za-z0-9._-]+$/.test(repo)) {
    return { ok: false, error: "Include both owner and repository, e.g. github.com/owner/repo" };
  }
  return { ok: true, owner, repo };
}
