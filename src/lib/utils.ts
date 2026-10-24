import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { parseGithubRepoUrl } from "./github-url";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Client-side convenience wrapper (early feedback only; the server re-validates). */
export function parseGithubUrl(
  input: string,
): { ok: true; owner: string; repo: string } | { ok: false; error: string } {
  const r = parseGithubRepoUrl(input);
  return r.ok ? { ok: true, owner: r.owner, repo: r.repo } : { ok: false, error: r.error };
}
