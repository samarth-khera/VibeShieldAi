import type { ServerConfig } from "../config";
import { fetchFileAtCommit, type FetchLike } from "../github";
import { COMMIT_SHA_RE } from "./verify";

const TTL_MS = 10 * 60_000;
const MAX_ENTRIES = 64;
const MAX_TOTAL_BYTES = 4 * 1024 * 1024;
const MAX_ENTRY_BYTES = 512 * 1024;
const FETCH_TIMEOUT_MS = 10_000;

type Entry = { content: string; bytes: number; expiresAt: number };

// Content at a commit SHA never changes, so entries only expire to bound memory per instance.
const cache = new Map<string, Entry>();
const inFlight = new Map<string, Promise<string>>();
let totalBytes = 0;

export type SourceRef = { owner: string; repo: string; commitSha: string; filePath: string };

function keyOf(ref: SourceRef): string {
  return `${ref.owner.toLowerCase()}/${ref.repo.toLowerCase()}@${ref.commitSha}:${ref.filePath}`;
}

function evict(key: string): void {
  const entry = cache.get(key);
  if (!entry) return;
  cache.delete(key);
  totalBytes -= entry.bytes;
}

function store(key: string, content: string): void {
  const bytes = Buffer.byteLength(content, "utf8");
  if (bytes > MAX_ENTRY_BYTES) return;
  evict(key);
  cache.set(key, { content, bytes, expiresAt: Date.now() + TTL_MS });
  totalBytes += bytes;
  // Map iteration order is insertion order, so the first key is the least recently used.
  while (cache.size > MAX_ENTRIES || totalBytes > MAX_TOTAL_BYTES) {
    evict(cache.keys().next().value!);
  }
}

/**
 * Fetches a file at an immutable commit, reusing recent results so repeated previews of the same
 * finding do not refetch from GitHub. Only full 40-character commit SHAs are cached.
 */
export async function fetchSourceAtCommit(
  fetchImpl: FetchLike,
  ref: SourceRef,
  config: ServerConfig,
): Promise<string> {
  if (!COMMIT_SHA_RE.test(ref.commitSha)) {
    throw new Error("Source can only be fetched for an immutable commit SHA.");
  }
  const key = keyOf(ref);
  const hit = cache.get(key);
  if (hit && hit.expiresAt > Date.now()) {
    cache.delete(key);
    cache.set(key, hit); // refresh recency
    return hit.content;
  }
  evict(key);

  const pending = inFlight.get(key);
  if (pending) return pending;

  const request = (async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const content = await fetchFileAtCommit(
        fetchImpl,
        ref.owner,
        ref.repo,
        ref.filePath,
        ref.commitSha,
        config,
        controller.signal,
      );
      store(key, content);
      return content;
    } finally {
      clearTimeout(timer);
      inFlight.delete(key);
    }
  })();
  inFlight.set(key, request);
  return request;
}

/** Test hook. */
export function clearSourceCache(): void {
  cache.clear();
  inFlight.clear();
  totalBytes = 0;
}
