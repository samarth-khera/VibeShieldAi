import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, mkdir, readdir, rename, rm, stat, utimes } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ServerConfig } from "../config";
import { RetrievalError } from "../errors";
import { openArchive } from "../github";
import type { ArchiveSource } from "./scan-executor";

const COMMIT_SHA_RE = /^[0-9a-f]{40}$/;

export type ArchiveCacheOptions = { dir: string; maxBytes: number; ttlMs: number };

/**
 * Disk cache of GitHub tarballs keyed by canonical repository identity plus immutable commit SHA.
 * Entries are written atomically (temp file + rename), made read-only, expire after `ttlMs`, and are
 * evicted oldest-first past `maxBytes`. The cache only stores compressed archives; every job still
 * extracts into its own fresh workspace with the usual limits, so no workspace is ever shared.
 */
export function createArchiveCache(opts: ArchiveCacheOptions): ArchiveSource {
  const inFlight = new Map<string, Promise<string>>();

  const fileFor = (owner: string, repo: string, sha: string) => {
    const repoKey = createHash("sha256").update(`${owner.toLowerCase()}/${repo.toLowerCase()}`).digest("hex").slice(0, 32);
    return path.join(opts.dir, `${repoKey}-${sha}.tar.gz`);
  };

  async function evict(): Promise<void> {
    const entries = [];
    for (const name of await readdir(opts.dir)) {
      if (!name.endsWith(".tar.gz")) continue;
      const p = path.join(opts.dir, name);
      const s = await stat(p).catch(() => null);
      if (s) entries.push({ p, size: s.size, mtime: s.mtimeMs });
    }
    entries.sort((a, b) => a.mtime - b.mtime);
    let total = entries.reduce((n, e) => n + e.size, 0);
    for (const e of entries) {
      if (Date.now() - e.mtime > opts.ttlMs || total > opts.maxBytes) {
        await rm(e.p, { force: true });
        total -= e.size;
      }
    }
  }

  async function download(owner: string, repo: string, sha: string, config: ServerConfig, signal: AbortSignal, file: string) {
    const res = await openArchive(fetch, owner, repo, sha, config, signal);
    const tmp = `${file}.${process.pid}.${Date.now()}.partial`;
    let bytes = 0;
    const limit = new Transform({
      transform(chunk, _enc, cb) {
        bytes += chunk.length;
        if (bytes > config.maxArchiveBytes) {
          cb(new RetrievalError("rejected_by_limits", "archive_too_large", "Repository archive exceeds the size limit."));
        } else cb(null, chunk);
      },
    });
    try {
      await pipeline(Readable.fromWeb(res.body as never), limit, createWriteStream(tmp, { mode: 0o600, flags: "wx" }), { signal });
      await chmod(tmp, 0o400);
      await rename(tmp, file);
    } catch (err) {
      await rm(tmp, { force: true });
      throw err;
    }
    await evict().catch(() => undefined);
    return file;
  }

  return async (owner, repo, sha, config, signal) => {
    if (!COMMIT_SHA_RE.test(sha)) throw new RetrievalError("failed", "internal_error", "Archive cache requires a commit SHA.");
    await mkdir(opts.dir, { recursive: true, mode: 0o700 });
    const file = fileFor(owner, repo, sha);
    const existing = await stat(file).catch(() => null);
    if (existing && Date.now() - existing.mtimeMs <= opts.ttlMs) {
      await utimes(file, new Date(), new Date()).catch(() => undefined); // keep recently used entries
      return { stream: createReadStream(file), bytes: existing.size, cache: "hit" };
    }
    let pending = inFlight.get(file);
    if (!pending) {
      pending = download(owner, repo, sha, config, signal, file).finally(() => inFlight.delete(file));
      inFlight.set(file, pending);
    }
    await pending;
    const s = await stat(file);
    return { stream: createReadStream(file), bytes: s.size, cache: "miss" };
  };
}
