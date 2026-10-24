import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { Readable, Transform, pipeline } from "node:stream";
import { createGunzip } from "node:zlib";
import { Parser } from "tar";
import { RetrievalError } from "./errors";

export type ArchiveLimits = { maxArchiveBytes: number; maxUnpackedBytes: number; maxFileCount: number };
export type ArchiveStats = { fileCount: number; unpackedBytes: number; skippedLinks: number };

const reject = (category: string, message: string) => new RetrievalError("rejected_by_limits", category, message);

/**
 * Returns the safe relative path inside `root` for an archive entry (dropping GitHub's single top-level
 * directory), or throws for anything that could escape the workspace.
 */
export function safeEntryPath(root: string, entryPath: string): string | null {
  if (entryPath.includes("\0") || entryPath.includes("\\")) throw reject("unsafe_path", "Archive contains an unsafe path.");
  if (entryPath.startsWith("/") || /^[A-Za-z]:/.test(entryPath)) throw reject("unsafe_path", "Archive contains an unsafe path.");
  const parts = entryPath.split("/").filter((p) => p !== "" && p !== ".");
  if (parts.some((p) => p === "..")) throw reject("unsafe_path", "Archive contains an unsafe path.");
  const rel = parts.slice(1); // strip "<owner>-<repo>-<sha>/"
  if (rel.length === 0) return null;
  const resolved = path.resolve(root, ...rel);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw reject("unsafe_path", "Archive contains an unsafe path.");
  }
  return resolved;
}

function counter(max: number, category: string, message: string, bump: (n: number) => void): Transform {
  let total = 0;
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      total += chunk.length;
      bump(chunk.length);
      if (total > max) return cb(reject(category, message));
      cb(null, chunk);
    },
  });
}

/**
 * Streams a .tar.gz into `root` with hard limits. Only regular files and directories are written;
 * symlinks/hardlinks are skipped, device/fifo entries are rejected. File modes are never preserved.
 * Nothing in the archive is ever executed.
 */
export async function extractArchiveSafely(source: Readable, root: string, limits: ArchiveLimits): Promise<ArchiveStats> {
  await mkdir(root, { recursive: true });
  const stats: ArchiveStats = { fileCount: 0, unpackedBytes: 0, skippedLinks: 0 };
  let failure: RetrievalError | null = null;
  const writes: Promise<void>[] = [];

  const fail = (err: RetrievalError) => {
    if (!failure) {
      failure = err;
      source.destroy(err);
    }
  };

  const parser = new Parser({
    strict: false,
    onReadEntry: (entry) => {
      if (failure) return void entry.resume();
      try {
        const type = entry.type;
        if (type === "SymbolicLink" || type === "Link") {
          stats.skippedLinks++;
          return void entry.resume();
        }
        if (type !== "File" && type !== "OldFile" && type !== "ContiguousFile" && type !== "Directory") {
          throw reject("unsafe_entry", "Archive contains an unsupported entry type.");
        }
        const dest = safeEntryPath(root, entry.path);
        if (!dest) return void entry.resume();
        if (type === "Directory") {
          writes.push(mkdir(dest, { recursive: true }).then(() => undefined));
          return void entry.resume();
        }
        stats.fileCount++;
        stats.unpackedBytes += entry.size;
        if (stats.fileCount > limits.maxFileCount) throw reject("file_count", "Repository has too many files.");
        if (stats.unpackedBytes > limits.maxUnpackedBytes) throw reject("unpacked_size", "Repository is too large once unpacked.");
        writes.push(
          mkdir(path.dirname(dest), { recursive: true }).then(
            () =>
              new Promise<void>((resolve, reject2) => {
                const ws = createWriteStream(dest, { flags: "wx", mode: 0o644 });
                ws.on("error", reject2);
                ws.on("finish", resolve);
                entry.on("error", reject2);
                entry.pipe(ws);
              }),
          ),
        );
      } catch (e) {
        fail(e instanceof RetrievalError ? e : reject("unsafe_entry", "Archive could not be processed safely."));
        entry.resume();
      }
    },
  });

  let compressed = 0;
  try {
    await new Promise<void>((resolve, rej) => {
      pipeline(
        source,
        counter(limits.maxArchiveBytes, "archive_too_large", "Repository archive exceeds the size limit.", (n) => (compressed += n)),
        createGunzip(),
        // Bound decompressed bytes (tar headers/padding included) to defeat decompression bombs.
        counter(limits.maxUnpackedBytes + 64 * 1024 * 1024, "unpacked_size", "Repository is too large once unpacked.", () => undefined),
        parser,
        (err) => (err ? rej(err) : resolve()),
      );
    });
    await Promise.all(writes);
  } catch (err) {
    await Promise.allSettled(writes);
    if (failure) throw failure;
    if (err instanceof RetrievalError) throw err;
    throw new RetrievalError("download_failed", "archive_corrupt", "Repository archive could not be read.");
  }
  if (failure) throw failure;
  void compressed;
  return stats;
}
