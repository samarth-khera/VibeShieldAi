import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { safeEntryPath, extractArchiveSafely } from "@/server/archive";
import { RetrievalError } from "@/server/errors";
import { Readable } from "node:stream";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";

describe("safeEntryPath", () => {
  const root = "/workspace/tmp/src";

  it("extracts clean relative paths stripping top-level directory", () => {
    const p = safeEntryPath(root, "owner-repo-sha/src/index.ts");
    expect(p).toBe(path.resolve(root, "src/index.ts"));
  });

  it("returns null for top-level root directory entry", () => {
    expect(safeEntryPath(root, "owner-repo-sha/")).toBeNull();
  });

  it("rejects path traversal sequences", () => {
    expect(() => safeEntryPath(root, "owner-repo-sha/../../etc/passwd")).toThrow(RetrievalError);
    expect(() => safeEntryPath(root, "owner-repo-sha/subdir/../../../shadow")).toThrow(RetrievalError);
  });

  it("rejects null bytes and backslashes", () => {
    expect(() => safeEntryPath(root, "owner-repo-sha/file\0.txt")).toThrow(RetrievalError);
    expect(() => safeEntryPath(root, "owner-repo-sha\\windows\\path")).toThrow(RetrievalError);
  });

  it("rejects absolute paths", () => {
    expect(() => safeEntryPath(root, "/etc/passwd")).toThrow(RetrievalError);
    expect(() => safeEntryPath(root, "C:\\autoexec.bat")).toThrow(RetrievalError);
  });
});

describe("extractArchiveSafely", () => {
  let tmpWorkspace: string;

  beforeEach(async () => {
    tmpWorkspace = await mkdtemp(path.join(tmpdir(), "archive-test-"));
  });

  afterEach(async () => {
    await rm(tmpWorkspace, { recursive: true, force: true });
  });

  async function createSampleTarGz(files: { name: string; content: string }[]): Promise<Buffer> {
    const staging = await mkdtemp(path.join(tmpdir(), "tar-staging-"));
    for (const f of files) {
      const full = path.join(staging, f.name);
      await (await import("node:fs/promises")).mkdir(path.dirname(full), { recursive: true });
      await (await import("node:fs/promises")).writeFile(full, f.content);
    }
    const chunks: Buffer[] = [];
    const stream = tar.create({ gzip: true, cwd: staging }, ["repo-root"]);
    for await (const chunk of stream) {
      chunks.push(chunk as Buffer);
    }
    await rm(staging, { recursive: true, force: true });
    return Buffer.concat(chunks);
  }

  it("extracts a valid tarball within limits", async () => {
    const tarBuffer = await createSampleTarGz([
      { name: "repo-root/README.md", content: "# Hello World" },
      { name: "repo-root/src/index.ts", content: "console.log('hi');" },
    ]);

    const readable = Readable.from([tarBuffer]);
    const stats = await extractArchiveSafely(readable, tmpWorkspace, {
      maxArchiveBytes: 10 * 1024 * 1024,
      maxUnpackedBytes: 10 * 1024 * 1024,
      maxFileCount: 100,
    });

    expect(stats.fileCount).toBe(2);
    expect(stats.unpackedBytes).toBeGreaterThan(0);

    const readmeContent = await readFile(path.join(tmpWorkspace, "README.md"), "utf8");
    expect(readmeContent).toBe("# Hello World");

    // Verify restricted permissions
    const fileStat = await stat(path.join(tmpWorkspace, "README.md"));
    expect(fileStat.mode & 0o777).toBe(0o600);

    const dirStat = await stat(path.join(tmpWorkspace, "src"));
    expect(dirStat.mode & 0o777).toBe(0o700);
  });

  it("rejects archives exceeding file count limit", async () => {
    const tarBuffer = await createSampleTarGz([
      { name: "repo-root/file1.txt", content: "1" },
      { name: "repo-root/file2.txt", content: "2" },
      { name: "repo-root/file3.txt", content: "3" },
    ]);

    const readable = Readable.from([tarBuffer]);
    await expect(
      extractArchiveSafely(readable, tmpWorkspace, {
        maxArchiveBytes: 10 * 1024 * 1024,
        maxUnpackedBytes: 10 * 1024 * 1024,
        maxFileCount: 2, // limit is 2, tar has 3 files
      }),
    ).rejects.toThrow("file_count");
  });

  it("rejects archives exceeding unpacked byte limit", async () => {
    const largeContent = "A".repeat(1000);
    const tarBuffer = await createSampleTarGz([
      { name: "repo-root/large.txt", content: largeContent },
    ]);

    const readable = Readable.from([tarBuffer]);
    await expect(
      extractArchiveSafely(readable, tmpWorkspace, {
        maxArchiveBytes: 10 * 1024 * 1024,
        maxUnpackedBytes: 500, // limit is 500 bytes, file is 1000
        maxFileCount: 10,
      }),
    ).rejects.toThrow("unpacked_size");
  });
});
