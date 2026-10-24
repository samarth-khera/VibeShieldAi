import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import type { ServerConfig } from "./config";
import { RetrievalError, log } from "./errors";
import { extractArchiveSafely } from "./archive";
import { fetchCommitSha, fetchRepoMetadata, openArchive, type FetchLike } from "./github";
import type { JobStore } from "./job-store";

export type RetrievalDeps = {
  store: JobStore;
  config: ServerConfig;
  fetchImpl: FetchLike;
  /** Parent directory for temp workspaces (defaults to the OS tmp dir). */
  tmpRoot?: string;
  now?: () => Date;
};

export type RetrievalOutcome = "ready_for_scan" | "skipped" | "failed";

/**
 * Worker pipeline: metadata → commit → bounded download → safe extraction check.
 * Idempotent: only a job that can be atomically claimed is processed. The temp workspace is always
 * removed. Repository code is never executed, installed or built, and nothing is scanned here.
 */
export async function runRetrieval(jobId: string, deps: RetrievalDeps): Promise<RetrievalOutcome> {
  const { store, config, fetchImpl } = deps;
  const now = deps.now ?? (() => new Date());
  const job = await store.get(jobId);
  if (!job) return "skipped";

  const staleBefore = new Date(now().getTime() - config.retrievalTimeoutMs * 2);
  if (!(await store.claim(jobId, staleBefore))) return "skipped";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.retrievalTimeoutMs);
  let workspace: string | null = null;

  try {
    const meta = await fetchRepoMetadata(fetchImpl, job.owner, job.repo, config, controller.signal);
    await store.update(jobId, {
      defaultBranch: meta.defaultBranch,
      description: meta.description,
      repoSizeKb: meta.sizeKb,
      stars: meta.stars,
      primaryLanguage: meta.language,
    });

    const sha = await fetchCommitSha(fetchImpl, job.owner, job.repo, meta.defaultBranch, config, controller.signal);
    await store.update(jobId, { commitSha: sha });

    const res = await openArchive(fetchImpl, job.owner, job.repo, sha, config, controller.signal);
    workspace = await mkdtemp(path.join(deps.tmpRoot ?? tmpdir(), "vibeshield-"));
    await chmod(workspace, 0o700);
    const source = Readable.fromWeb(res.body as never);
    controller.signal.addEventListener("abort", () => source.destroy(new RetrievalError("download_failed", "timeout", "Retrieval timed out.")), { once: true });

    const stats = await extractArchiveSafely(source, path.join(workspace, "src"), config);
    const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);

    await store.update(jobId, {
      status: "ready_for_scan",
      fileCount: stats.fileCount,
      unpackedBytes: stats.unpackedBytes,
      archiveBytes: Number.isFinite(declared) ? declared : null,
      completedAt: now(),
      failureCategory: null,
      errorMessage: null,
    });
    log("info", "retrieval_ready", { jobId, files: stats.fileCount });
    return "ready_for_scan";
  } catch (err) {
    const known =
      err instanceof RetrievalError
        ? err
        : controller.signal.aborted
          ? new RetrievalError("download_failed", "timeout", "Retrieval timed out.")
          : new RetrievalError("failed", "internal_error", "Retrieval failed unexpectedly.");
    // Log only the category — never raw error text, URLs or stack traces.
    log(known.status === "failed" ? "error" : "warn", "retrieval_failed", { jobId, status: known.status, category: known.category, cause: err instanceof Error ? err.name : "unknown" });
    await store.update(jobId, {
      status: known.status,
      failureCategory: known.category,
      errorMessage: known.publicMessage,
      completedAt: now(),
    });
    return "failed";
  } finally {
    clearTimeout(timer);
    controller.abort(); // release any still-open connection
    if (workspace) await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  }
}
