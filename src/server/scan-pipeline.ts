import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import type { ServerConfig } from "./config";
import { RetrievalError, log } from "./errors";
import { extractArchiveSafely } from "./archive";
import { fetchCommitSha, fetchRepoMetadata, openArchive, type FetchLike } from "./github";
import type { JobStore } from "./job-store";
import { runSecurityScanEngine } from "./scanners/engine";
import type { ScanEngineResult } from "./scanners/types";

export type PipelineDeps = {
  store: JobStore;
  config: ServerConfig;
  fetchImpl: FetchLike;
  tmpRoot?: string;
  now?: () => Date;
  scanEngine?: (dir: string) => Promise<ScanEngineResult>;
};

export type PipelineOutcome = "completed" | "completed_with_warnings" | "ready_for_scan" | "skipped" | "failed";

/**
 * End-to-end secure worker pipeline:
 * metadata → commit → bounded download → safe extraction → scanning (Gitleaks + Semgrep + OSV-Scanner) → persistence.
 *
 * Repositories are processed as untrusted input in an unprivileged temporary workspace.
 * Temporary files are guaranteed to be cleaned up on both success and failure.
 * Repository code is never executed.
 */
export async function runScanPipeline(jobId: string, deps: PipelineDeps): Promise<PipelineOutcome> {
  const { store, config, fetchImpl } = deps;
  const now = deps.now ?? (() => new Date());
  const job = await store.get(jobId);
  if (!job) return "skipped";

  const staleBefore = new Date(now().getTime() - config.retrievalTimeoutMs * 2);

  // If already retrieved (ready_for_scan), claim for scanning; otherwise claim queued
  let isScanOnly = false;
  if (job.status === "ready_for_scan" && job.commitSha) {
    if (!(await store.claimForScan(jobId, staleBefore))) return "skipped";
    isScanOnly = true;
  } else {
    if (!(await store.claim(jobId, staleBefore))) return "skipped";
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.retrievalTimeoutMs);
  let workspace: string | null = null;

  try {
    let commitSha = job.commitSha;

    if (!isScanOnly || !commitSha) {
      const meta = await fetchRepoMetadata(fetchImpl, job.owner, job.repo, config, controller.signal);
      await store.update(jobId, {
        defaultBranch: meta.defaultBranch,
        description: meta.description,
        repoSizeKb: meta.sizeKb,
        stars: meta.stars,
        primaryLanguage: meta.language,
      });

      commitSha = await fetchCommitSha(fetchImpl, job.owner, job.repo, meta.defaultBranch, config, controller.signal);
      await store.update(jobId, { commitSha });
    }

    // Bounded download and extraction
    const res = await openArchive(fetchImpl, job.owner, job.repo, commitSha, config, controller.signal);
    workspace = await mkdtemp(path.join(deps.tmpRoot ?? tmpdir(), "vibeshield-"));
    await chmod(workspace, 0o700);
    const sourceDir = path.join(workspace, "src");
    const source = Readable.fromWeb(res.body as never);
    controller.signal.addEventListener(
      "abort",
      () => source.destroy(new RetrievalError("download_failed", "timeout", "Retrieval timed out.")),
      { once: true },
    );

    const stats = await extractArchiveSafely(source, sourceDir, config);
    const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);

    // Transition to scanning state
    await store.update(jobId, {
      status: "scanning",
      fileCount: stats.fileCount,
      unpackedBytes: stats.unpackedBytes,
      archiveBytes: Number.isFinite(declared) ? declared : null,
      gitleaksStatus: "running",
      semgrepStatus: "running",
      osvStatus: "running",
      failureCategory: null,
      errorMessage: null,
    });
    log("info", "scan_started", { jobId, files: stats.fileCount });

    // Run security scanning engine across the untrusted extracted code
    const engine = deps.scanEngine ?? runSecurityScanEngine;
    const scanResult = await engine(sourceDir);

    // Save normalized findings
    await store.saveFindings(jobId, scanResult.findings);

    // Update job record with real scanner results and counts
    await store.update(jobId, {
      status: scanResult.status,
      gitleaksStatus: scanResult.gitleaksStatus,
      gitleaksDurationMs: scanResult.gitleaksDurationMs,
      gitleaksError: scanResult.gitleaksError,
      semgrepStatus: scanResult.semgrepStatus,
      semgrepDurationMs: scanResult.semgrepDurationMs,
      semgrepError: scanResult.semgrepError,
      osvStatus: scanResult.osvStatus,
      osvDurationMs: scanResult.osvDurationMs,
      osvError: scanResult.osvError,
      scannerVersions: scanResult.scannerVersions,
      scanCoverage: scanResult.scanCoverage,
      criticalCount: scanResult.counts.critical,
      highCount: scanResult.counts.high,
      mediumCount: scanResult.counts.medium,
      lowCount: scanResult.counts.low,
      infoCount: scanResult.counts.info,
      completedAt: now(),
      failureCategory: null,
      errorMessage: null,
    });

    log("info", "scan_completed", {
      jobId,
      status: scanResult.status,
      findings: scanResult.findings.length,
      critical: scanResult.counts.critical,
    });

    return scanResult.status;
  } catch (err) {
    const known =
      err instanceof RetrievalError
        ? err
        : controller.signal.aborted
          ? new RetrievalError("download_failed", "timeout", "Operation timed out.")
          : new RetrievalError("failed", "internal_error", "Processing failed unexpectedly.");

    log(known.status === "failed" ? "error" : "warn", "pipeline_failed", {
      jobId,
      status: known.status,
      category: known.category,
      cause: err instanceof Error ? err.name : "unknown",
    });

    await store.update(jobId, {
      status: known.status,
      failureCategory: known.category,
      errorMessage: known.publicMessage,
      completedAt: now(),
    });

    return "failed";
  } finally {
    clearTimeout(timer);
    controller.abort();
    if (workspace) {
      await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}
