import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { parseGithubRepoUrl } from "../../lib/github-url";
import type { ServerConfig } from "../config";
import { fetchCommitSha, fetchRepoMetadata, openArchive, openArchiveUrl } from "../github";
import { extractArchiveSafely } from "../archive";
import { RetrievalError } from "../errors";
import { runSecurityScanEngine } from "../scanners/engine";
import { redactText } from "../scanners/redact";
import type { NormalizedFinding, SingleScannerResult } from "../scanners/types";
import { postSigned } from "./signed-http";

/** Supplies the archive for an immutable commit. The default streams it from GitHub. */
export type ArchiveSource = (
  owner: string,
  repo: string,
  commitSha: string,
  config: ServerConfig,
  signal: AbortSignal,
) => Promise<{ stream: Readable; bytes: number | null; cache: "hit" | "miss" | "none" }>;

export const githubArchiveSource: ArchiveSource = async (owner, repo, sha, config, signal) => {
  const res = await openArchive(fetch, owner, repo, sha, config, signal);
  const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);
  return { stream: Readable.fromWeb(res.body as never), bytes: Number.isFinite(declared) ? declared : null, cache: "none" };
};

import { PRIVATE_REPOSITORY } from "./private-repository";
export { PRIVATE_REPOSITORY };

type PrivateSourceDescriptor = { owner: string; repo: string; defaultBranch: string; commitSha: string; archiveUrl: string };

export type ScanJobContext = {
  jobId: string;
  repositoryUrl: string;
  /** Scan callback endpoint; built by the caller from trusted configuration, never from job data. */
  callbackUrl: string;
  secret: string;
  /** Warm-worker lease. Every callback carries it so a superseded run cannot write results. */
  lease?: string;
  runId?: string;
  runUrl?: string;
  runnerStartedAt?: string;
  config: ServerConfig;
  archives?: ArchiveSource;
  log?: (line: string) => void;
};

function redactFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  for (const f of findings) if (f.redactedEvidence) f.redactedEvidence = redactText(f.redactedEvidence);
  return findings;
}

/**
 * Retrieves the repository at its current default-branch commit, scans it with all three
 * scanners in parallel, publishes each scanner's findings as soon as it finishes, and then posts
 * the final aggregate. Never executes repository code.
 */
export async function executeScanJob(ctx: ScanJobContext): Promise<"completed" | "completed_with_warnings" | "failed"> {
  const say = ctx.log ?? (() => undefined);
  const base = { jobId: ctx.jobId, lease: ctx.lease, workflowRunId: ctx.runId, workflowRunUrl: ctx.runUrl };
  const progress: Record<string, string> = ctx.runnerStartedAt ? { worker_startedAt: ctx.runnerStartedAt } : {};
  const post = (payload: Record<string, unknown>, attempts = 3) =>
    postSigned(ctx.callbackUrl, ctx.secret, { ...base, ...payload }, { attempts });
  const heartbeat = async (phase: string, extra: Record<string, unknown> = {}) => {
    const at = new Date().toISOString();
    progress[`${phase}At`] = at;
    // Best-effort and single-attempt: progress reporting must never fail a scan.
    await post({ type: "progress", phase, at, ...extra }, 1).catch(() => say(`progress '${phase}' not delivered`));
  };

  const isPrivate = ctx.repositoryUrl === PRIVATE_REPOSITORY;
  const parsed = isPrivate ? null : parseGithubRepoUrl(ctx.repositoryUrl);
  if (parsed && !parsed.ok) {
    await post({ status: "failed", failureCategory: "invalid_repository", errorMessage: parsed.error, findings: [] }).catch(() => undefined);
    return "failed";
  }

  const config = ctx.config;
  const archives = ctx.archives ?? githubArchiveSource;
  let workspace: string | null = null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.retrievalTimeoutMs);
  try {
    const t0 = Date.now();
    await heartbeat("retrieving");
    const tMeta = Date.now();
    let commitSha: string;
    let defaultBranch: string;
    let privateSource: PrivateSourceDescriptor | null = null;
    if (isPrivate) {
      // Private: identity and a short-lived archive URL come from the app, authorized by the user.
      const res = await postSigned(ctx.callbackUrl.replace(/\/callback$/, "/source"), ctx.secret, { jobId: ctx.jobId, lease: ctx.lease });
      if (!res.ok) throw new Error(`Private repository source unavailable (HTTP ${res.status}).`);
      privateSource = ((await res.json()) as { data: PrivateSourceDescriptor }).data;
      commitSha = privateSource.commitSha;
      defaultBranch = privateSource.defaultBranch;
    } else {
      const meta = await fetchRepoMetadata(fetch, parsed!.owner, parsed!.repo, config, controller.signal);
      defaultBranch = meta.defaultBranch;
      commitSha = await fetchCommitSha(fetch, parsed!.owner, parsed!.repo, meta.defaultBranch, config, controller.signal);
    }
    const metadataMs = Date.now() - tMeta;

    const tDownload = Date.now();
    // Private archives bypass the worker's on-disk cache so their content is not kept after the scan.
    const archive = privateSource
      ? await (async () => {
          const r = await openArchiveUrl(fetch, privateSource!.archiveUrl, config, controller.signal);
          const declared = Number.parseInt(r.headers.get("content-length") ?? "", 10);
          return { stream: Readable.fromWeb(r.body as never), bytes: Number.isFinite(declared) ? declared : null, cache: "none" as const };
        })()
      : await archives(parsed!.owner, parsed!.repo, commitSha, config, controller.signal);
    const downloadMs = Date.now() - tDownload;

    workspace = await mkdtemp(path.join(tmpdir(), "vibeshield-run-"));
    await chmod(workspace, 0o700);
    const sourceDir = path.join(workspace, "src");
    controller.signal.addEventListener("abort", () => archive.stream.destroy(new Error("Download timed out.")), { once: true });

    await heartbeat("extracting", { commitSha, defaultBranch });
    const tExtract = Date.now();
    const stats = await extractArchiveSafely(archive.stream, sourceDir, config);
    clearTimeout(timer);
    const extractionMs = Date.now() - tExtract;

    await heartbeat("scanning");
    const tScan = Date.now();
    const result = await runSecurityScanEngine(sourceDir, {
      onScannerComplete: async (r: SingleScannerResult) => {
        const res = await post({
          type: "scanner_result",
          scanner: r.scanner,
          status: r.status === "completed" ? "completed" : "failed",
          durationMs: r.durationMs,
          error: r.error ?? null,
          at: new Date().toISOString(),
          findings: redactFindings(r.findings),
        });
        say(`${r.scanner} ${r.status} in ${r.durationMs}ms (${r.findings.length} findings) -> HTTP ${res.status}`);
      },
    });
    const scanningMs = Date.now() - tScan;
    redactFindings(result.findings);

    const stageDurations = { metadataMs, downloadMs, extractionMs, scanningMs, callbackMs: 0 };
    const coverage = { ...result.scanCoverage, stageDurations, progress, archiveCache: archive.cache } as unknown as Record<string, unknown>;
    const tCallback = Date.now();
    const res = await post({
      status: result.status,
      commitSha,
      archiveBytes: archive.bytes,
      fileCount: stats.fileCount,
      unpackedBytes: stats.unpackedBytes,
      gitleaksStatus: result.gitleaksStatus,
      gitleaksDurationMs: result.gitleaksDurationMs,
      gitleaksError: result.gitleaksError,
      semgrepStatus: result.semgrepStatus,
      semgrepDurationMs: result.semgrepDurationMs,
      semgrepError: result.semgrepError,
      osvStatus: result.osvStatus,
      osvDurationMs: result.osvDurationMs,
      osvError: result.osvError,
      scannerVersions: result.scannerVersions as unknown as Record<string, unknown>,
      scanCoverage: coverage,
      counts: result.counts,
      findings: result.findings,
      remediations: [],
    });
    if (!res.ok) throw new Error(`Final callback rejected with HTTP ${res.status}.`);
    say(
      `[Metrics] job=${ctx.jobId} metadata=${metadataMs}ms download=${downloadMs}ms (archive cache ${archive.cache}) extraction=${extractionMs}ms scanning=${scanningMs}ms callback=${Date.now() - tCallback}ms total=${Date.now() - t0}ms`,
    );
    return result.status;
  } catch (err: unknown) {
    const message = redactText(err instanceof Error ? err.message : String(err)).slice(0, 280);
    say(`scan failed: ${message}`);
    // Expected retrieval/limit failures keep their category and user-safe message (e.g. archive_too_large).
    const failure =
      err instanceof RetrievalError
        ? { failureCategory: err.category, errorMessage: err.publicMessage }
        : { failureCategory: "scan_failed", errorMessage: message };
    await post({ status: "failed", ...failure, findings: [] }).catch(() =>
      say("could not report failure"),
    );
    return "failed";
  } finally {
    clearTimeout(timer);
    if (workspace) await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  }
}
