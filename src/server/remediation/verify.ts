import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import type { ServerConfig } from "../config";
import { openArchive, type FetchLike } from "../github";
import { extractArchiveSafely } from "../archive";
import type { ScanEngineResult } from "../scanners/types";
import { applyAndRescanInSandbox, failedResult, type BaselineFinding, type SandboxResult } from "./sandbox";

export const COMMIT_SHA_RE = /^[0-9a-f]{40}$/;

export type SnapshotVerificationParams = {
  owner: string;
  repo: string;
  /** Immutable commit the original scan ran against. Branch names are rejected. */
  commitSha: string;
  unifiedDiff: string;
  targetedFingerprints: string[];
  /** Findings of the original scan; the regression baseline. */
  baselineFindings: BaselineFinding[];
  config: Pick<ServerConfig, "maxArchiveBytes" | "maxUnpackedBytes" | "maxFileCount" | "retrievalTimeoutMs" | "githubToken">;
  fetchImpl?: FetchLike;
  scanEngine?: (dir: string) => Promise<ScanEngineResult>;
};

/**
 * Rebuilds the full repository at the scanned commit from GitHub's archive (same bounded download
 * and safe extraction as the scan worker), applies the approved patch, and rescans the whole tree.
 */
export async function verifyRemediationOnSnapshot(params: SnapshotVerificationParams): Promise<SandboxResult> {
  const baseline = params.baselineFindings;

  if (!COMMIT_SHA_RE.test(params.commitSha)) {
    return failedResult(
      { originalFindings: baseline, targetedFingerprints: params.targetedFingerprints },
      "commit_unknown",
      "The scanned commit is unknown, so the repository snapshot cannot be rebuilt.",
    );
  }

  const fetchImpl = params.fetchImpl ?? fetch;
  const workspace = await mkdtemp(path.join(tmpdir(), "vibeshield-verify-"));
  await chmod(workspace, 0o700);
  const sourceDir = path.join(workspace, "src");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.config.retrievalTimeoutMs);

  try {
    const tDownload = Date.now();
    const res = await openArchive(
      fetchImpl,
      params.owner,
      params.repo,
      params.commitSha,
      params.config as ServerConfig,
      controller.signal,
    );
    const downloadMs = Date.now() - tDownload;

    const stream = Readable.fromWeb(res.body as never);
    controller.signal.addEventListener("abort", () => stream.destroy(new Error("Download timed out.")), { once: true });
    const tExtract = Date.now();
    const stats = await extractArchiveSafely(stream, sourceDir, params.config);
    const extractionMs = Date.now() - tExtract;
    clearTimeout(timer);

    const result = await applyAndRescanInSandbox({
      originalFindings: baseline,
      targetedFingerprints: params.targetedFingerprints,
      unifiedDiff: params.unifiedDiff,
      sourceDir,
      scanEngine: params.scanEngine,
    });
    result.summary.snapshot = { commitSha: params.commitSha, fileCount: stats.fileCount };
    result.summary.timings = { ...result.summary.timings, downloadMs, extractionMs };
    return result;
  } finally {
    clearTimeout(timer);
    await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  }
}
