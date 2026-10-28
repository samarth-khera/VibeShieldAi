import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { parseGithubRepoUrl } from "../src/lib/github-url";
import { getConfig } from "../src/server/config";
import { fetchCommitSha, fetchRepoMetadata, openArchive } from "../src/server/github";
import { extractArchiveSafely } from "../src/server/archive";
import { runSecurityScanEngine } from "../src/server/scanners/engine";
import { redactText } from "../src/server/scanners/redact";
import { signCallbackPayload, verificationSpecSigningPayload } from "../src/server/callback-auth";
import { verifyRemediationOnSnapshot } from "../src/server/remediation/verify";
import type { RescanComparison } from "../src/server/remediation/types";
import type { BaselineFinding } from "../src/server/remediation/sandbox";

type RunContext = {
  jobId: string;
  repoUrl: string;
  callbackUrl: string;
  callbackSecret: string;
  runId?: string;
  runUrl?: string;
  runnerStartedAt?: string;
};

async function main() {
  const mode = process.env.WORKER_MODE?.trim() || "scan";
  const jobId = process.env.JOB_ID?.trim();
  const repoUrl = process.env.REPOSITORY_URL?.trim();
  const callbackUrl = process.env.CALLBACK_URL?.trim();
  const callbackSecret = process.env.CALLBACK_SECRET?.trim();

  if (!jobId || !repoUrl || !callbackUrl || !callbackSecret) {
    console.error("Missing required environment variables (JOB_ID, REPOSITORY_URL, CALLBACK_URL, CALLBACK_SECRET).");
    process.exit(1);
  }

  const runId = process.env.GITHUB_RUN_ID;
  const serverUrl = process.env.GITHUB_SERVER_URL || "https://github.com";
  const githubRepo = process.env.GITHUB_REPOSITORY;
  const ctx: RunContext = {
    jobId,
    repoUrl,
    callbackUrl,
    callbackSecret,
    runId,
    runUrl: runId && githubRepo ? `${serverUrl}/${githubRepo}/actions/runs/${runId}` : undefined,
    runnerStartedAt: process.env.RUNNER_STARTED_AT?.trim() || undefined,
  };

  if (mode === "verify") {
    const remediationId = process.env.REMEDIATION_ID?.trim();
    if (!remediationId) {
      console.error("Missing REMEDIATION_ID for verify mode.");
      process.exit(1);
    }
    await runVerification(ctx, remediationId);
  } else {
    await runScan(ctx);
  }
}

async function runScan(ctx: RunContext) {
  const { jobId, repoUrl, callbackUrl, callbackSecret, runId, runUrl } = ctx;
  console.log(`Starting VibeShield AI scan worker for job ${jobId} (${repoUrl})`);

  const parsed = parseGithubRepoUrl(repoUrl);
  if (!parsed.ok) {
    console.error(`Invalid repository URL: ${parsed.error}`);
    await postFailure(ctx, "invalid_repository", parsed.error);
    process.exit(1);
  }

  const config = getConfig();
  let workspace: string | null = null;
  const progress: Record<string, string> = ctx.runnerStartedAt ? { worker_startedAt: ctx.runnerStartedAt } : {};
  const heartbeat = async (phase: string, extra: Record<string, unknown> = {}) => {
    const at = new Date().toISOString();
    progress[`${phase}At`] = at;
    await postProgress(ctx, { phase, at, ...extra });
  };

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.retrievalTimeoutMs);
    const t0 = Date.now();

    await heartbeat("retrieving");
    const tMeta = Date.now();
    const meta = await fetchRepoMetadata(fetch, parsed.owner, parsed.repo, config, controller.signal);
    const commitSha = await fetchCommitSha(fetch, parsed.owner, parsed.repo, meta.defaultBranch, config, controller.signal);
    const metadataDurationMs = Date.now() - tMeta;
    console.log(`Commit: ${commitSha} on branch ${meta.defaultBranch} (metadata: ${metadataDurationMs}ms)`);

    const tDownload = Date.now();
    const res = await openArchive(fetch, parsed.owner, parsed.repo, commitSha, config, controller.signal);
    const declaredArchiveBytes = Number.parseInt(res.headers.get("content-length") ?? "", 10);
    const downloadDurationMs = Date.now() - tDownload;

    workspace = await mkdtemp(path.join(tmpdir(), "vibeshield-run-"));
    await chmod(workspace, 0o700);
    const sourceDir = path.join(workspace, "src");
    const sourceStream = Readable.fromWeb(res.body as never);
    controller.signal.addEventListener("abort", () => sourceStream.destroy(new Error("Download timed out.")), {
      once: true,
    });

    await heartbeat("extracting", { commitSha, defaultBranch: meta.defaultBranch });
    const tExtract = Date.now();
    const stats = await extractArchiveSafely(sourceStream, sourceDir, config);
    clearTimeout(timer);
    const extractDurationMs = Date.now() - tExtract;
    console.log(`Extracted ${stats.fileCount} files (${(stats.unpackedBytes / 1024 / 1024).toFixed(2)} MB) in ${extractDurationMs}ms.`);

    await heartbeat("scanning");
    const tScan = Date.now();
    const scanResult = await runSecurityScanEngine(sourceDir);
    const scanEngineDurationMs = Date.now() - tScan;
    console.log(
      `Scan ${scanResult.status} in ${scanEngineDurationMs}ms (Gitleaks: ${scanResult.gitleaksDurationMs}ms, Semgrep: ${scanResult.semgrepDurationMs}ms, OSV: ${scanResult.osvDurationMs}ms); findings: ${scanResult.findings.length}`,
    );

    for (const f of scanResult.findings) {
      if (f.redactedEvidence) f.redactedEvidence = redactText(f.redactedEvidence);
    }

    const stageDurations = {
      metadataMs: metadataDurationMs,
      downloadMs: downloadDurationMs,
      extractionMs: extractDurationMs,
      scanningMs: scanEngineDurationMs,
      callbackMs: 0,
    };
    scanResult.scanCoverage.stageDurations = stageDurations;
    (scanResult.scanCoverage as unknown as Record<string, unknown>).progress = progress;

    const callbackPayload = {
      jobId: ctx.jobId,
      status: scanResult.status,
      workflowRunId: runId,
      workflowRunUrl: runUrl,
      commitSha,
      archiveBytes: Number.isFinite(declaredArchiveBytes) ? declaredArchiveBytes : null,
      fileCount: stats.fileCount,
      unpackedBytes: stats.unpackedBytes,
      gitleaksStatus: scanResult.gitleaksStatus,
      gitleaksDurationMs: scanResult.gitleaksDurationMs,
      gitleaksError: scanResult.gitleaksError,
      semgrepStatus: scanResult.semgrepStatus,
      semgrepDurationMs: scanResult.semgrepDurationMs,
      semgrepError: scanResult.semgrepError,
      osvStatus: scanResult.osvStatus,
      osvDurationMs: scanResult.osvDurationMs,
      osvError: scanResult.osvError,
      scannerVersions: scanResult.scannerVersions as unknown as Record<string, unknown>,
      scanCoverage: scanResult.scanCoverage as unknown as Record<string, unknown>,
      counts: scanResult.counts,
      findings: scanResult.findings,
      remediations: [],
    };

    const tCallback = Date.now();
    await postSigned(callbackUrl, callbackSecret, callbackPayload);
    const callbackDurationMs = Date.now() - tCallback;
    console.log(
      `[Metrics] job=${jobId} metadata=${metadataDurationMs}ms download=${downloadDurationMs}ms extraction=${extractDurationMs}ms scanning=${scanEngineDurationMs}ms callback=${callbackDurationMs}ms total=${Date.now() - t0}ms`,
    );
  } catch (err: unknown) {
    console.error("Scan worker failed:", err instanceof Error ? redactText(err.message) : "unknown error");
    await postFailure(ctx, "scan_failed", err instanceof Error ? err.message : String(err));
    process.exit(1);
  } finally {
    if (workspace) await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  }
}

type VerificationSpec = {
  scanJobId: string;
  remediationId: string;
  owner: string;
  repo: string;
  commitSha: string;
  unifiedDiff: string;
  targetedFingerprints: string[];
  baselineFindings: BaselineFinding[];
  queuedAt: string;
};

async function runVerification(ctx: RunContext, remediationId: string) {
  const { jobId, callbackUrl, callbackSecret } = ctx;
  console.log(`Starting VibeShield AI verification worker for job ${jobId}, remediation ${remediationId}`);
  const t0 = Date.now();

  const postResult = (rescanStatus: "verified" | "needs_review" | "failed", summary: RescanComparison) =>
    postSigned(callbackUrl, callbackSecret, { scanJobId: jobId, remediationId, rescanStatus, summary });

  try {
    // The approved diff and commit come from server-side storage, never from workflow inputs.
    const tSpec = Date.now();
    const res = await fetch(callbackUrl, {
      headers: {
        "X-VibeShield-Signature": signCallbackPayload(verificationSpecSigningPayload(jobId, remediationId), callbackSecret),
        "User-Agent": "VibeShieldAI-Worker/0.2",
      },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`Verification spec request returned HTTP ${res.status}.`);
    const spec = ((await res.json()) as { data: VerificationSpec }).data;
    const specFetchMs = Date.now() - tSpec;

    const parsed = parseGithubRepoUrl(ctx.repoUrl);
    if (
      spec.scanJobId !== jobId ||
      spec.remediationId !== remediationId ||
      !parsed.ok ||
      parsed.owner.toLowerCase() !== spec.owner.toLowerCase() ||
      parsed.repo.toLowerCase() !== spec.repo.toLowerCase()
    ) {
      throw new Error("Verification spec does not match the dispatched job.");
    }
    console.log(`Verifying ${spec.owner}/${spec.repo}@${spec.commitSha} against ${spec.baselineFindings.length} baseline findings`);

    const result = await verifyRemediationOnSnapshot({
      owner: spec.owner,
      repo: spec.repo,
      commitSha: spec.commitSha,
      unifiedDiff: spec.unifiedDiff,
      targetedFingerprints: spec.targetedFingerprints,
      baselineFindings: spec.baselineFindings,
      config: getConfig(),
    });

    const queuedAt = Date.parse(spec.queuedAt);
    result.summary.workflowRunUrl = ctx.runUrl;
    result.summary.timings = {
      ...result.summary.timings,
      specFetchMs,
      queueMs: Number.isFinite(queuedAt) ? Math.max(0, t0 - queuedAt) : undefined,
      totalMs: Date.now() - t0,
    };
    console.log(
      `[Metrics] verification=${result.rescanStatus} reason=${result.summary.reason ?? "none"} timings=${JSON.stringify(result.summary.timings)} scanners=${JSON.stringify(result.summary.scannerStatuses ?? {})}`,
    );
    await postResult(result.rescanStatus, result.summary);
  } catch (err: unknown) {
    const message = redactText(err instanceof Error ? err.message : String(err)).slice(0, 280);
    console.error("Verification worker failed:", message);
    await postResult("failed", {
      targetResolved: false,
      originalFindingsCount: 0,
      postRescanFindingsCount: 0,
      newFindingsCount: 0,
      resolvedFingerprints: [],
      remainingFingerprints: [],
      regressions: [],
      reason: "worker_failed",
      detail: message,
      workflowRunUrl: ctx.runUrl,
      timings: { totalMs: Date.now() - t0 },
    }).catch(() => console.error("Could not report verification failure."));
    process.exit(1);
  }
}

/** Best-effort, single-attempt heartbeat: progress reporting must never fail a scan. */
async function postProgress(ctx: RunContext, fields: Record<string, unknown>) {
  const json = JSON.stringify({
    type: "progress",
    jobId: ctx.jobId,
    workflowRunId: ctx.runId,
    workflowRunUrl: ctx.runUrl,
    ...fields,
  });
  try {
    await fetch(ctx.callbackUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VibeShield-Signature": signCallbackPayload(json, ctx.callbackSecret),
        "User-Agent": "VibeShieldAI-Worker/0.2",
      },
      body: json,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    console.warn(`Progress heartbeat '${String(fields.phase)}' could not be delivered.`);
  }
}

async function postSigned(url: string, secret: string, payload: unknown): Promise<void> {
  const json = JSON.stringify(payload);
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      // Re-sign each attempt so retries stay inside the replay window.
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-VibeShield-Signature": signCallbackPayload(json, secret),
          "User-Agent": "VibeShieldAI-Worker/0.2",
        },
        body: json,
        signal: AbortSignal.timeout(30_000),
      });
      if (res.ok) return;
      console.warn(`Callback attempt ${attempt} returned HTTP ${res.status}.`);
    } catch {
      console.warn(`Callback attempt ${attempt} failed with a network error.`);
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }
  throw new Error("Failed to post callback after 3 attempts.");
}

async function postFailure(ctx: RunContext, category: string, error: string): Promise<void> {
  await postSigned(ctx.callbackUrl, ctx.callbackSecret, {
    jobId: ctx.jobId,
    status: "failed",
    workflowRunId: ctx.runId,
    workflowRunUrl: ctx.runUrl,
    failureCategory: category,
    errorMessage: redactText(error).slice(0, 300),
    findings: [],
  }).catch(() => console.error("Could not post failure state to callback."));
}

main().catch((err) => {
  console.error("Fatal runner crash:", err instanceof Error ? redactText(err.message) : "unknown");
  process.exit(1);
});
