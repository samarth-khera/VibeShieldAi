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
import { signCallbackPayload } from "../src/server/callback-auth";

async function main() {
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
  const runUrl = runId && githubRepo ? `${serverUrl}/${githubRepo}/actions/runs/${runId}` : undefined;

  console.log(`Starting VibeShield AI runner for Job ${jobId}...`);
  console.log(`Repository: ${repoUrl}`);

  const parsed = parseGithubRepoUrl(repoUrl);
  if (!parsed.ok) {
    console.error(`Invalid repository URL: ${parsed.error}`);
    await postFailure(callbackUrl, callbackSecret, jobId, "invalid_repository", parsed.error, runId, runUrl);
    process.exit(1);
  }

  const config = getConfig();
  let workspace: string | null = null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.retrievalTimeoutMs);

    const t0 = Date.now();
    console.log("Fetching repository metadata and commit SHA...");
    const tMeta = Date.now();
    const meta = await fetchRepoMetadata(fetch, parsed.owner, parsed.repo, config, controller.signal);
    const commitSha = await fetchCommitSha(fetch, parsed.owner, parsed.repo, meta.defaultBranch, config, controller.signal);
    const metadataDurationMs = Date.now() - tMeta;

    console.log(`Commit: ${commitSha} on branch ${meta.defaultBranch} (retrieval: ${metadataDurationMs}ms)`);

    // Bounded download and safe extraction
    console.log("Downloading bounded archive snapshot...");
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

    console.log("Extracting archive safely with resource limits...");
    const tExtract = Date.now();
    const stats = await extractArchiveSafely(sourceStream, sourceDir, config);
    clearTimeout(timer);
    const extractDurationMs = Date.now() - tExtract;
    console.log(`Extracted ${stats.fileCount} files (${(stats.unpackedBytes / 1024 / 1024).toFixed(2)} MB in ${extractDurationMs}ms).`);

    // Execute real security scanning engine
    console.log("Running Gitleaks, Semgrep, and OSV-Scanner in parallel...");
    const tScan = Date.now();
    const scanResult = await runSecurityScanEngine(sourceDir);
    const scanEngineDurationMs = Date.now() - tScan;
    console.log(`Scan completed with status: ${scanResult.status} in ${scanEngineDurationMs}ms (Gitleaks: ${scanResult.gitleaksDurationMs}ms, Semgrep: ${scanResult.semgrepDurationMs}ms, OSV: ${scanResult.osvDurationMs}ms)`);
    console.log(`Findings count: ${scanResult.findings.length} (Critical: ${scanResult.counts.critical}, High: ${scanResult.counts.high}, Medium: ${scanResult.counts.medium}, Low: ${scanResult.counts.low}, Info: ${scanResult.counts.info})`);

    // Sanitize all findings before sending
    for (const f of scanResult.findings) {
      if (f.redactedEvidence) {
        f.redactedEvidence = redactText(f.redactedEvidence);
      }
    }

    const stageDurations = {
      metadataMs: metadataDurationMs,
      downloadMs: downloadDurationMs,
      extractionMs: extractDurationMs,
      scanningMs: scanEngineDurationMs,
      callbackMs: 0,
    };

    scanResult.scanCoverage.stageDurations = stageDurations;

    // Assemble payload
    const callbackPayload = {
      jobId,
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

    console.log("Signing payload and sending callback to Vercel control plane...");
    const tCallback = Date.now();
    await postCallback(callbackUrl, callbackSecret, callbackPayload);
    const callbackDurationMs = Date.now() - tCallback;
    stageDurations.callbackMs = callbackDurationMs;
    const totalPipelineDurationMs = Date.now() - t0;
    console.log(`[Metrics] Retrieval: ${metadataDurationMs}ms, Download: ${downloadDurationMs}ms, Extraction: ${extractDurationMs}ms, Scanning: ${scanEngineDurationMs}ms, Callback: ${callbackDurationMs}ms (Total: ${totalPipelineDurationMs}ms).`);
    console.log("Callback successfully accepted!");
  } catch (err: unknown) {
    console.error("Worker pipeline failed with error:", err);
    const message = err instanceof Error ? err.message : String(err);
    await postFailure(callbackUrl, callbackSecret, jobId, "scan_failed", message, runId, runUrl);
    process.exit(1);
  } finally {
    if (workspace) {
      await rm(workspace, { recursive: true, force: true }).catch(() => undefined);
      console.log("Temporary workspace cleaned up.");
    }
  }
}

async function postCallback(url: string, secret: string, payload: unknown): Promise<void> {
  const json = JSON.stringify(payload);
  const signature = signCallbackPayload(json, secret);

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-VibeShield-Signature": signature,
          "User-Agent": "VibeShieldAI-Worker/0.1",
        },
        body: json,
        signal: AbortSignal.timeout(30_000),
      });

      if (res.ok) return;

      const errText = await res.text().catch(() => "");
      console.warn(`Callback attempt ${attempt} returned HTTP ${res.status}: ${errText}`);
    } catch (netErr) {
      console.warn(`Callback attempt ${attempt} network error:`, netErr);
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }

  throw new Error("Failed to post callback after 3 attempts.");
}

async function postFailure(
  url: string,
  secret: string,
  jobId: string,
  category: string,
  error: string,
  runId?: string,
  runUrl?: string,
): Promise<void> {
  const payload = {
    jobId,
    status: "failed",
    workflowRunId: runId,
    workflowRunUrl: runUrl,
    failureCategory: category,
    errorMessage: error.slice(0, 300),
    findings: [],
  };
  await postCallback(url, secret, payload).catch((err) => {
    console.error("Could not post failure state to callback:", err);
  });
}

main().catch((err) => {
  console.error("Fatal runner crash:", err);
  process.exit(1);
});
