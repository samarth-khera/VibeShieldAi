import { parseGithubRepoUrl } from "../src/lib/github-url";
import { getConfig } from "../src/server/config";
import { redactText } from "../src/server/scanners/redact";
import { verificationSpecSigningPayload } from "../src/server/callback-auth";
import { executeScanJob } from "../src/server/worker/scan-executor";
import { getSigned, postSigned } from "../src/server/worker/signed-http";
import { verifyRemediationOnSnapshot } from "../src/server/remediation/verify";
import type { VerificationProgressEvent } from "../src/server/remediation/sandbox";
import { PRIVATE_REPOSITORY } from "../src/server/worker/private-repository";
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
  console.log(`Starting VibeShield AI scan worker for job ${ctx.jobId} (${ctx.repoUrl})`);
  const outcome = await executeScanJob({
    jobId: ctx.jobId,
    repositoryUrl: ctx.repoUrl,
    callbackUrl: ctx.callbackUrl,
    secret: ctx.callbackSecret,
    runId: ctx.runId,
    runUrl: ctx.runUrl,
    runnerStartedAt: ctx.runnerStartedAt,
    config: getConfig(),
    log: (line) => console.log(line),
  });
  if (outcome === "failed") process.exit(1);
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
  /** Private repositories only: short-lived archive URL. Never logged. */
  archiveUrl?: string;
};

async function runVerification(ctx: RunContext, remediationId: string) {
  const { jobId, callbackUrl, callbackSecret } = ctx;
  console.log(`Starting VibeShield AI verification worker for job ${jobId}, remediation ${remediationId}`);
  const t0 = Date.now();

  const postResult = async (rescanStatus: "verified" | "needs_review" | "failed", summary: RescanComparison) => {
    const res = await postSigned(callbackUrl, callbackSecret, { scanJobId: jobId, remediationId, rescanStatus, summary });
    if (!res.ok) throw new Error(`Verification result rejected with HTTP ${res.status}.`);
  };

  try {
    // The approved diff and commit come from server-side storage, never from workflow inputs.
    const tSpec = Date.now();
    const res = await getSigned(callbackUrl, callbackSecret, verificationSpecSigningPayload(jobId, remediationId));
    if (!res.ok) throw new Error(`Verification spec request returned HTTP ${res.status}.`);
    const spec = ((await res.json()) as { data: VerificationSpec }).data;
    const specFetchMs = Date.now() - tSpec;

    // Private repositories are dispatched with a placeholder; their name stays out of public logs.
    const isPrivate = ctx.repoUrl === PRIVATE_REPOSITORY;
    const parsed = isPrivate ? null : parseGithubRepoUrl(ctx.repoUrl);
    if (
      spec.scanJobId !== jobId ||
      spec.remediationId !== remediationId ||
      (isPrivate
        ? !spec.archiveUrl
        : !parsed?.ok ||
          parsed.owner.toLowerCase() !== spec.owner.toLowerCase() ||
          parsed.repo.toLowerCase() !== spec.repo.toLowerCase())
    ) {
      throw new Error("Verification spec does not match the dispatched job.");
    }
    console.log(
      isPrivate
        ? `Verifying a private repository against ${spec.baselineFindings.length} baseline findings`
        : `Verifying ${spec.owner}/${spec.repo}@${spec.commitSha} against ${spec.baselineFindings.length} baseline findings`,
    );

    // Real progress for the report (snapshot prepared, patch applied, each scanner finished), signed
    // like the result and sent in order; a failed progress post never affects the verification.
    let progressChain: Promise<unknown> = Promise.resolve();
    const onProgress = async (progress: VerificationProgressEvent): Promise<void> => {
      progressChain = progressChain
        .then(() => postSigned(callbackUrl, callbackSecret, { scanJobId: jobId, remediationId, progress }))
        .catch(() => undefined);
      await progressChain;
    };
    const result = await verifyRemediationOnSnapshot({
      owner: spec.owner,
      repo: spec.repo,
      commitSha: spec.commitSha,
      unifiedDiff: spec.unifiedDiff,
      targetedFingerprints: spec.targetedFingerprints,
      baselineFindings: spec.baselineFindings,
      config: getConfig(),
      archiveUrl: isPrivate ? spec.archiveUrl : undefined,
      onProgress,
    });
    await progressChain;

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

main().catch((err) => {
  console.error("Fatal runner crash:", err instanceof Error ? redactText(err.message) : "unknown");
  process.exit(1);
});
