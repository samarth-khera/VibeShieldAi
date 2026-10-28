// Dependency-free status reporter for the scanner workflow. It runs before `npm ci` (to report that a
// runner picked the job up) and after any failed or cancelled step (so a job never stays pending
// because setup broke before the TypeScript worker could report). Uses only Node built-ins and the
// same `t=<ts>,v1=<hmac>` signature format as src/server/callback-auth.ts.
//
// Usage: node scripts/ci/post-worker-status.mjs started
//        node scripts/ci/post-worker-status.mjs failed <category> <message>
import { createHmac } from "node:crypto";

const [, , event, category = "worker_failed", message = "The scanner worker failed before completing."] = process.argv;
const env = (name) => process.env[name]?.trim() || "";

const mode = env("WORKER_MODE") || "scan";
const jobId = env("JOB_ID");
const remediationId = env("REMEDIATION_ID");
const callbackUrl = env("CALLBACK_URL");
const secret = env("CALLBACK_SECRET");
const runId = env("GITHUB_RUN_ID");
const runUrl = runId ? `${env("GITHUB_SERVER_URL") || "https://github.com"}/${env("GITHUB_REPOSITORY")}/actions/runs/${runId}` : undefined;

function allowedCallback(raw) {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" || url.hostname === "localhost" || url.hostname === "127.0.0.1";
  } catch {
    return false;
  }
}

function payloadFor() {
  const at = new Date().toISOString();
  if (event === "started") {
    // Verification has no separate heartbeat; its remediation stays `applied` until the result.
    if (mode !== "scan") return null;
    return { type: "progress", jobId, phase: "worker_started", at, workflowRunId: runId, workflowRunUrl: runUrl };
  }
  if (event === "failed") {
    if (mode === "verify") {
      return {
        scanJobId: jobId,
        remediationId,
        rescanStatus: "failed",
        summary: {
          targetResolved: false,
          originalFindingsCount: 0,
          postRescanFindingsCount: 0,
          newFindingsCount: 0,
          resolvedFingerprints: [],
          remainingFingerprints: [],
          regressions: [],
          reason: "worker_failed",
          detail: message.slice(0, 280),
          workflowRunUrl: runUrl,
        },
      };
    }
    return {
      jobId,
      status: "failed",
      workflowRunId: runId,
      workflowRunUrl: runUrl,
      failureCategory: category.slice(0, 40),
      errorMessage: message.slice(0, 300),
      findings: [],
    };
  }
  throw new Error(`Unknown event: ${event}`);
}

async function main() {
  if (!jobId || !callbackUrl || !secret || !allowedCallback(callbackUrl)) {
    console.warn("Worker status not reported: callback configuration is missing or invalid.");
    return;
  }
  const payload = payloadFor();
  if (!payload) return;
  const json = JSON.stringify(payload);
  for (let attempt = 1; attempt <= 3; attempt++) {
    const t = Math.floor(Date.now() / 1000);
    const signature = `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${json}`).digest("hex")}`;
    try {
      const res = await fetch(callbackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-VibeShield-Signature": signature, "User-Agent": "VibeShieldAI-Worker/0.2" },
        body: json,
        signal: AbortSignal.timeout(15_000),
      });
      console.log(`Worker status '${event}' reported (HTTP ${res.status}).`);
      if (res.ok || res.status < 500) return;
    } catch {
      console.warn(`Worker status '${event}' attempt ${attempt} failed.`);
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }
}

// Reporting must never change the job's own outcome.
main().catch(() => console.warn("Worker status reporting failed."));
