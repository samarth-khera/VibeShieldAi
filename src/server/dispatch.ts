import type { ServerConfig } from "./config";
import { enqueueRetrieval } from "./queue";

export type DispatchResult =
  | { success: true; backend: "github-actions" | "bullmq"; workflowRef?: string }
  | { success: false; error: string; statusCode?: number };

/**
 * Dispatches a scan job for execution.
 * In production (zero-cost architecture), dispatches an ephemeral GitHub Actions workflow
 * on the public VibeShield AI repository at ₹0 cost.
 * In local Docker development, falls back to BullMQ if configured.
 */
export async function dispatchScanJob(
  jobId: string,
  repositoryUrl: string,
  config: ServerConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<DispatchResult> {
  if (config.scanDispatchBackend === "bullmq") {
    try {
      await enqueueRetrieval(jobId, 0);
      return { success: true, backend: "bullmq" };
    } catch (err) {
      return {
        success: false,
        error: `Local BullMQ queue failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  const appUrl = config.appUrl.replace(/\/+$/, "");
  return dispatchWorkflow(
    {
      mode: "scan",
      job_id: jobId,
      repository_url: repositoryUrl,
      callback_url: `${appUrl}/api/scans/${encodeURIComponent(jobId)}/callback`,
    },
    config,
    fetchImpl,
  );
}

/**
 * Starts the verification worker for an approved remediation. Only identifiers travel as workflow
 * inputs: the worker fetches the approved diff and the commit SHA from the signed verification
 * endpoint, so an arbitrary patch can never be injected through the workflow form.
 */
export async function dispatchRemediationVerification(
  jobId: string,
  remediationId: string,
  repositoryUrl: string,
  config: ServerConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<DispatchResult> {
  const appUrl = config.appUrl.replace(/\/+$/, "");
  return dispatchWorkflow(
    {
      mode: "verify",
      job_id: jobId,
      remediation_id: remediationId,
      repository_url: repositoryUrl,
      callback_url: `${appUrl}/api/scans/${encodeURIComponent(jobId)}/remediation/${encodeURIComponent(remediationId)}/verification`,
    },
    config,
    fetchImpl,
  );
}

async function dispatchWorkflow(
  inputs: Record<string, string>,
  config: ServerConfig,
  fetchImpl: typeof fetch,
): Promise<DispatchResult> {
  if (!config.githubDispatchToken) {
    return {
      success: false,
      error: "GitHub Actions workflow dispatch token (GITHUB_DISPATCH_TOKEN or GITHUB_TOKEN) is not configured.",
    };
  }

  const dispatchUrl = `https://api.github.com/repos/${config.githubRepository}/actions/workflows/scanner-worker.yml/dispatches`;
  const payload = { ref: config.githubWorkflowRef || "main", inputs };

  try {
    const res = await fetchImpl(dispatchUrl, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${config.githubDispatchToken}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VibeShieldAI-Dispatcher/0.1",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (res.status === 204) {
      return { success: true, backend: "github-actions", workflowRef: config.githubWorkflowRef };
    }

    const errorBody = await res.text().catch(() => "");
    return {
      success: false,
      statusCode: res.status,
      error: `GitHub Actions dispatch failed (HTTP ${res.status}): ${errorBody.slice(0, 200) || "Unknown error"}`,
    };
  } catch (netErr) {
    return {
      success: false,
      error: `Network error dispatching GitHub Actions workflow: ${netErr instanceof Error ? netErr.message : String(netErr)}`,
    };
  }
}
