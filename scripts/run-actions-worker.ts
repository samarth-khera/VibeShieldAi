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
import { OllamaProvider } from "../src/server/ai/client";
import { SYSTEM_PROMPT, buildUserPrompt, computeContextHash, AI_PROMPT_VERSION } from "../src/server/ai/prompts";
import { AiExplanationSchema } from "../src/server/ai/types";
import { classifyRemediationEligibility } from "../src/server/remediation/eligibility";
import { generateRemediationPatch } from "../src/server/remediation/patch";
import { signCallbackPayload } from "../src/server/callback-auth";
import { randomUUID } from "node:crypto";

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

    console.log("Fetching repository metadata and commit SHA...");
    const meta = await fetchRepoMetadata(fetch, parsed.owner, parsed.repo, config, controller.signal);
    const commitSha = await fetchCommitSha(fetch, parsed.owner, parsed.repo, meta.defaultBranch, config, controller.signal);

    console.log(`Commit: ${commitSha} on branch ${meta.defaultBranch}`);

    // Bounded download and safe extraction
    console.log("Downloading bounded archive snapshot...");
    const res = await openArchive(fetch, parsed.owner, parsed.repo, commitSha, config, controller.signal);
    const declaredArchiveBytes = Number.parseInt(res.headers.get("content-length") ?? "", 10);

    workspace = await mkdtemp(path.join(tmpdir(), "vibeshield-run-"));
    await chmod(workspace, 0o700);
    const sourceDir = path.join(workspace, "src");

    const sourceStream = Readable.fromWeb(res.body as never);
    controller.signal.addEventListener("abort", () => sourceStream.destroy(new Error("Download timed out.")), {
      once: true,
    });

    console.log("Extracting archive safely with resource limits...");
    const stats = await extractArchiveSafely(sourceStream, sourceDir, config);
    clearTimeout(timer);
    console.log(`Extracted ${stats.fileCount} files (${(stats.unpackedBytes / 1024 / 1024).toFixed(2)} MB).`);

    // Execute real security scanning engine
    console.log("Running Gitleaks, Semgrep, and OSV-Scanner...");
    const scanResult = await runSecurityScanEngine(sourceDir);
    console.log(`Scan completed with status: ${scanResult.status}`);
    console.log(`Findings count: ${scanResult.findings.length} (Critical: ${scanResult.counts.critical}, High: ${scanResult.counts.high}, Medium: ${scanResult.counts.medium}, Low: ${scanResult.counts.low}, Info: ${scanResult.counts.info})`);

    // Local AI inference via Ollama
    const ollamaUrl = process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434";
    const ollamaModel = process.env.OLLAMA_MODEL || "qwen3.5:2b";
    let ollamaProvider: OllamaProvider | null = null;

    try {
      const pingRes = await fetch(`${ollamaUrl}/api/tags`, { signal: AbortSignal.timeout(3000) });
      if (pingRes.ok) {
        ollamaProvider = new OllamaProvider({
          baseUrl: ollamaUrl,
          modelName: ollamaModel,
          timeoutMs: 45_000,
          maxConcurrency: 1,
        });
        console.log(`Connected to local Ollama on ephemeral runner with model ${ollamaModel}.`);
      }
    } catch {
      console.log("Local Ollama is not active or unavailable on this runner. Skipping precomputed AI explanations.");
    }

    const precomputedRemediations: Array<{
      id: string;
      findingFingerprints: string[];
      commitSha: string;
      patchSummary: string;
      unifiedDiff: string;
      affectedFiles: string[];
      eligibility: "safe" | "potentially_breaking" | "unsuitable";
      eligibilityReason: string;
      requiresRotation: boolean;
      warnings?: string[];
    }> = [];

    // Precompute explanations and fixes for high/critical findings (bounded to top 5)
    if (ollamaProvider) {
      const targetFindings = scanResult.findings
        .filter((f) => f.severity === "critical" || f.severity === "high")
        .slice(0, 5);

      for (const finding of targetFindings) {
        try {
          console.log(`Generating local AI explanation for ${finding.ruleId} (${finding.filePath}:${finding.startLine})...`);
          const userPrompt = buildUserPrompt(finding as never);
          const rawExplanation = await ollamaProvider.generateText({
            system: SYSTEM_PROMPT,
            userPrompt,
            format: "json",
            maxTokens: 1000,
            timeoutMs: 35_000,
          });

          let parsedExplanation;
          try {
            const cleaned = rawExplanation.trim().replace(/^```(?:json)?\n?/i, "").replace(/\n?```$/i, "").trim();
            parsedExplanation = JSON.parse(cleaned);
          } catch {
            // Non-JSON fallback
          }

          if (parsedExplanation) {
            const valid = AiExplanationSchema.safeParse(parsedExplanation);
            if (valid.success) {
              const contextHash = computeContextHash(finding as never, AI_PROMPT_VERSION, ollamaModel);
              finding.aiExplanation = {
                explanation: valid.data,
                generatedAt: new Date().toISOString(),
                model: ollamaModel,
                promptVersion: AI_PROMPT_VERSION,
                contextHash,
                cacheKey: `${finding.fingerprint}:${contextHash}:${AI_PROMPT_VERSION}:${ollamaModel}`,
              };
            }
          }

          // Remediation preview if eligible
          const eligibility = classifyRemediationEligibility(finding);
          if (eligibility.canAutoFix) {
            console.log(`Generating proposed remediation diff for ${finding.ruleId}...`);
            const patchRes = await generateRemediationPatch({
              finding: finding as never,
              scanJobId: jobId,
              commitSha,
              llmProvider: ollamaProvider,
            });

            if (patchRes.unifiedDiff) {
              precomputedRemediations.push({
                id: randomUUID(),
                findingFingerprints: [finding.fingerprint],
                commitSha,
                patchSummary: patchRes.patchSummary,
                unifiedDiff: patchRes.unifiedDiff,
                affectedFiles: patchRes.affectedFiles,
                eligibility: eligibility.eligibility,
                eligibilityReason: eligibility.reason,
                requiresRotation: eligibility.requiresRotation,
                warnings: eligibility.warnings,
              });
            }
          }
        } catch (aiErr) {
          console.warn(`AI precomputation error for finding ${finding.fingerprint}:`, aiErr);
        }
      }
    }

    // Sanitize all findings before sending
    for (const f of scanResult.findings) {
      if (f.redactedEvidence) {
        f.redactedEvidence = redactText(f.redactedEvidence);
      }
    }

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
      remediations: precomputedRemediations,
    };

    console.log("Signing payload and sending callback to Vercel control plane...");
    await postCallback(callbackUrl, callbackSecret, callbackPayload);
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
