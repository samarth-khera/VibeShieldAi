import type { JobStore, FindingRecord } from "../job-store";
import {
  AiExplanationSchema,
  type AiFindingExplanation,
  type CachedAiExplanation,
  type AiExplainResult,
} from "./types";
import { AI_PROMPT_VERSION, SYSTEM_PROMPT, buildUserPrompt, computeContextHash } from "./prompts";
import { getLlmProvider, type LlmProvider } from "./client";
import { tripAiCircuitBreaker, recordAiRequest } from "./circuit-breaker";
import { isQuotaExhaustedError } from "./gemini-provider";

function extractJson(text: string): string {
  const trimmed = text.trim();
  // Strip markdown fences if present
  if (trimmed.startsWith("```")) {
    const lines = trimmed.split("\n");
    if (lines.length >= 2) {
      const start = 1;
      const end = lines[lines.length - 1].trim().startsWith("```") ? lines.length - 1 : lines.length;
      return lines.slice(start, end).join("\n").trim();
    }
  }
  return trimmed;
}

export async function explainFinding(
  jobId: string,
  findingId: string,
  deps: {
    store: JobStore;
    provider?: LlmProvider;
    timeoutMs?: number;
    maxTokens?: number;
    clientIpHash?: string;
  }
): Promise<AiExplainResult> {
  const finding: FindingRecord | null = await deps.store.getFinding(jobId, findingId).catch(() => null);
  if (!finding) {
    throw new Error("Finding not found");
  }

  const provider = deps.provider || getLlmProvider();
  const modelName = provider.getModelName();

  if (!provider.isConfigured()) {
    return {
      available: false,
      code: "ai_not_configured",
      message:
        "Local AI Security Analyst is currently unavailable or disabled on the server.",
    };
  }

  const contextHash = computeContextHash(finding, AI_PROMPT_VERSION, modelName);
  const cacheKey = `${finding.fingerprint}:${contextHash}:${AI_PROMPT_VERSION}:${modelName}`;

  // Check if finding already has a valid cached explanation
  const existingCache = finding.aiExplanation as CachedAiExplanation | undefined;
  if (
    existingCache &&
    existingCache.cacheKey === cacheKey &&
    existingCache.explanation
  ) {
    const parseResult = AiExplanationSchema.safeParse(existingCache.explanation);
    if (parseResult.success) {
      return {
        available: true,
        cached: true,
        model: existingCache.model,
        explanation: parseResult.data,
        generatedAt: existingCache.generatedAt,
      };
    }
  }

  // Not in cache: call provider
  const userPrompt = buildUserPrompt(finding);
  let rawText: string;

  try {
    rawText = await provider.generateText({
      system: SYSTEM_PROMPT,
      userPrompt,
      format: "json",
      maxTokens:
        deps.maxTokens ??
        Number.parseInt(process.env.AI_MAX_OUTPUT_TOKENS || "800", 10),
      timeoutMs:
        deps.timeoutMs ??
        Number.parseInt(process.env.OLLAMA_TIMEOUT_MS || process.env.AI_REQUEST_TIMEOUT_MS || "120000", 10),
    });
  } catch (err: unknown) {
    if (isQuotaExhaustedError(err)) {
      await tripAiCircuitBreaker({
        reason: "quota_exhausted",
        message:
          "AI Security Analyst is temporarily offline due to upstream daily quota limits. Security scanners remain fully operational.",
      }).catch(() => undefined);
      return {
        available: false,
        code: "quota_exhausted",
        message:
          "AI Security Analyst is temporarily unavailable due to upstream daily quota limits. Security scanner findings remain fully accessible.",
      };
    }
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("timed out") || message.includes("timeout")) {
      return {
        available: false,
        code: "timeout",
        message: "The AI analysis request timed out. Please try again.",
      };
    }
    if (message.includes("not installed in Ollama") || message.includes("not found")) {
      return {
        available: false,
        code: "model_missing",
        message: `The configured local model is not installed in Ollama (${provider.getModelName()}). Please pull the model on the host.`,
      };
    }
    if (
      message.includes("service is unavailable") ||
      message.includes("ECONNREFUSED") ||
      message.includes("Failed to fetch")
    ) {
      return {
        available: false,
        code: "service_unavailable",
        message:
          "The AI inference service is temporarily offline or unreachable. Scanner findings and static guidance remain accessible.",
      };
    }
    return {
      available: false,
      code: "provider_error",
      message: "The AI provider encountered an issue analyzing this finding. Please retry shortly.",
    };
  }

  let parsedJson: unknown;
  try {
    const cleanJson = extractJson(rawText);
    parsedJson = JSON.parse(cleanJson);
  } catch {
    return {
      available: false,
      code: "invalid_response",
      message: "The AI analysis returned malformed output. Please retry.",
    };
  }

  const validation = AiExplanationSchema.safeParse(parsedJson);
  if (!validation.success) {
    return {
      available: false,
      code: "invalid_response",
      message: "The AI explanation failed schema validation. Please retry.",
    };
  }

  const explanation: AiFindingExplanation = validation.data;
  const now = new Date().toISOString();

  const cacheObject: CachedAiExplanation = {
    cacheKey,
    fingerprint: finding.fingerprint,
    contextHash,
    promptVersion: AI_PROMPT_VERSION,
    model: modelName,
    generatedAt: now,
    explanation,
  };

  // Persist cached explanation to database
  await deps.store.saveFindingAiExplanation(jobId, finding.id, cacheObject).catch((err) => {
    // Non-fatal: if caching fails, return the valid explanation to the client anyway
    console.error("Failed to persist AI explanation cache:", err);
  });

  if (deps.clientIpHash) {
    await recordAiRequest({
      clientIpHash: deps.clientIpHash,
      scanJobId: jobId,
      findingId: finding.id,
      action: "explain",
      success: true,
    }).catch(() => undefined);
  }

  return {
    available: true,
    cached: false,
    model: modelName,
    explanation,
    generatedAt: now,
  };
}
