import { randomUUID } from "node:crypto";
import type { JobStore, FindingRecord } from "../job-store";
import {
  AiExplanationSchema,
  AiExplanationJsonSchema,
  type AiFindingExplanation,
  type CachedAiExplanation,
  type AiExplainResult,
} from "./types";
import { AI_PROMPT_VERSION, SYSTEM_PROMPT, buildUserPrompt, computeContextHash } from "./prompts";
import { getLlmProvider, type LlmProvider } from "./client";
import { tripAiCircuitBreaker, recordAiRequest } from "./circuit-breaker";
import { isQuotaExhaustedError, GeminiTruncatedOutputError } from "./gemini-provider";

export class TruncatedJsonError extends Error {
  readonly isTruncated = true;
  constructor(message: string) {
    super(message);
    this.name = "TruncatedJsonError";
  }
}

/**
 * Extracts a JSON object from text using a string/escape-aware balanced brace parser.
 * Handles pure JSON, markdown fenced blocks, and harmless surrounding text.
 * Throws TruncatedJsonError if opening braces remain unclosed at EOF.
 * Throws SyntaxError if no valid JSON object can be extracted.
 */
export function extractJson(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new SyntaxError("Empty AI response received.");
  }

  // 1. If text contains a markdown fence ```...```, try extracting from the fence first
  const fenceMatch = trimmed.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (fenceMatch && fenceMatch[1]) {
    const candidate = fenceMatch[1].trim();
    if (candidate.startsWith("{") && candidate.endsWith("}")) {
      try {
        JSON.parse(candidate);
        return candidate;
      } catch {
        // Fall through to balanced brace parser
      }
    }
  }

  // 2. String/escape-aware balanced-brace parser
  let startIndex = -1;
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === "\\") {
      if (inString) {
        escape = true;
      }
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      continue;
    }

    if (!inString) {
      if (ch === "{") {
        if (depth === 0) {
          startIndex = i;
        }
        depth++;
      } else if (ch === "}") {
        if (depth > 0) {
          depth--;
          if (depth === 0 && startIndex !== -1) {
            const candidate = trimmed.slice(startIndex, i + 1);
            try {
              JSON.parse(candidate);
              return candidate;
            } catch {
              // Not valid JSON object; reset and keep scanning
              startIndex = -1;
            }
          }
        }
      }
    }
  }

  // If we found a start brace that remained unclosed at EOF, it's truncated output
  if (startIndex !== -1 && (depth > 0 || inString)) {
    throw new TruncatedJsonError("AI response was cut off before closing JSON object.");
  }

  // 3. Fallback: try parsing trimmed text directly
  try {
    JSON.parse(trimmed);
    return trimmed;
  } catch {
    throw new SyntaxError("No valid balanced JSON object found in AI response.");
  }
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
  const correlationId = randomUUID().slice(0, 12);

  if (!provider.isConfigured()) {
    return {
      available: false,
      code: "ai_not_configured",
      message: "Local AI Security Analyst is currently unavailable or disabled on the server.",
      diagnostic: { correlationId, model: modelName, category: "not_configured" },
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
      responseSchema: AiExplanationJsonSchema,
      maxTokens:
        deps.maxTokens ??
        Number.parseInt(process.env.AI_MAX_OUTPUT_TOKENS || "1500", 10),
      timeoutMs:
        deps.timeoutMs ??
        Number.parseInt(process.env.AI_REQUEST_TIMEOUT_MS || "30000", 10),
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
        diagnostic: { correlationId, model: modelName, category: "quota_exhausted" },
      };
    }
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof GeminiTruncatedOutputError || message.includes("truncated") || message.includes("output token limit")) {
      return {
        available: false,
        code: "output_truncated",
        message: "The AI analysis response was truncated due to output limits. Please retry.",
        diagnostic: { correlationId, model: modelName, category: "output_truncated" },
      };
    }
    if (message.includes("timed out") || message.includes("timeout")) {
      return {
        available: false,
        code: "timeout",
        message: "The AI analysis request timed out. Please try again.",
        diagnostic: { correlationId, model: modelName, category: "timeout" },
      };
    }
    if (message.includes("not installed in Ollama") || message.includes("not found")) {
      return {
        available: false,
        code: "model_missing",
        message: `The configured local model is not installed in Ollama (${provider.getModelName()}). Please pull the model on the host.`,
        diagnostic: { correlationId, model: modelName, category: "model_missing" },
      };
    }
    if (
      message.includes("service is unavailable") ||
      message.includes("ECONNREFUSED") ||
      message.includes("Failed to fetch") ||
      message.includes("503")
    ) {
      return {
        available: false,
        code: "service_unavailable",
        message:
          "The AI inference service is temporarily offline or unreachable. Scanner findings and static guidance remain accessible.",
        diagnostic: { correlationId, model: modelName, category: "service_unavailable" },
      };
    }
    return {
      available: false,
      code: "provider_error",
      message: "The AI provider encountered an issue analyzing this finding. Please retry shortly.",
      diagnostic: { correlationId, model: modelName, category: "provider_error" },
    };
  }

  let parsedJson: unknown;
  try {
    const cleanJson = extractJson(rawText);
    parsedJson = JSON.parse(cleanJson);
  } catch (parseErr: unknown) {
    if (parseErr instanceof TruncatedJsonError) {
      return {
        available: false,
        code: "output_truncated",
        message: "The AI analysis response was truncated. Please retry.",
        diagnostic: { correlationId, model: modelName, category: "output_truncated" },
      };
    }
    return {
      available: false,
      code: "invalid_response",
      message: "The AI analysis returned malformed output. Please retry.",
      diagnostic: { correlationId, model: modelName, category: "malformed_json" },
    };
  }

  const validation = AiExplanationSchema.safeParse(parsedJson);
  if (!validation.success) {
    return {
      available: false,
      code: "schema_validation_failed",
      message: "The AI explanation failed schema validation. Please retry.",
      diagnostic: { correlationId, model: modelName, category: "schema_validation_failed" },
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
