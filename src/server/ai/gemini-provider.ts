import { GoogleGenAI, ApiError } from "@google/genai";
import type { LlmMessageParams, LlmProvider } from "./client";
import { AiExplanationJsonSchema } from "./types";

export class GeminiQuotaExceededError extends Error {
  readonly status = 429;
  readonly isQuotaExhausted = true;

  constructor(message: string) {
    super(redactSecrets(message));
    this.name = "GeminiQuotaExceededError";
  }
}

export class GeminiTruncatedOutputError extends Error {
  readonly isTruncated = true;

  constructor(message: string) {
    super(redactSecrets(message));
    this.name = "GeminiTruncatedOutputError";
  }
}


/**
 * Strips Google API keys or sensitive authorization tokens from strings.
 */
export function redactSecrets(text: string): string {
  if (!text) return "";
  let sanitized = text.replace(/AIza[0-9A-Za-z_-]{35}/g, "[REDACTED_API_KEY]");
  const currentKey = process.env.GEMINI_API_KEY?.trim();
  if (currentKey && currentKey.length > 5) {
    sanitized = sanitized.replaceAll(currentKey, "[REDACTED_API_KEY]");
  }
  return sanitized;
}

/**
 * Checks if an error corresponds to an upstream quota exhaustion or rate limit (HTTP 429 / RESOURCE_EXHAUSTED).
 */
export function isQuotaExhaustedError(err: unknown): boolean {
  if (!err) return false;
  if (err instanceof GeminiQuotaExceededError) return true;

  if (typeof err === "object" && err !== null) {
    const errorObj = err as { status?: number; statusCode?: number; message?: string; code?: string | number };
    if (errorObj.status === 429 || errorObj.statusCode === 429 || errorObj.code === 429) {
      return true;
    }
    const message = String(errorObj.message || "").toLowerCase();
    if (
      message.includes("resource_exhausted") ||
      message.includes("quota exceeded") ||
      message.includes("quota_exhausted") ||
      message.includes("rate limit") ||
      message.includes("429")
    ) {
      return true;
    }
  }

  const str = String(err).toLowerCase();
  return (
    str.includes("resource_exhausted") ||
    str.includes("quota exceeded") ||
    str.includes("quota_exhausted") ||
    str.includes("rate limit") ||
    str.includes("429")
  );
}

export type GeminiProviderOptions = {
  apiKey?: string;
  modelName?: string;
  timeoutMs?: number;
  client?: GoogleGenAI;
};

/**
 * Server-side Gemini LLM Provider powered by official @google/genai SDK.
 *
 * Zero-Billing Guardrails:
 * - Operates strictly within Google AI Studio Free Tier limits.
 * - Detects 429 RESOURCE_EXHAUSTED immediately and halts retries.
 * - Never switches to a paid billing account or paid fallback provider.
 * - Redacts any potential API key tokens from errors, prompts, and logs.
 */
export class GeminiProvider implements LlmProvider {
  private readonly apiKey?: string;
  private readonly modelName: string;
  private readonly defaultTimeoutMs: number;
  private clientInstance: GoogleGenAI | null = null;

  constructor(options?: GeminiProviderOptions) {
    this.apiKey = options?.apiKey || process.env.GEMINI_API_KEY?.trim() || undefined;
    this.modelName = options?.modelName || process.env.GEMINI_MODEL?.trim() || "gemini-2.5-flash";
    this.defaultTimeoutMs = options?.timeoutMs ?? Number.parseInt(process.env.AI_REQUEST_TIMEOUT_MS || "30000", 10);
    if (options?.client) {
      this.clientInstance = options.client;
    }
  }

  isConfigured(): boolean {
    const provider = (process.env.AI_PROVIDER || "gemini").toLowerCase();
    if (provider === "none" || process.env.AI_GEMINI_ENABLED === "false") {
      return false;
    }
    return Boolean(this.apiKey);
  }

  getModelName(): string {
    return this.modelName;
  }

  private getClient(timeoutMs?: number): GoogleGenAI {
    if (this.clientInstance && (!timeoutMs || timeoutMs === this.defaultTimeoutMs)) {
      return this.clientInstance;
    }
    if (!this.apiKey) {
      throw new Error("GEMINI_API_KEY is not configured.");
    }
    const client = new GoogleGenAI({
      apiKey: this.apiKey,
      httpOptions: {
        timeout: timeoutMs ?? this.defaultTimeoutMs,
      },
    });
    if (!this.clientInstance) {
      this.clientInstance = client;
    }
    return client;
  }

  async generateText(params: LlmMessageParams): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error("Gemini AI provider is disabled or not configured.");
    }

    const timeoutMs = params.timeoutMs ?? this.defaultTimeoutMs;
    const client = this.getClient(timeoutMs);

    // Retry loop: AT MOST 1 retry for transient 500/503 network errors.
    // NEVER retry on 429 / RESOURCE_EXHAUSTED.
    const maxAttempts = 2;
    let lastError: unknown = null;

    const schema =
      params.responseJsonSchema ?? params.responseSchema ?? (params.format === "json" ? AiExplanationJsonSchema : undefined);

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const responsePromise = client.models.generateContent({
          model: this.modelName,
          contents: [
            {
              role: "user",
              parts: [{ text: params.userPrompt }],
            },
          ],
          config: {
            systemInstruction: params.system ? { parts: [{ text: params.system }] } : undefined,
            responseMimeType: params.format === "json" ? "application/json" : undefined,
            responseJsonSchema: schema,
            temperature: 0.1,
            maxOutputTokens: params.maxTokens ?? 1500,
          },
        });

        const timeoutPromise = new Promise<never>((_, reject) => {
          const timer = setTimeout(() => {
            reject(new Error(`Gemini AI inference request timed out after ${timeoutMs}ms.`));
          }, timeoutMs);
          timer.unref?.();
        });

        const response = await Promise.race([responsePromise, timeoutPromise]);
        const candidate = response?.candidates?.[0];
        const finishReason = candidate?.finishReason;

        if (finishReason === "MAX_TOKENS") {
          throw new GeminiTruncatedOutputError("Gemini output was truncated due to output token limit.");
        }

        const text = response?.text;

        if (typeof text === "string" && text.length > 0) {
          return text;
        }

        throw new Error("Empty response received from Gemini API.");
      } catch (err: unknown) {
        lastError = err;

        // Check if quota exhaustion (429 / RESOURCE_EXHAUSTED)
        if (isQuotaExhaustedError(err)) {
          // DO NOT RETRY!
          const rawMsg = err instanceof Error ? err.message : String(err);
          throw new GeminiQuotaExceededError(
            `Gemini API quota exhausted (429 / RESOURCE_EXHAUSTED): ${redactSecrets(rawMsg)}`
          );
        }

        if (err instanceof GeminiTruncatedOutputError) {
          throw err;
        }

        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes("timed out")) {
          throw new Error(redactSecrets(msg));
        }

        // Only retry genuinely transient 500 or 503 errors if attempt < maxAttempts
        const isTransient =
          err instanceof ApiError && (err.status === 500 || err.status === 503);
        if (attempt < maxAttempts && isTransient) {
          await new Promise((r) => setTimeout(r, 1000));
          continue;
        }

        throw new Error(redactSecrets(msg));
      }
    }

    throw new Error(redactSecrets(lastError instanceof Error ? lastError.message : String(lastError)));
  }
}
