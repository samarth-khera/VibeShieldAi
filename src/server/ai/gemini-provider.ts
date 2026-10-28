import { GoogleGenAI, ApiError } from "@google/genai";
import type { LlmMessageParams, LlmProvider } from "./client";
import { AiExplanationJsonSchema } from "./types";
import { log } from "../errors";

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
  /** Thinking token budget. Defaults to 0 (off) for 2.5 Flash models, where thinking tokens share the output budget. */
  thinkingBudget?: number;
  client?: GoogleGenAI;
};

/**
 * Gemini 2.5 Flash thinks by default, and those tokens count against `maxOutputTokens`, which adds
 * seconds of latency and can truncate the JSON answer. The explanation task is grounded summarization,
 * so thinking is disabled there unless AI_THINKING_BUDGET overrides it.
 */
export function resolveThinkingBudget(modelName: string, override?: number): number | undefined {
  if (override !== undefined && Number.isFinite(override)) return override;
  const raw = process.env.AI_THINKING_BUDGET?.trim();
  if (raw) {
    const n = Number.parseInt(raw, 10);
    if (Number.isFinite(n)) return n;
  }
  return /^gemini-2\.5-flash/.test(modelName) ? 0 : undefined;
}

class GeminiTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Gemini AI inference request timed out after ${timeoutMs}ms.`);
  }
}

/** Rejects as soon as `signal` aborts, even if the underlying promise ignores the signal. */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal, onAbort: () => Error): Promise<T> {
  if (signal.aborted) return Promise.reject(onAbort());
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(onAbort());
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (err) => {
        signal.removeEventListener("abort", abort);
        reject(err);
      },
    );
  });
}

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
  private readonly thinkingBudget?: number;
  private clientInstance: GoogleGenAI | null = null;

  constructor(options?: GeminiProviderOptions) {
    this.apiKey = options?.apiKey || process.env.GEMINI_API_KEY?.trim() || undefined;
    this.modelName = options?.modelName || process.env.GEMINI_MODEL?.trim() || "gemini-2.5-flash";
    this.defaultTimeoutMs = options?.timeoutMs ?? Number.parseInt(process.env.AI_REQUEST_TIMEOUT_MS || "30000", 10);
    this.thinkingBudget = resolveThinkingBudget(this.modelName, options?.thinkingBudget);
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

  private getClient(): GoogleGenAI {
    if (this.clientInstance) return this.clientInstance;
    if (!this.apiKey) {
      throw new Error("GEMINI_API_KEY is not configured.");
    }
    // No SDK-level timeout: generateText enforces one deadline through an AbortSignal.
    this.clientInstance = new GoogleGenAI({ apiKey: this.apiKey });
    return this.clientInstance;
  }

  async generateText(params: LlmMessageParams): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error("Gemini AI provider is disabled or not configured.");
    }

    const timeoutMs = params.timeoutMs ?? this.defaultTimeoutMs;
    const client = this.getClient();
    const schema =
      params.responseJsonSchema ?? params.responseSchema ?? (params.format === "json" ? AiExplanationJsonSchema : undefined);

    // One deadline covers every attempt; aborting it cancels the in-flight HTTP request.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const timedOut = () => new GeminiTimeoutError(timeoutMs);
    const started = Date.now();

    // AT MOST 1 retry, and only for transient 500/503. NEVER retry on 429 / RESOURCE_EXHAUSTED.
    const maxAttempts = 2;
    try {
      for (let attempt = 1; ; attempt++) {
        try {
          const response = await untilAborted(
            client.models.generateContent({
              model: this.modelName,
              contents: [{ role: "user", parts: [{ text: params.userPrompt }] }],
              config: {
                systemInstruction: params.system ? { parts: [{ text: params.system }] } : undefined,
                responseMimeType: params.format === "json" ? "application/json" : undefined,
                responseJsonSchema: schema,
                temperature: 0.1,
                maxOutputTokens: params.maxTokens ?? 1500,
                thinkingConfig: this.thinkingBudget !== undefined ? { thinkingBudget: this.thinkingBudget } : undefined,
                abortSignal: controller.signal,
              },
            }),
            controller.signal,
            timedOut,
          );

          const candidate = response?.candidates?.[0];
          const usage = response?.usageMetadata;
          log("info", "ai_inference", {
            correlationId: params.correlationId,
            model: this.modelName,
            attempt,
            durationMs: Date.now() - started,
            finishReason: candidate?.finishReason ?? null,
            promptTokens: usage?.promptTokenCount ?? null,
            outputTokens: usage?.candidatesTokenCount ?? null,
            thinkingTokens: usage?.thoughtsTokenCount ?? null,
          });

          if (candidate?.finishReason === "MAX_TOKENS") {
            throw new GeminiTruncatedOutputError("Gemini output was truncated due to output token limit.");
          }
          const text = response?.text;
          if (typeof text === "string" && text.length > 0) {
            return text;
          }
          throw new Error("Empty response received from Gemini API.");
        } catch (err: unknown) {
          if (controller.signal.aborted) throw timedOut();

          if (isQuotaExhaustedError(err)) {
            const rawMsg = err instanceof Error ? err.message : String(err);
            throw new GeminiQuotaExceededError(
              `Gemini API quota exhausted (429 / RESOURCE_EXHAUSTED): ${redactSecrets(rawMsg)}`
            );
          }
          if (err instanceof GeminiTruncatedOutputError) {
            throw err;
          }

          const isTransient = err instanceof ApiError && (err.status === 500 || err.status === 503);
          if (attempt < maxAttempts && isTransient) {
            await untilAborted(new Promise((r) => setTimeout(r, 1000)), controller.signal, timedOut);
            continue;
          }
          throw new Error(redactSecrets(err instanceof Error ? err.message : String(err)));
        }
      }
    } finally {
      clearTimeout(timer);
    }
  }
}
