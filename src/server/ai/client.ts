export type LlmMessageParams = {
  system: string;
  userPrompt: string;
  maxTokens?: number;
  timeoutMs?: number;
  format?: "json";
};

export interface LlmProvider {
  isConfigured(): boolean;
  getModelName(): string;
  generateText(params: LlmMessageParams): Promise<string>;
}

/**
 * Concurrency limiter to protect CPU and memory on local hardware (e.g. 2-OCPU ARM64).
 * Serializes local LLM inference requests when AI_MAX_CONCURRENCY=1.
 */
class AsyncSemaphore {
  private current = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async acquire(): Promise<void> {
    if (this.current < this.max) {
      this.current++;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
    this.current++;
  }

  release(): void {
    this.current--;
    const next = this.queue.shift();
    if (next) next();
  }
}

export type OllamaProviderOptions = {
  baseUrl?: string;
  modelName?: string;
  numCtx?: number;
  timeoutMs?: number;
  maxConcurrency?: number;
  fetchImpl?: typeof fetch;
};

/**
 * Local LLM Provider powered by Ollama.
 *
 * Zero-API / 100% Privacy Guarantee:
 * - Direct HTTP communication with the local Ollama instance (default: http://localhost:11434 or http://ollama:11434).
 * - Never sends source code, findings, or prompts to any external cloud API (Anthropic, OpenAI, or Ollama Cloud).
 * - Enforces single-request concurrency and bounded context windows to prevent memory exhaustion on resource-constrained servers.
 */
export class OllamaProvider implements LlmProvider {
  private readonly baseUrl: string;
  private readonly modelName: string;
  private readonly numCtx: number;
  private readonly defaultTimeoutMs: number;
  private readonly semaphore: AsyncSemaphore;
  private readonly fetchFn: typeof fetch;

  constructor(options?: OllamaProviderOptions) {
    this.baseUrl = (options?.baseUrl || process.env.OLLAMA_BASE_URL || "http://localhost:11434").replace(/\/+$/, "");
    this.modelName = options?.modelName || process.env.OLLAMA_MODEL || "qwen3.5:4b-q4_K_M";
    this.numCtx = options?.numCtx ?? Number.parseInt(process.env.OLLAMA_NUM_CTX || "8192", 10);
    this.defaultTimeoutMs = options?.timeoutMs ?? Number.parseInt(process.env.OLLAMA_TIMEOUT_MS || "120000", 10);
    const concurrency = options?.maxConcurrency ?? Number.parseInt(process.env.AI_MAX_CONCURRENCY || "1", 10);
    this.semaphore = new AsyncSemaphore(Math.max(1, concurrency));
    this.fetchFn = options?.fetchImpl || fetch;
  }

  isConfigured(): boolean {
    const provider = (process.env.AI_PROVIDER || "ollama").toLowerCase();
    if (provider === "none" || process.env.OLLAMA_DISABLED === "true") {
      return false;
    }
    return Boolean(this.baseUrl && this.modelName);
  }

  getModelName(): string {
    return this.modelName;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  async generateText(params: LlmMessageParams): Promise<string> {
    if (!this.isConfigured()) {
      throw new Error("Local Ollama AI provider is disabled or not configured.");
    }

    await this.semaphore.acquire();
    const timeoutMs = params.timeoutMs ?? this.defaultTimeoutMs;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const url = `${this.baseUrl}/api/chat`;
      const body: Record<string, unknown> = {
        model: this.modelName,
        messages: [
          { role: "system", content: params.system },
          { role: "user", content: params.userPrompt },
        ],
        stream: false,
        think: false,
        options: {
          temperature: 0.1,
          num_ctx: this.numCtx,
          num_predict: params.maxTokens ?? 1500,
        },
      };

      if (params.format) {
        body.format = params.format;
      }

      let response: Response;
      try {
        response = await this.fetchFn(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (networkErr: unknown) {
        clearTimeout(timeout);
        if (controller.signal.aborted) {
          throw new Error(`Local AI inference request timed out after ${timeoutMs}ms.`);
        }
        const errMessage = networkErr instanceof Error ? networkErr.message : String(networkErr);
        throw new Error(
          `Local Ollama service is unavailable at ${this.baseUrl}. Ensure the Ollama service is running. (${errMessage})`
        );
      }

      clearTimeout(timeout);

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        if (response.status === 404 || errorText.toLowerCase().includes("not found")) {
          throw new Error(
            `Local model '${this.modelName}' is not installed in Ollama. Pull it using: ollama pull ${this.modelName}`
          );
        }
        throw new Error(`Ollama API returned HTTP ${response.status}: ${errorText || "Unknown error"}`);
      }

      const data = (await response.json()) as {
        message?: { content?: string };
        done?: boolean;
      };

      if (data && data.message && typeof data.message.content === "string") {
        return data.message.content;
      }

      throw new Error("Invalid response format received from local Ollama instance.");
    } catch (err: unknown) {
      clearTimeout(timeout);
      if (err instanceof Error && (err.name === "AbortError" || err.message.includes("abort"))) {
        throw new Error(`Local AI inference request timed out after ${timeoutMs}ms.`);
      }
      throw err;
    } finally {
      this.semaphore.release();
    }
  }
}

let defaultProvider: LlmProvider | null = null;

export function getLlmProvider(): LlmProvider {
  if (!defaultProvider) {
    defaultProvider = new OllamaProvider();
  }
  return defaultProvider;
}

export function setLlmProvider(provider: LlmProvider | null): void {
  defaultProvider = provider;
}
