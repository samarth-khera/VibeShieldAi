import Anthropic from "@anthropic-ai/sdk";

export type LlmMessageParams = {
  system: string;
  userPrompt: string;
  maxTokens?: number;
  timeoutMs?: number;
};

export interface LlmProvider {
  isConfigured(): boolean;
  getModelName(): string;
  generateText(params: LlmMessageParams): Promise<string>;
}

export class AnthropicProvider implements LlmProvider {
  private client: Anthropic | null = null;
  private readonly apiKey: string | undefined;
  private readonly modelName: string;

  constructor(apiKey?: string, modelName?: string) {
    this.apiKey = apiKey || process.env.ANTHROPIC_API_KEY;
    this.modelName = modelName || process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5";

    if (this.apiKey) {
      this.client = new Anthropic({ apiKey: this.apiKey });
    }
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  getModelName(): string {
    return this.modelName;
  }

  async generateText(params: LlmMessageParams): Promise<string> {
    if (!this.client) {
      throw new Error("Anthropic API key is not configured.");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), params.timeoutMs ?? 25000);

    try {
      const response = await this.client.messages.create(
        {
          model: this.modelName,
          max_tokens: params.maxTokens ?? 1500,
          system: params.system,
          messages: [{ role: "user", content: params.userPrompt }],
        },
        { signal: controller.signal }
      );

      clearTimeout(timeout);

      const firstBlock = response.content[0];
      if (firstBlock && firstBlock.type === "text") {
        return firstBlock.text;
      }

      throw new Error("Invalid response content format received from Anthropic.");
    } catch (err: unknown) {
      clearTimeout(timeout);
      if (err instanceof Error && (err.name === "AbortError" || err.message.includes("abort"))) {
        throw new Error("AI provider request timed out.");
      }
      throw err;
    }
  }
}

let defaultProvider: LlmProvider | null = null;

export function getLlmProvider(): LlmProvider {
  if (!defaultProvider) {
    defaultProvider = new AnthropicProvider();
  }
  return defaultProvider;
}

export function setLlmProvider(provider: LlmProvider | null): void {
  defaultProvider = provider;
}
