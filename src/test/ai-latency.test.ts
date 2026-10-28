import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, type GoogleGenAI } from "@google/genai";
import { GeminiProvider, GeminiQuotaExceededError, resolveThinkingBudget } from "@/server/ai/gemini-provider";
import { SYSTEM_PROMPT, buildUserPrompt } from "@/server/ai/prompts";
import { explainFinding } from "@/server/ai/service";
import { InMemoryJobStore } from "./mock-store";

const okResponse = (text = '{"ok":true}') => ({
  text,
  candidates: [{ finishReason: "STOP" }],
  usageMetadata: { promptTokenCount: 300, candidatesTokenCount: 450, thoughtsTokenCount: 0 },
});

function providerWith(generateContent: (req: { config: { abortSignal?: AbortSignal; thinkingConfig?: unknown } }) => Promise<unknown>, opts: { modelName?: string; timeoutMs?: number } = {}) {
  const client = { models: { generateContent: vi.fn(generateContent) } } as unknown as GoogleGenAI;
  return {
    provider: new GeminiProvider({ apiKey: "test-key", client, modelName: opts.modelName, timeoutMs: opts.timeoutMs }),
    calls: (client.models.generateContent as unknown as ReturnType<typeof vi.fn>).mock.calls,
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

describe("Gemini request lifecycle", () => {
  it("enforces one deadline, aborts the in-flight request, and rejects even if the SDK ignores the signal", async () => {
    let seen: AbortSignal | undefined;
    const { provider } = providerWith(async (req) => {
      seen = req.config.abortSignal;
      return new Promise(() => undefined); // never settles, ignores abort
    }, { timeoutMs: 60 });

    const t0 = Date.now();
    await expect(provider.generateText({ system: "s", userPrompt: "u", format: "json" })).rejects.toThrow(/timed out after 60ms/);
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(seen?.aborted).toBe(true);
  });

  it("leaves no timer behind after a successful call", async () => {
    vi.useFakeTimers();
    const { provider } = providerWith(async () => okResponse(), { timeoutMs: 30_000 });
    await expect(provider.generateText({ system: "s", userPrompt: "u", format: "json" })).resolves.toBe('{"ok":true}');
    expect(vi.getTimerCount()).toBe(0);
  });

  it("retries a transient 503 once inside the same deadline, but never retries quota exhaustion", async () => {
    let n = 0;
    const transient = providerWith(async () => {
      n++;
      if (n === 1) throw new ApiError({ message: "unavailable", status: 503 });
      return okResponse();
    });
    await expect(transient.provider.generateText({ system: "s", userPrompt: "u" })).resolves.toBeTruthy();
    expect(transient.calls).toHaveLength(2);

    const quota = providerWith(async () => {
      throw new ApiError({ message: "RESOURCE_EXHAUSTED", status: 429 });
    });
    await expect(quota.provider.generateText({ system: "s", userPrompt: "u" })).rejects.toBeInstanceOf(GeminiQuotaExceededError);
    expect(quota.calls).toHaveLength(1);
  });

  it("disables thinking for 2.5 Flash so thinking tokens do not consume the output budget", async () => {
    const flash = providerWith(async () => okResponse(), { modelName: "gemini-2.5-flash" });
    await flash.provider.generateText({ system: "s", userPrompt: "u" });
    expect(flash.calls[0][0].config.thinkingConfig).toEqual({ thinkingBudget: 0 });

    expect(resolveThinkingBudget("gemini-2.5-pro")).toBeUndefined();
    vi.stubEnv("AI_THINKING_BUDGET", "256");
    expect(resolveThinkingBudget("gemini-2.5-flash")).toBe(256);
  });
});

describe("Prompt size and redundant work", () => {
  it("does not repeat the JSON schema that responseJsonSchema already enforces, but keeps the safety rules", () => {
    expect(SYSTEM_PROMPT).not.toMatch(/"whyItMatters"|"remediationSteps"|REQUIRED JSON OUTPUT SCHEMA/);
    expect(SYSTEM_PROMPT).toMatch(/PROMPT INJECTION/);
    expect(SYSTEM_PROMPT).toMatch(/untrusted/i);
    expect(SYSTEM_PROMPT.length).toBeLessThan(1200);
  });

  it("bounds the untrusted evidence placed in the prompt", () => {
    const prompt = buildUserPrompt({
      id: "f",
      scanJobId: "j",
      fingerprint: "fp",
      scanner: "semgrep",
      ruleId: "r",
      category: "Code Analysis",
      severity: "high",
      originalSeverity: null,
      title: "t",
      description: "d".repeat(10_000),
      filePath: "a.ts",
      startLine: 1,
      endLine: 1,
      redactedEvidence: "e".repeat(10_000),
      vulnerabilityId: null,
      remediation: "r".repeat(10_000),
      packageInfo: null,
      metadata: null,
      createdAt: new Date(),
    });
    expect(prompt.length).toBeLessThan(3500);
  });

  it("reuses the finding the route already loaded instead of reading it again", async () => {
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "o", repo: "r", repositoryUrl: "https://github.com/o/r", expiresAt: new Date(Date.now() + 1e6) });
    await store.saveFindings(job.id, [
      {
        scanner: "semgrep",
        ruleId: "eval",
        category: "Code Analysis",
        severity: "high",
        title: "eval",
        description: "eval use",
        filePath: "a.js",
        fingerprint: "fp-ai",
        startLine: 1,
        endLine: 1,
        redactedEvidence: "eval(x)",
        vulnerabilityId: null,
        remediation: null,
        packageInfo: null,
        metadata: null,
      },
    ]);
    const finding = (await store.getFindings(job.id)).findings[0];
    const getFinding = vi.spyOn(store, "getFinding");
    const provider = {
      isConfigured: () => true,
      getModelName: () => "gemini-2.5-flash",
      generateText: vi.fn().mockResolvedValue(
        JSON.stringify({
          summary: "eval() executes attacker-controlled strings.",
          whyItMatters: "Arbitrary code execution in the server process.",
          impact: "Full compromise of the application runtime.",
          exploitabilityConditions: "Input reaching eval() must be user controlled.",
          remediationSteps: ["Replace eval with JSON.parse"],
          verificationSteps: ["Re-run Semgrep"],
          uncertainties: [],
          disclaimer: "AI-generated; review before use.",
        }),
      ),
    };

    const first = await explainFinding(job.id, finding.id, { store, provider, finding });
    expect(first.available).toBe(true);
    expect(getFinding).not.toHaveBeenCalled();
    expect(provider.generateText.mock.calls[0][0].correlationId).toMatch(/^[0-9a-f-]{12}$/);

    // A finding from another scan is never trusted as preloaded.
    await explainFinding("x".repeat(32), finding.id, { store, provider, finding }).catch(() => undefined);
    expect(getFinding).toHaveBeenCalledTimes(1);
  });
});

describe("AI failures never poison the cache or block findings", () => {
  async function seeded() {
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "o", repo: "r", repositoryUrl: "https://github.com/o/r", expiresAt: new Date(Date.now() + 1e6) });
    await store.saveFindings(job.id, [
      {
        scanner: "semgrep", ruleId: "eval", category: "Code Analysis", severity: "high", title: "eval", description: "eval use",
        filePath: "a.js", fingerprint: "fp-bad", startLine: 1, endLine: 1, redactedEvidence: "eval(x)", vulnerabilityId: null,
        remediation: null, packageInfo: null, metadata: null,
      },
    ]);
    return { store, job, finding: (await store.getFindings(job.id)).findings[0] };
  }

  it.each([
    ["malformed JSON", "{ not json"],
    ["truncated JSON", '{"summary": "cut off'],
    ["schema-invalid JSON", JSON.stringify({ summary: "too short" })],
  ])("does not cache %s as a successful explanation", async (_label, raw) => {
    const { store, job, finding } = await seeded();
    const save = vi.spyOn(store, "saveFindingAiExplanation");
    const provider = { isConfigured: () => true, getModelName: () => "gemini-2.5-flash", generateText: vi.fn().mockResolvedValue(raw) };
    const res = await explainFinding(job.id, finding.id, { store, provider, finding });
    expect(res.available).toBe(false);
    expect(save).not.toHaveBeenCalled();
    // Findings are untouched and still readable.
    expect((await store.getFindings(job.id)).findings).toHaveLength(1);
  });
});

