import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { GeminiProvider, isQuotaExhaustedError, redactSecrets, GeminiQuotaExceededError } from "../server/ai/gemini-provider";
import { checkAiQuotaAndCircuitBreaker } from "../server/ai/circuit-breaker";
import { explainFinding } from "../server/ai/service";
import { InMemoryJobStore } from "./mock-store";
import { GET as adminGet, POST as adminPost } from "../app/api/admin/circuit-breaker/route";
import type { FindingRecord } from "../server/job-store";

vi.mock("../server/db", () => ({
  withDbRetry: (fn: () => unknown) => fn(),
  prisma: {
    aiCircuitBreaker: {
      findUnique: vi.fn().mockResolvedValue({
        id: "global",
        isOpen: false,
      }),
      upsert: vi.fn().mockResolvedValue({}),
      update: vi.fn().mockResolvedValue({}),
    },
    aiRequestLog: {
      count: vi.fn().mockResolvedValue(0),
      create: vi.fn().mockResolvedValue({}),
    },
  },
}));

describe("Phase 7: Production Gemini Migration & Zero-Billing Security Test Suite", () => {
  const originalEnv = { ...process.env };
  let mockStore: InMemoryJobStore;

  beforeEach(() => {
    process.env = { ...originalEnv };
    mockStore = new InMemoryJobStore();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  describe("1. GeminiProvider Configuration & Security", () => {
    it("reports not configured when GEMINI_API_KEY is missing", () => {
      delete process.env.GEMINI_API_KEY;
      process.env.AI_PROVIDER = "gemini";
      process.env.AI_GEMINI_ENABLED = "true";

      const provider = new GeminiProvider();
      expect(provider.isConfigured()).toBe(false);
      expect(provider.getModelName()).toBe("gemini-2.5-flash");
    });

    it("reports not configured when AI_GEMINI_ENABLED is false", () => {
      process.env.GEMINI_API_KEY = "test-mock-gemini-key-12345";
      process.env.AI_GEMINI_ENABLED = "false";

      const provider = new GeminiProvider();
      expect(provider.isConfigured()).toBe(false);
    });

    it("reports configured when valid key and enabled flag are set", () => {
      process.env.GEMINI_API_KEY = "test-mock-gemini-key-12345";
      process.env.AI_GEMINI_ENABLED = "true";
      process.env.GEMINI_MODEL = "gemini-2.5-flash";

      const provider = new GeminiProvider();
      expect(provider.isConfigured()).toBe(true);
      expect(provider.getModelName()).toBe("gemini-2.5-flash");
    });

    it("redacts Google API keys and secrets from error strings", () => {
      process.env.GEMINI_API_KEY = "test-mock-gemini-key-12345";
      const sampleGoogleKey = ["AIza", "SyTestSampleSecretKey1234567890abcdef"].join("");
      const sensitiveMsg = `Error at https://generativelanguage.googleapis.com with key ${sampleGoogleKey} failed`;
      const sanitized = redactSecrets(sensitiveMsg);

      expect(sanitized).not.toContain(sampleGoogleKey);
      expect(sanitized).toContain("[REDACTED_API_KEY]");
    });
  });

  describe("2. Quota Detection & Zero-Retry Guardrail", () => {
    it("detects 429 and RESOURCE_EXHAUSTED errors correctly", () => {
      expect(isQuotaExhaustedError(new GeminiQuotaExceededError("Rate limit"))).toBe(true);
      expect(isQuotaExhaustedError({ status: 429, message: "Resource exhausted" })).toBe(true);
      expect(isQuotaExhaustedError({ statusCode: 429, message: "Too many requests" })).toBe(true);
      expect(isQuotaExhaustedError(new Error("429 RESOURCE_EXHAUSTED: quota exceeded"))).toBe(true);
      expect(isQuotaExhaustedError(new Error("Generic network failure"))).toBe(false);
    });

    it("never retries on quota exhaustion (429)", async () => {
      let callCount = 0;
      const mockClient = {
        models: {
          generateContent: vi.fn().mockImplementation(async () => {
            callCount++;
            const err = new Error("Resource has been exhausted (e.g. check quota).");
            (err as unknown as { status: number }).status = 429;
            throw err;
          }),
        },
      };

      const provider = new GeminiProvider({
        apiKey: "test-mock-gemini-key-12345",
        client: mockClient as never,
      });

      await expect(
        provider.generateText({
          system: "system prompt",
          userPrompt: "user prompt",
        })
      ).rejects.toThrow("Gemini API quota exhausted (429 / RESOURCE_EXHAUSTED)");

      // Exact single attempt: zero retry storms after quota error
      expect(callCount).toBe(1);
    });

    it("allows single retry for transient 503 errors with backoff", async () => {
      let callCount = 0;
      const { ApiError } = await import("@google/genai");

      const mockClient = {
        models: {
          generateContent: vi.fn().mockImplementation(async () => {
            callCount++;
            if (callCount === 1) {
              throw new ApiError({ status: 503, message: "Service Unavailable" });
            }
            return { text: '{"summary": "Fixed"}' };
          }),
        },
      };

      const provider = new GeminiProvider({
        apiKey: "test-mock-gemini-key-12345",
        client: mockClient as never,
      });

      const res = await provider.generateText({
        system: "system prompt",
        userPrompt: "user prompt",
      });

      expect(callCount).toBe(2);
      expect(res).toBe('{"summary": "Fixed"}');
    });
  });

  describe("3. Database-Backed Circuit Breaker & Quotas", () => {
    it("trips circuit breaker on quota exhaustion and blocks subsequent calls", async () => {
      const mockPrisma = {
        aiCircuitBreaker: {
          findUnique: vi.fn().mockResolvedValue({
            id: "global",
            isOpen: true,
            reason: "quota_exhausted",
            message: "AI Security Analyst is temporarily offline due to upstream daily quota limits.",
            cooldownUntil: new Date(Date.now() + 3600 * 1000),
          }),
          upsert: vi.fn().mockResolvedValue({}),
          update: vi.fn().mockResolvedValue({}),
        },
        aiRequestLog: {
          count: vi.fn().mockResolvedValue(0),
          create: vi.fn().mockResolvedValue({}),
        },
      };

      const check = await checkAiQuotaAndCircuitBreaker("test-ip-hash", {
        prisma: mockPrisma as never,
        now: new Date(),
      });

      expect(check.allowed).toBe(false);
      expect(check.reason).toBe("circuit_breaker_open");
      expect(check.message).toContain("AI Security Analyst is temporarily offline");
      expect(check.retryAfterSeconds).toBeGreaterThan(0);
    });

    it("enforces hourly IP quota and rejects excessive requests", async () => {
      const mockPrisma = {
        aiCircuitBreaker: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        aiRequestLog: {
          count: vi.fn().mockImplementation(async (args) => {
            if (args?.where?.clientIpHash) {
              return 6; // Exceeds default limit 5
            }
            return 0;
          }),
          create: vi.fn().mockResolvedValue({}),
        },
      };

      const check = await checkAiQuotaAndCircuitBreaker("test-ip-hash", {
        prisma: mockPrisma as never,
        now: new Date(),
        config: { aiMaxRequestsPerIpHourly: 5 },
      });

      expect(check.allowed).toBe(false);
      expect(check.reason).toBe("ip_hourly_limit");
    });

    it("enforces global daily cap and rejects calls when capacity is reached", async () => {
      const mockPrisma = {
        aiCircuitBreaker: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        aiRequestLog: {
          count: vi.fn().mockImplementation(async (args) => {
            if (!args?.where?.clientIpHash) {
              return 55; // Exceeds global cap of 50
            }
            return 1;
          }),
          create: vi.fn().mockResolvedValue({}),
        },
      };

      const check = await checkAiQuotaAndCircuitBreaker("test-ip-hash", {
        prisma: mockPrisma as never,
        now: new Date(),
        config: { aiGlobalDailyCap: 50 },
      });

      expect(check.allowed).toBe(false);
      expect(check.reason).toBe("global_daily_cap");
    });
  });

  describe("4. Administrative Circuit Breaker API Authorization", () => {
    it("rejects unauthenticated requests with 401", async () => {
      process.env.ADMIN_SECRET = "super-secret-admin-pass-123";

      const unauthReq = new Request("http://localhost/api/admin/circuit-breaker", {
        method: "GET",
      });

      const res = await adminGet(unauthReq);
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error.code).toBe("unauthorized");
    });

    it("allows authenticated GET and POST reset with valid secret", async () => {
      process.env.ADMIN_SECRET = "super-secret-admin-pass-123";

      const authHeaders = {
        "x-vibeshield-admin-secret": "super-secret-admin-pass-123",
      };

      const authReq = new Request("http://localhost/api/admin/circuit-breaker", {
        method: "GET",
        headers: authHeaders,
      });

      const res = await adminGet(authReq);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.data.circuitBreaker).toBeDefined();

      const postReq = new Request("http://localhost/api/admin/circuit-breaker", {
        method: "POST",
        headers: {
          ...authHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({ action: "reset" }),
      });

      const postRes = await adminPost(postReq);
      expect(postRes.status).toBe(200);
    });
  });

  describe("5. End-to-End Explain Finding Service with Gemini Provider", () => {
    it("returns structured explanation and caches result when Gemini succeeds", async () => {
      const mockFinding: FindingRecord = {
        id: "finding-gemini-1",
        scanJobId: "job-123",
        fingerprint: "fp-gemini-1",
        scanner: "semgrep",
        ruleId: "javascript.lang.security.audit.eval",
        category: "sast",
        severity: "high",
        originalSeverity: "high",
        title: "Dangerous eval() used",
        description: "Executing arbitrary code via eval() is hazardous.",
        filePath: "src/utils.js",
        startLine: 12,
        endLine: 12,
        redactedEvidence: "eval(userInput);",
        vulnerabilityId: "CWE-95",
        remediation: "Use JSON.parse instead.",
        packageInfo: null,
        metadata: null,
        aiExplanation: null,
        createdAt: new Date(),
      };

      await mockStore.saveFindings("job-123", [mockFinding as never]);

      const validJsonResponse = JSON.stringify({
        summary: "Use of eval() introduces arbitrary code execution risks.",
        whyItMatters: "Untrusted input executed by eval runs with application privileges.",
        impact: "Remote code execution or sensitive data theft.",
        exploitabilityConditions: "Attacker controls userInput argument.",
        remediationSteps: [
          "Replace eval() with JSON.parse()",
          "Validate input against strict schema",
        ],
        codeExample: {
          language: "javascript",
          code: "const data = JSON.parse(userInput);",
          title: "Safe JSON parsing",
          isDiff: false,
        },
        verificationSteps: [
          "Run test with malformed payload to verify safe rejection",
        ],
        uncertainties: [
          "Caller sanitization not visible in isolated snippet",
        ],
        disclaimer: "Review before merging.",
      });

      const mockProvider = {
        isConfigured: () => true,
        getModelName: () => "gemini-2.5-flash",
        generateText: vi.fn().mockResolvedValue(validJsonResponse),
      };

      const result = await explainFinding("job-123", "finding-gemini-1", {
        store: mockStore,
        provider: mockProvider,
      });

      expect(result.available).toBe(true);
      if (result.available) {
        expect(result.explanation.summary).toContain("eval()");
        expect(result.model).toBe("gemini-2.5-flash");
      }
      expect(mockProvider.generateText).toHaveBeenCalledTimes(1);

      // Verify cached in store
      const stored = await mockStore.getFinding("job-123", "finding-gemini-1");
      expect(stored?.aiExplanation).toBeDefined();
    });

    it("handles quota exhaustion safely without throwing uncaught errors", async () => {
      const mockFinding: FindingRecord = {
        id: "finding-gemini-2",
        scanJobId: "job-123",
        fingerprint: "fp-gemini-2",
        scanner: "semgrep",
        ruleId: "javascript.audit.xss",
        category: "sast",
        severity: "medium",
        originalSeverity: "medium",
        title: "Cross-site scripting",
        description: "Direct innerHTML assignment",
        filePath: "src/dom.js",
        startLine: 5,
        endLine: 5,
        redactedEvidence: "elem.innerHTML = content;",
        vulnerabilityId: "CWE-79",
        remediation: "Use textContent",
        packageInfo: null,
        metadata: null,
        aiExplanation: null,
        createdAt: new Date(),
      };

      await mockStore.saveFindings("job-123", [mockFinding as never]);

      const quotaProvider = {
        isConfigured: () => true,
        getModelName: () => "gemini-2.5-flash",
        generateText: vi.fn().mockRejectedValue(new GeminiQuotaExceededError("Rate limit exceeded")),
      };

      const result = await explainFinding("job-123", "finding-gemini-2", {
        store: mockStore,
        provider: quotaProvider,
      });

      expect(result.available).toBe(false);
      if (!result.available) {
        expect(result.code).toBe("quota_exhausted");
        expect(result.message).toContain("upstream daily quota limits");
      }
    });
  });
});
