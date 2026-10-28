import { describe, expect, it, vi } from "vitest";
import { signCallbackPayload, verifyCallbackSignature } from "../server/callback-auth";
import { checkDatabaseQuotas } from "../server/rate-limit";
import { dispatchScanJob } from "../server/dispatch";
import { isTransientDbError, withDbRetry } from "../server/db";
import { Prisma } from "@prisma/client";

describe("Callback Authentication & Replay Protection (Rule 7)", () => {
  const secret = "test-high-entropy-secret-1234567890abcdef";
  const payload = JSON.stringify({ jobId: "test-job-123", status: "completed" });

  it("successfully signs and verifies a valid callback payload", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const signatureHeader = signCallbackPayload(payload, secret, timestamp);

    const result = verifyCallbackSignature(payload, signatureHeader, secret, timestamp);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.timestamp).toBe(timestamp);
    }
  });

  it("rejects callbacks with tampered payload", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const signatureHeader = signCallbackPayload(payload, secret, timestamp);
    const tamperedPayload = JSON.stringify({ jobId: "test-job-123", status: "failed" });

    const result = verifyCallbackSignature(tamperedPayload, signatureHeader, secret, timestamp);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("signature_mismatch");
    }
  });

  it("rejects callbacks with an expired timestamp (older than 300 seconds)", () => {
    const oldTimestamp = Math.floor(Date.now() / 1000) - 350; // 350s ago
    const signatureHeader = signCallbackPayload(payload, secret, oldTimestamp);

    const result = verifyCallbackSignature(payload, signatureHeader, secret, Math.floor(Date.now() / 1000));
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("timestamp_expired");
    }
  });

  it("rejects callbacks with missing or malformed signature header", () => {
    expect(verifyCallbackSignature(payload, null, secret).valid).toBe(false);
    expect(verifyCallbackSignature(payload, "invalid-header-format", secret).valid).toBe(false);
    expect(verifyCallbackSignature(payload, "t=123", secret).valid).toBe(false);
  });

  it("rejects callbacks when server secret is not configured", () => {
    const signatureHeader = signCallbackPayload(payload, secret);
    const result = verifyCallbackSignature(payload, signatureHeader, undefined);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("missing_secret");
    }
  });
});

describe("Free-tier Database Quotas & Concurrency Limiting (Rule 8)", () => {
  const config = {
    maxScansPerIpHourly: 3,
    maxScansPerIpDaily: 5,
    globalDailyScanCap: 20,
    maxConcurrentHeavyScans: 1,
    maxQueuedScans: 10,
    jobTimeoutMs: 900_000,
  };

  it("allows scan when within all quotas", async () => {
    const mockPrisma = {
      scanJob: {
        count: vi.fn().mockResolvedValue(0),
      },
    };

    const res = await checkDatabaseQuotas(mockPrisma as never, "client-hash-1", config);
    expect(res.allowed).toBe(true);
    expect(res.retryAfterSeconds).toBe(0);
  });

  it("rejects submissions explicitly once the waiting queue is full", async () => {
    const mockPrisma = {
      scanJob: {
        count: vi.fn().mockImplementation(({ where }) => {
          if (where.status === "queued" && where.startedAt === null) return Promise.resolve(10); // waiting
          return Promise.resolve(0);
        }),
      },
    };

    const res = await checkDatabaseQuotas(mockPrisma as never, "client-hash-1", config);
    expect(res.allowed).toBe(false);
    expect(res.reason).toBe("queue_full");
    expect(res.retryAfterSeconds).toBe(120);
  });

  it("enforces hourly limit of 3 scans per IP", async () => {
    const mockPrisma = {
      scanJob: {
        count: vi.fn().mockImplementation(({ where }) => {
          if (where.clientIpHash && where.createdAt) {
            // First call with clientIpHash is the 1-hour window
            return Promise.resolve(3);
          }
          return Promise.resolve(0);
        }),
      },
    };

    const res = await checkDatabaseQuotas(mockPrisma as never, "client-hash-1", config);
    expect(res.allowed).toBe(false);
    expect(res.reason).toBe("hourly_ip_limit");
    expect(res.retryAfterSeconds).toBe(1800);
  });

  it("enforces daily limit of 5 scans per IP", async () => {
    let callIndex = 0;
    const mockPrisma = {
      scanJob: {
        count: vi.fn().mockImplementation(() => {
          callIndex++;
          if (callIndex === 1) return Promise.resolve(0); // concurrency: 0
          if (callIndex === 2) return Promise.resolve(2); // hourly: 2 (under 3)
          if (callIndex === 3) return Promise.resolve(5); // daily: 5 (at limit!)
          return Promise.resolve(0);
        }),
      },
    };

    const res = await checkDatabaseQuotas(mockPrisma as never, "client-hash-1", config);
    expect(res.allowed).toBe(false);
    expect(res.reason).toBe("daily_ip_limit");
    expect(res.retryAfterSeconds).toBe(3600);
  });

  it("enforces global daily cap of 20 scans", async () => {
    let callIndex = 0;
    const mockPrisma = {
      scanJob: {
        count: vi.fn().mockImplementation(() => {
          callIndex++;
          if (callIndex === 1) return Promise.resolve(0); // concurrency: 0
          if (callIndex === 2) return Promise.resolve(1); // hourly: 1
          if (callIndex === 3) return Promise.resolve(2); // daily: 2
          if (callIndex === 4) return Promise.resolve(20); // global daily cap: 20!
          return Promise.resolve(0);
        }),
      },
    };

    const res = await checkDatabaseQuotas(mockPrisma as never, "client-hash-1", config);
    expect(res.allowed).toBe(false);
    expect(res.reason).toBe("global_daily_limit");
    expect(res.retryAfterSeconds).toBe(7200);
  });
});

describe("Workflow Dispatching (Rule 4)", () => {
  it("successfully dispatches GitHub Actions workflow", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 204,
      ok: true,
      text: () => Promise.resolve(""),
    });

    const config = {
      scanDispatchBackend: "github-actions" as const,
      githubDispatchToken: "ghp_mock_token_12345",
      githubRepository: "samarth-khera/VibeShieldAi",
      githubWorkflowRef: "main",
      appUrl: "https://vibeshield-ai.vercel.app",
    };

    const res = await dispatchScanJob("job-abc", "https://github.com/owner/repo", config as never, mockFetch as never);
    expect(res.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/samarth-khera/VibeShieldAi/actions/workflows/scanner-worker.yml/dispatches",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer ghp_mock_token_12345",
        }),
      }),
    );
  });

  it("fails gracefully if workflow dispatch token is missing", async () => {
    const config = {
      scanDispatchBackend: "github-actions" as const,
      githubDispatchToken: undefined,
      githubRepository: "samarth-khera/VibeShieldAi",
      githubWorkflowRef: "main",
      appUrl: "https://vibeshield-ai.vercel.app",
    };

    const res = await dispatchScanJob("job-abc", "https://github.com/owner/repo", config as never);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(res.error).toContain("token");
    }
  });
});

describe("Database Cold-Start Resilience (Rule 3)", () => {
  it("identifies transient Neon connection errors", () => {
    expect(isTransientDbError(new Error("Can't reach database server at ..."))).toBe(true);
    expect(isTransientDbError(new Error("Connection closed by peer"))).toBe(true);
    expect(isTransientDbError(new Error("read ECONNRESET"))).toBe(true);
    expect(isTransientDbError(new Prisma.PrismaClientInitializationError("init error", "client-version"))).toBe(true);
    expect(isTransientDbError(new Error("syntax error at or near 'SELECT'"))).toBe(false);
  });

  it("retries on transient errors and succeeds when connection resumes", async () => {
    let attempts = 0;
    const operation = vi.fn(async () => {
      attempts++;
      if (attempts < 2) {
        throw new Error("Can't reach database server at ephemeral-host");
      }
      return "db-result";
    });

    const result = await withDbRetry(operation, 3, 10);
    expect(result).toBe("db-result");
    expect(attempts).toBe(2);
  });

  it("throws immediately on non-transient errors without retry loops", async () => {
    let attempts = 0;
    const operation = vi.fn(async () => {
      attempts++;
      throw new Error("Unique constraint violation");
    });

    await expect(withDbRetry(operation, 3, 10)).rejects.toThrow("Unique constraint violation");
    expect(attempts).toBe(1);
  });
});
