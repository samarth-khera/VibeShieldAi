import { describe, expect, it, vi } from "vitest";
import { submitScan, type ScanDeps } from "@/server/scans-service";
import { InMemoryJobStore } from "./mock-store";
import { getConfig, type ServerConfig } from "@/server/config";
import { prismaJobStore } from "@/server/db";
import { prisma } from "@/server/db";

function makeScanRequest(repo: string, ip: string): Request {
  return new Request("http://localhost:3000/api/scans", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-real-ip": ip,
      "user-agent": "test-agent",
    },
    body: JSON.stringify({
      repositoryUrl: `https://github.com/test-owner/${repo}`,
    }),
  });
}

describe("Atomic Quota Reservation & Concurrency Hardening", () => {
  it("queues simultaneous submissions instead of dropping them, but executes exactly `cap` at once", async () => {
    const store = new InMemoryJobStore();
    const baseConfig = getConfig();
    const config: ServerConfig = {
      ...baseConfig,
      maxConcurrentHeavyScans: 1, // Only 1 scan may execute at a time
      maxQueuedScans: 10,
      maxScansPerIpHourly: 10,
      maxScansPerIpDaily: 20,
      globalDailyScanCap: 50,
    };

    const deps: ScanDeps = {
      store,
      config,
      enqueue: vi.fn().mockResolvedValue(undefined),
      rateLimit: vi.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: vi.fn().mockResolvedValue(true),
    };

    const responses = await Promise.all(
      Array.from({ length: 10 }, (_, i) => submitScan(makeScanRequest(`repo-concurrent-${i}`, `198.51.100.${i + 1}`), deps)),
    );
    expect(responses.map((r) => r.status)).toEqual(Array(10).fill(202));
    // Exactly one executor dispatch; nothing beyond the cap runs.
    expect(deps.enqueue).toHaveBeenCalledTimes(1);

    const jobs = await Promise.all(responses.map((r) => r.json()));
    const positions = jobs.map((j) => j.data.queue?.position).filter((p) => p != null).sort((a, b) => a - b);
    expect(positions).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);

    // The waiting queue is bounded: once 10 are waiting, the next submission is rejected explicitly.
    expect((await submitScan(makeScanRequest("repo-10", "198.51.100.50"), deps)).status).toBe(202);
    const full = await submitScan(makeScanRequest("repo-11", "198.51.100.51"), deps);
    expect(full.status).toBe(429);
    expect((await full.json()).error.code).toBe("queue_full");
  });

  it("prevents per-IP hourly race: exactly 3 of 10 simultaneous requests from same IP succeed", async () => {
    const store = new InMemoryJobStore();
    const baseConfig = getConfig();
    const config: ServerConfig = {
      ...baseConfig,
      maxConcurrentHeavyScans: 10, // Relax active scan limit to test hourly IP limit
      maxScansPerIpHourly: 3,      // Exact limit: 3 per hour
      maxScansPerIpDaily: 10,
      globalDailyScanCap: 50,
    };

    const deps: ScanDeps = {
      store,
      config,
      enqueue: vi.fn().mockResolvedValue(undefined),
      rateLimit: vi.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: vi.fn().mockResolvedValue(true),
    };

    const targetIp = "203.0.113.42";
    const requests = Array.from({ length: 10 }, (_, i) =>
      submitScan(makeScanRequest(`hourly-repo-${i}`, targetIp), deps),
    );

    const responses = await Promise.all(requests);
    const accepted = responses.filter((r) => r.status === 202);
    const rateLimited = responses.filter((r) => r.status === 429);

    expect(accepted.length).toBe(3);
    expect(rateLimited.length).toBe(7);

    for (const res of rateLimited) {
      const body = await res.json();
      expect(body.error.code).toBe("hourly_ip_limit");
      expect(res.headers.get("Retry-After")).toBe("1800");
    }
  });

  it("prevents per-IP daily race: exactly 5 of 12 simultaneous requests from same IP succeed", async () => {
    const store = new InMemoryJobStore();
    const baseConfig = getConfig();
    const config: ServerConfig = {
      ...baseConfig,
      maxConcurrentHeavyScans: 20,
      maxScansPerIpHourly: 20,
      maxScansPerIpDaily: 5, // Exact limit: 5 per day
      globalDailyScanCap: 50,
    };

    const deps: ScanDeps = {
      store,
      config,
      enqueue: vi.fn().mockResolvedValue(undefined),
      rateLimit: vi.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: vi.fn().mockResolvedValue(true),
    };

    const targetIp = "203.0.113.99";
    const requests = Array.from({ length: 12 }, (_, i) =>
      submitScan(makeScanRequest(`daily-repo-${i}`, targetIp), deps),
    );

    const responses = await Promise.all(requests);
    const accepted = responses.filter((r) => r.status === 202);
    const rateLimited = responses.filter((r) => r.status === 429);

    expect(accepted.length).toBe(5);
    expect(rateLimited.length).toBe(7);

    for (const res of rateLimited) {
      const body = await res.json();
      expect(body.error.code).toBe("daily_ip_limit");
      expect(res.headers.get("Retry-After")).toBe("3600");
    }
  });

  it("prevents global daily race: exactly 20 of 30 simultaneous requests succeed across distinct IPs", async () => {
    const store = new InMemoryJobStore();
    const baseConfig = getConfig();
    const config: ServerConfig = {
      ...baseConfig,
      maxConcurrentHeavyScans: 50,
      maxQueuedScans: 50,
      maxScansPerIpHourly: 50,
      maxScansPerIpDaily: 50,
      globalDailyScanCap: 20, // Exact global cap: 20 per day
    };

    const deps: ScanDeps = {
      store,
      config,
      enqueue: vi.fn().mockResolvedValue(undefined),
      rateLimit: vi.fn().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: vi.fn().mockResolvedValue(true),
    };

    // 30 simultaneous requests from 30 distinct IPs
    const requests = Array.from({ length: 30 }, (_, i) =>
      submitScan(makeScanRequest(`global-repo-${i}`, `10.0.0.${i + 1}`), deps),
    );

    const responses = await Promise.all(requests);
    const accepted = responses.filter((r) => r.status === 202);
    const rateLimited = responses.filter((r) => r.status === 429);

    expect(accepted.length).toBe(20);
    expect(rateLimited.length).toBe(10);

    for (const res of rateLimited) {
      const body = await res.json();
      expect(body.error.code).toBe("global_daily_limit");
      expect(res.headers.get("Retry-After")).toBe("7200");
    }
  });

  it("verifies prismaJobStore acquires PostgreSQL advisory xact lock in transaction", async () => {
    const mockExecuteRaw = vi.fn().mockResolvedValue(1);
    const mockCount = vi.fn().mockResolvedValue(0);
    const mockCreate = vi.fn().mockResolvedValue({
      id: "mock-job-id-12345678901234567890",
      status: "queued",
      owner: "octocat",
      repo: "Hello-World",
      repositoryUrl: "https://github.com/octocat/Hello-World",
      clientIpHash: "test-hash",
      createdAt: new Date(),
      expiresAt: new Date(),
    });

    const mockTx = {
      $executeRaw: mockExecuteRaw,
      scanJob: {
        count: mockCount,
        create: mockCreate,
        findMany: vi.fn().mockResolvedValue([]),
        updateMany: vi.fn().mockResolvedValue({ count: 0 }),
      },
      finding: { deleteMany: vi.fn() },
      remediation: {
        count: vi.fn().mockResolvedValue(0),
        findMany: vi.fn().mockResolvedValue([]),
        updateMany: vi.fn().mockResolvedValue({ count: 0 }),
      },
    };

    const txSpy = (vi.spyOn(prisma, "$transaction") as unknown as {
      mockImplementation: (fn: (cb: (tx: typeof mockTx) => Promise<unknown>) => Promise<unknown>) => { mockRestore: () => void };
    }).mockImplementation(async (cb) => {
      return cb(mockTx);
    });

    try {
      const res = await prismaJobStore.createWithQuota!(
        {
          owner: "octocat",
          repo: "Hello-World",
          repositoryUrl: "https://github.com/octocat/Hello-World",
          clientIpHash: "test-hash",
          expiresAt: new Date(Date.now() + 86400_000),
        },
        getConfig(),
      );

      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.job.id).toBe("mock-job-id-12345678901234567890");
      }
      expect(mockExecuteRaw).toHaveBeenCalledTimes(1);
      expect(mockCreate).toHaveBeenCalledTimes(1);
    } finally {
      txSpy.mockRestore();
    }
  });
});

describe("default free-tier limits", () => {
  it("allows 6 submissions per IP per hour, 10 per day, 40 globally and 20 waiting, and still rejects beyond them", async () => {
    vi.stubEnv("MAX_SCANS_PER_IP_HOURLY", "");
    vi.stubEnv("MAX_SCANS_PER_IP_DAILY", "");
    vi.stubEnv("GLOBAL_DAILY_SCAN_CAP", "");
    vi.stubEnv("MAX_QUEUED_SCANS", "");
    vi.stubEnv("MAX_CONCURRENT_HEAVY_SCANS", "");
    const { evaluateQuota } = await import("@/server/quota");
    const c = getConfig();
    expect(c.maxConcurrentHeavyScans).toBe(2); // execution concurrency deliberately unchanged
    expect(evaluateQuota({ waiting: 0, ipHourly: 5, ipDaily: 5, globalDaily: 5 }, c).allowed).toBe(true);
    expect(evaluateQuota({ waiting: 0, ipHourly: 6, ipDaily: 6, globalDaily: 6 }, c).reason).toBe("hourly_ip_limit");
    expect(evaluateQuota({ waiting: 0, ipHourly: 0, ipDaily: 10, globalDaily: 10 }, c).reason).toBe("daily_ip_limit");
    expect(evaluateQuota({ waiting: 0, ipHourly: 0, ipDaily: 0, globalDaily: 40 }, c).reason).toBe("global_daily_limit");
    expect(evaluateQuota({ waiting: 19, ipHourly: 0, ipDaily: 0, globalDaily: 0 }, c).allowed).toBe(true);
    expect(evaluateQuota({ waiting: 20, ipHourly: 0, ipDaily: 0, globalDaily: 0 }, c).reason).toBe("queue_full");
    expect(evaluateQuota({ active: 2 }, c).reason).toBe("concurrency_limit");
    vi.unstubAllEnvs();
  });
});
