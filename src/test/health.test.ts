import { describe, expect, it, vi, beforeEach } from "vitest";
import { GET } from "../app/api/health/route";
import * as dbModule from "../server/db";
import * as configModule from "../server/config";
import * as queueModule from "../server/queue";

describe("Health API Route (/api/health)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("GitHub Actions Mode", () => {
    it("returns healthy 200 when database is reachable and dispatch config is present without checking Redis", async () => {
      vi.spyOn(configModule, "getConfig").mockReturnValue({
        scanDispatchBackend: "github-actions",
        githubDispatchToken: "ghp_mock_token_12345",
        githubRepository: "samarth-khera/VibeShieldAi",
        scanCallbackSecret: "mock_callback_secret_xyz",
      } as never);

      vi.spyOn(dbModule.prisma, "$queryRaw").mockResolvedValue([{ 1: 1 }] as never);
      const redisPingSpy = vi.spyOn(queueModule, "getRedis");

      const response = await GET();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.status).toBe("healthy");
      expect(json.mode).toBe("github-actions");
      expect(json.services.database).toBe("healthy");
      expect(json.services.dispatcher).toBe("ready");
      expect(json.services.redis).toBeUndefined();
      expect(json.services.worker).toBeUndefined();
      expect(redisPingSpy).not.toHaveBeenCalled();
    });

    it("returns unhealthy 503 when database is unreachable", async () => {
      vi.spyOn(configModule, "getConfig").mockReturnValue({
        scanDispatchBackend: "github-actions",
        githubDispatchToken: "ghp_mock_token_12345",
        githubRepository: "samarth-khera/VibeShieldAi",
        scanCallbackSecret: "mock_callback_secret_xyz",
      } as never);

      vi.spyOn(dbModule.prisma, "$queryRaw").mockRejectedValue(new Error("Connection refused"));

      const response = await GET();
      expect(response.status).toBe(503);

      const json = await response.json();
      expect(json.status).toBe("unhealthy");
      expect(json.services.database).toBe("unhealthy");
    });

    it("returns unhealthy 503 when dispatch configuration is missing required secrets", async () => {
      vi.spyOn(configModule, "getConfig").mockReturnValue({
        scanDispatchBackend: "github-actions",
        githubDispatchToken: undefined, // Missing token
        githubRepository: "samarth-khera/VibeShieldAi",
        scanCallbackSecret: undefined, // Missing callback secret
      } as never);

      vi.spyOn(dbModule.prisma, "$queryRaw").mockResolvedValue([{ 1: 1 }] as never);

      const response = await GET();
      expect(response.status).toBe(503);

      const json = await response.json();
      expect(json.status).toBe("unhealthy");
      expect(json.services.dispatcher).toBe("unconfigured");
    });
  });

  describe("BullMQ / Local Development Mode", () => {
    it("checks Redis and worker in bullmq mode and returns healthy when both online", async () => {
      vi.spyOn(configModule, "getConfig").mockReturnValue({
        scanDispatchBackend: "bullmq",
      } as never);

      vi.spyOn(dbModule.prisma, "$queryRaw").mockResolvedValue([{ 1: 1 }] as never);
      vi.spyOn(queueModule, "getRedis").mockReturnValue({
        ping: vi.fn().mockResolvedValue("PONG"),
      } as never);
      vi.spyOn(queueModule, "isWorkerOnline").mockResolvedValue(true);

      const response = await GET();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.status).toBe("healthy");
      expect(json.mode).toBe("bullmq");
      expect(json.services.database).toBe("healthy");
      expect(json.services.redis).toBe("healthy");
      expect(json.services.worker).toBe("online");
    });

    it("returns degraded status when Redis is healthy but background worker is offline", async () => {
      vi.spyOn(configModule, "getConfig").mockReturnValue({
        scanDispatchBackend: "bullmq",
      } as never);

      vi.spyOn(dbModule.prisma, "$queryRaw").mockResolvedValue([{ 1: 1 }] as never);
      vi.spyOn(queueModule, "getRedis").mockReturnValue({
        ping: vi.fn().mockResolvedValue("PONG"),
      } as never);
      vi.spyOn(queueModule, "isWorkerOnline").mockResolvedValue(false);

      const response = await GET();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.status).toBe("degraded");
      expect(json.services.worker).toBe("offline");
    });
  });
});
