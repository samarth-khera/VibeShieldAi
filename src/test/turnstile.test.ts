import { describe, expect, it, vi } from "vitest";
import { verifyTurnstileToken } from "@/server/turnstile";
import { submitScan } from "@/server/scans-service";
import { InMemoryJobStore } from "./mock-store";
import { getConfig } from "@/server/config";

describe("Cloudflare Turnstile Abuse Protection", () => {
  it("bypasses verification when secret key is unconfigured in development", async () => {
    const res = await verifyTurnstileToken({
      secretKey: "",
      required: false,
    });
    expect(res.success).toBe(true);
    expect(res.status).toBe("unconfigured_bypassed");
  });

  it("fails closed when verification is required but secret key is missing", async () => {
    const res = await verifyTurnstileToken({
      secretKey: "",
      required: true,
    });
    expect(res.success).toBe(false);
    expect(res.status).toBe("service_unavailable");
  });

  it("fails when token is missing or empty", async () => {
    const res = await verifyTurnstileToken({
      token: "   ",
      secretKey: "0x4AAAAAAtestsecret",
    });
    expect(res.success).toBe(false);
    expect(res.status).toBe("failed");
    expect(res.errorCodes).toContain("missing-input-response");
  });

  it("verifies valid token successfully via Cloudflare siteverify API", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        action: "scan_submit",
        hostname: "vibeshield.ai",
      }),
    });

    const res = await verifyTurnstileToken({
      token: "valid-token-123",
      secretKey: "0x4AAAAAAtestsecret",
      fetchImpl: mockFetch as unknown as typeof fetch,
      expectedAction: "scan_submit",
      expectedHostname: "vibeshield.ai",
    });

    expect(res.success).toBe(true);
    expect(res.status).toBe("verified");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("rejects expired or duplicate challenge tokens", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: false,
        "error-codes": ["timeout-or-duplicate"],
      }),
    });

    const res = await verifyTurnstileToken({
      token: "expired-token",
      secretKey: "0x4AAAAAAtestsecret",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("failed");
    expect(res.message).toMatch(/expired or already used/i);
  });

  it("rejects when action name mismatches configured expected action", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        action: "login_attempt",
      }),
    });

    const res = await verifyTurnstileToken({
      token: "valid-token",
      secretKey: "0x4AAAAAAtestsecret",
      expectedAction: "scan_submit",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("failed");
    expect(res.errorCodes).toContain("action-mismatch");
  });

  it("rejects when action is missing but expected action is configured", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        // action omitted
      }),
    });

    const res = await verifyTurnstileToken({
      token: "valid-token",
      secretKey: "0x4AAAAAAtestsecret",
      expectedAction: "scan_submit",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("failed");
    expect(res.errorCodes).toContain("missing-action");
  });

  it("rejects when hostname mismatches configured expected hostname", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        hostname: "attacker.com",
      }),
    });

    const res = await verifyTurnstileToken({
      token: "valid-token",
      secretKey: "0x4AAAAAAtestsecret",
      expectedHostname: "vibeshield.ai",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("failed");
    expect(res.errorCodes).toContain("hostname-mismatch");
  });

  it("rejects when hostname is missing but expected hostname is configured", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        // hostname omitted
      }),
    });

    const res = await verifyTurnstileToken({
      token: "valid-token",
      secretKey: "0x4AAAAAAtestsecret",
      expectedHostname: "vibeshield.ai",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("failed");
    expect(res.errorCodes).toContain("missing-hostname");
  });

  it("fails closed with service_unavailable on Cloudflare HTTP 500 error", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });

    const res = await verifyTurnstileToken({
      token: "valid-token",
      secretKey: "0x4AAAAAAtestsecret",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("service_unavailable");
    expect(res.errorCodes).toContain("http-500");
  });

  it("fails closed with service_unavailable on network or timeout error", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("Connection reset"));

    const res = await verifyTurnstileToken({
      token: "valid-token",
      secretKey: "0x4AAAAAAtestsecret",
      fetchImpl: mockFetch as unknown as typeof fetch,
    });

    expect(res.success).toBe(false);
    expect(res.status).toBe("service_unavailable");
    expect(res.errorCodes).toContain("network-error");
  });

  it("rejects submitScan with 403 when Turnstile token verification fails", async () => {
    const store = new InMemoryJobStore();
    const config = getConfig();

    const req = new Request("http://localhost:3100/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repositoryUrl: "https://github.com/owner/repo",
        turnstileToken: "invalid-token",
      }),
    });

    const mockVerify = vi.fn().mockResolvedValue({
      success: false,
      status: "failed",
      message: "Security verification failed.",
    });

    const res = await submitScan(req, {
      store,
      config,
      enqueue: vi.fn(),
      rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: async () => true,
      verifyTurnstile: mockVerify,
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.code).toBe("turnstile_verification_failed");
  });
});
