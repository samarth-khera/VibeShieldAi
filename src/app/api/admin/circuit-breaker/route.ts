import { getConfig } from "@/server/config";
import { fail, ok } from "@/server/api";
import {
  getAiCircuitBreakerStatus,
  resetAiCircuitBreaker,
  tripAiCircuitBreaker,
} from "@/server/ai/circuit-breaker";

function authenticateAdmin(req: Request): boolean {
  const config = getConfig();
  const secret = config.adminSecret || process.env.ADMIN_SECRET || process.env.SCAN_CALLBACK_SECRET;
  if (!secret) return false;

  const authHeader = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim();
  const customHeader = req.headers.get("x-vibeshield-admin-secret")?.trim();

  return Boolean(
    (authHeader && authHeader === secret) ||
    (customHeader && customHeader === secret)
  );
}

export async function GET(req: Request): Promise<Response> {
  if (!authenticateAdmin(req)) {
    return fail(401, "unauthorized", "Unauthorized: Valid admin authorization required.");
  }

  const status = await getAiCircuitBreakerStatus();
  return ok(status);
}

export async function POST(req: Request): Promise<Response> {
  if (!authenticateAdmin(req)) {
    return fail(401, "unauthorized", "Unauthorized: Valid admin authorization required.");
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return fail(400, "invalid_json", "Request body must be valid JSON.");
  }

  const { action, reason, message, cooldownMinutes } = (body as {
    action?: string;
    reason?: "quota_exhausted" | "rate_limited" | "api_error" | "manual";
    message?: string;
    cooldownMinutes?: number;
  }) || {};

  if (action === "reset") {
    await resetAiCircuitBreaker();
    const updated = await getAiCircuitBreakerStatus();
    return ok({ success: true, message: "AI circuit breaker has been reset.", status: updated });
  }

  if (action === "trip") {
    await tripAiCircuitBreaker({
      reason: reason || "manual",
      message: message || "AI Security Analyst manually paused by administrator.",
      cooldownMs: typeof cooldownMinutes === "number" ? cooldownMinutes * 60 * 1000 : undefined,
    });
    const updated = await getAiCircuitBreakerStatus();
    return ok({ success: true, message: "AI circuit breaker has been tripped.", status: updated });
  }

  return fail(400, "invalid_action", "Invalid action. Supported actions: 'reset' | 'trip'.");
}
