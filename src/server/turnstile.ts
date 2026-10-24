export type TurnstileVerificationResult = {
  success: boolean;
  status: "verified" | "failed" | "unconfigured_bypassed" | "service_unavailable";
  message: string;
  errorCodes?: string[];
  hostname?: string;
  action?: string;
};

export type VerifyTurnstileParams = {
  token?: string | null;
  clientIp?: string;
  secretKey?: string;
  required?: boolean;
  expectedAction?: string;
  expectedHostname?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
};

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/**
 * Server-side verification for Cloudflare Turnstile challenge tokens.
 *
 * Implements strict abuse protection:
 * - Validates response token against Cloudflare's siteverify API.
 * - Enforces expected action and hostname if configured.
 * - Prevents reuse, expired tokens, or forged challenges.
 * - Safely handles missing credentials, network timeouts, and unexpected provider responses.
 */
export async function verifyTurnstileToken(params: VerifyTurnstileParams): Promise<TurnstileVerificationResult> {
  const secretKey = (params.secretKey ?? process.env.TURNSTILE_SECRET_KEY)?.trim();
  const required = params.required ?? (process.env.TURNSTILE_REQUIRED === "true");
  const expectedAction = (params.expectedAction ?? process.env.TURNSTILE_EXPECTED_ACTION)?.trim();
  const expectedHostname = (params.expectedHostname ?? process.env.TURNSTILE_EXPECTED_HOSTNAME)?.trim();
  const fetchFn = params.fetchImpl ?? fetch;
  const timeoutMs = params.timeoutMs ?? 5000;

  if (!secretKey) {
    if (required) {
      return {
        success: false,
        status: "service_unavailable",
        message: "Public abuse protection is required but verification service is not configured.",
      };
    }
    // In local development or testing without Turnstile credentials, bypass with notification
    return {
      success: true,
      status: "unconfigured_bypassed",
      message: "Turnstile verification bypassed (unconfigured in development).",
    };
  }

  const token = params.token?.trim();
  if (!token) {
    return {
      success: false,
      status: "failed",
      message: "Security verification challenge token is missing. Please complete the verification.",
      errorCodes: ["missing-input-response"],
    };
  }

  const formData = new URLSearchParams();
  formData.append("secret", secretKey);
  formData.append("response", token);
  if (params.clientIp && params.clientIp !== "unknown") {
    formData.append("remoteip", params.clientIp);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchFn(SITEVERIFY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: formData.toString(),
      signal: controller.signal,
    });

    if (!res.ok) {
      return {
        success: false,
        status: "service_unavailable",
        message: "Security verification service returned an unexpected response. Please try again shortly.",
        errorCodes: [`http-${res.status}`],
      };
    }

    const data = (await res.json()) as {
      success?: boolean;
      "error-codes"?: string[];
      challenge_ts?: string;
      hostname?: string;
      action?: string;
      cdata?: string;
    };

    if (!data.success) {
      const codes = data["error-codes"] || [];
      const isExpiredOrUsed = codes.includes("timeout-or-duplicate");
      return {
        success: false,
        status: "failed",
        message: isExpiredOrUsed
          ? "Verification challenge expired or already used. Please refresh and try again."
          : "Security verification failed. Please try again.",
        errorCodes: codes,
      };
    }

    // Validate expected action if specified
    if (expectedAction && data.action && data.action !== expectedAction) {
      return {
        success: false,
        status: "failed",
        message: "Security verification action mismatch.",
        errorCodes: ["action-mismatch"],
      };
    }

    // Validate expected hostname if specified
    if (expectedHostname && data.hostname && data.hostname.toLowerCase() !== expectedHostname.toLowerCase()) {
      return {
        success: false,
        status: "failed",
        message: "Security verification hostname mismatch.",
        errorCodes: ["hostname-mismatch"],
      };
    }

    return {
      success: true,
      status: "verified",
      message: "Security verification passed.",
      hostname: data.hostname,
      action: data.action,
    };
  } catch {
    const isTimeout = controller.signal.aborted;
    return {
      success: false,
      status: "service_unavailable",
      message: isTimeout
        ? "Security verification timed out. Please try again."
        : "Could not reach security verification service.",
      errorCodes: [isTimeout ? "timeout" : "network-error"],
    };
  } finally {
    clearTimeout(timer);
  }
}
