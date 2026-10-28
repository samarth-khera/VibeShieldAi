import { createHmac, timingSafeEqual } from "node:crypto";

export type CallbackSignatureResult =
  | { valid: true; timestamp: number }
  | { valid: false; reason: "missing_header" | "malformed_header" | "timestamp_expired" | "signature_mismatch" | "missing_secret" };

const MAX_DRIFT_SECONDS = 300; // 5 minutes replay protection window

/**
 * Computes an HMAC-SHA256 signature for a callback payload.
 * Format: `t={timestamp},v1={hex_signature}`
 */
export function signCallbackPayload(payload: string, secret: string, timestamp: number = Math.floor(Date.now() / 1000)): string {
  const message = `${timestamp}.${payload}`;
  const hmac = createHmac("sha256", secret).update(message).digest("hex");
  return `t=${timestamp},v1=${hmac}`;
}

/**
 * Validates the HMAC-SHA256 signature and timestamp of a received callback request.
 */
export function verifyCallbackSignature(
  rawBody: string,
  signatureHeader: string | null | undefined,
  secret: string | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): CallbackSignatureResult {
  if (!secret) {
    return { valid: false, reason: "missing_secret" };
  }
  if (!signatureHeader) {
    return { valid: false, reason: "missing_header" };
  }

  // Parse t={timestamp},v1={hash}
  const parts = signatureHeader.split(",");
  let timestampStr: string | undefined;
  let signatureHex: string | undefined;

  for (const part of parts) {
    const [k, v] = part.trim().split("=");
    if (k === "t") timestampStr = v;
    if (k === "v1") signatureHex = v;
  }

  if (!timestampStr || !signatureHex) {
    return { valid: false, reason: "malformed_header" };
  }

  const timestamp = Number.parseInt(timestampStr, 10);
  if (!Number.isFinite(timestamp)) {
    return { valid: false, reason: "malformed_header" };
  }

  // Replay check: reject if timestamp is older than 300s or in future by > 60s
  if (Math.abs(nowSeconds - timestamp) > MAX_DRIFT_SECONDS) {
    return { valid: false, reason: "timestamp_expired" };
  }

  const expectedHmac = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");

  try {
    const a = Buffer.from(signatureHex, "hex");
    const b = Buffer.from(expectedHmac, "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, reason: "signature_mismatch" };
    }
  } catch {
    return { valid: false, reason: "signature_mismatch" };
  }

  return { valid: true, timestamp };
}

/** Canonical string the verification worker signs when requesting an approved remediation spec. */
export function verificationSpecSigningPayload(scanJobId: string, remediationId: string): string {
  return `verification-spec:${scanJobId}:${remediationId}`;
}
