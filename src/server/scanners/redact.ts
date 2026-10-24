import { createHash } from "node:crypto";

const SECRET_PATTERNS: RegExp[] = [
  // GitHub tokens
  /gh[pousr]_[A-Za-z0-9_]{16,255}/g,
  /github_pat_[A-Za-z0-9_]{22,255}/g,
  // AWS keys
  /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
  // Slack tokens
  /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
  // Stripe keys
  /(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}/g,
  // Private keys
  /-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----/g,
  // Generic high-entropy assignments: key = "..."
  /(?:password|passwd|secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*["']([^"']{8,})["']/gi,
  // Bearer tokens
  /Bearer\s+[A-Za-z0-9._~+/-]{16,}/gi,
];

/**
 * Replaces known credentials or potential secret substrings with [REDACTED].
 */
export function redactText(text: string | null | undefined): string {
  if (!text) return "";
  let result = text;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replace(pattern, (match, captured) => {
      // If there's a capture group (e.g. key = "value"), replace only the value
      if (captured && typeof captured === "string") {
        return match.replace(captured, "••••••••");
      }
      return "[REDACTED]";
    });
  }
  return result;
}

/**
 * Ensures code lines in evidence snippets do not leak raw secret values.
 */
export function redactEvidence(evidence: string | null | undefined): string | null {
  if (!evidence) return null;
  return redactText(evidence);
}

/**
 * Computes a stable, non-reversible SHA-256 fingerprint for deduplication.
 */
export function computeFingerprint(parts: (string | number | null | undefined)[]): string {
  const content = parts.map((p) => String(p ?? "")).join("::");
  return createHash("sha256").update(content).digest("hex").slice(0, 32);
}
