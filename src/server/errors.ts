import type { ScanStatus } from "@prisma/client";

/** Terminal failure statuses a retrieval can end in. */
export type FailureStatus = Extract<ScanStatus, "invalid_repository" | "download_failed" | "rejected_by_limits" | "failed">;

/**
 * An expected, user-explainable retrieval failure. `publicMessage` is safe to show to users;
 * it must never contain internal details, tokens or stack traces.
 */
export class RetrievalError extends Error {
  constructor(
    public readonly status: FailureStatus,
    public readonly category: string,
    public readonly publicMessage: string,
  ) {
    super(`${status}:${category}`);
    this.name = "RetrievalError";
  }
}

/** Minimal structured logger: only primitive, pre-vetted fields. Never pass URLs with queries or secrets. */
export function log(level: "info" | "warn" | "error", event: string, fields: Record<string, string | number | boolean | null | undefined> = {}) {
  const line = JSON.stringify({ t: new Date().toISOString(), level, event, ...fields });
  (level === "error" ? console.error : level === "warn" ? console.warn : console.log)(line);
}
