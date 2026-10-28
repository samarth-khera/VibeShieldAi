import { repositoryUrlForWorker } from "./auth/private-source";
import { getAuthDeps } from "./deps";
import { z } from "zod";
import { fail, ok } from "./api";
import { verifyCallbackSignature } from "./callback-auth";
import type { ServerConfig } from "./config";
import { log } from "./errors";
import type { JobStore } from "./job-store";
import { WARM_LEASE_PREFIX } from "./quota";
import { buildVerificationSpec } from "./remediation/api";

// Worker-only control plane for the persistent warm worker. The worker connects outbound over
// HTTPS (no inbound port on the VM). Every request is HMAC-signed with WARM_WORKER_SECRET, carries
// a strictly increasing per-worker request timestamp (replays are rejected), and the endpoints do
// not exist unless WARM_WORKER_ENABLED=true.

const MAX_BODY_BYTES = 16 * 1024;
const MAX_CLOCK_SKEW_MS = 5 * 60_000;

const Identity = {
  workerId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/),
  requestMs: z.number().int().positive(),
  capacity: z.number().int().min(1).max(4),
  activeJobs: z.number().int().min(0).max(4),
  version: z.string().max(40).optional(),
  arch: z.string().max(40).optional(),
  scannerVersions: z.record(z.string(), z.string().max(80)).optional(),
};

const ClaimSchema = z.object({ ...Identity, accept: z.array(z.enum(["scan", "verify"])).min(1).max(2) });
const HeartbeatSchema = z.object({ ...Identity, leases: z.array(z.string().max(100)).max(4) });

export type WorkerApiDeps = { store: JobStore; config: ServerConfig; now?: () => Date };

type AuthResult<T> = { ok: false; response: Response } | { ok: true; body: T; now: Date };

async function authenticate<T extends z.ZodTypeAny>(req: Request, schema: T, deps: WorkerApiDeps): Promise<AuthResult<z.infer<T>>> {
  const { config } = deps;
  if (!config.warmWorkerEnabled || !config.warmWorkerSecret) {
    return { ok: false, response: fail(404, "not_found", "Not found.") } as const;
  }
  const declared = Number.parseInt(req.headers.get("content-length") ?? "0", 10);
  if (declared > MAX_BODY_BYTES) return { ok: false, response: fail(413, "payload_too_large", "Request too large.") } as const;
  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return { ok: false, response: fail(413, "payload_too_large", "Request too large.") } as const;
  if (!verifyCallbackSignature(raw, req.headers.get("x-vibeshield-signature"), config.warmWorkerSecret).valid) {
    return { ok: false, response: fail(401, "unauthorized", "Invalid or missing worker signature.") } as const;
  }
  let body: z.infer<T>;
  try {
    const parsed = schema.safeParse(JSON.parse(raw));
    if (!parsed.success) return { ok: false, response: fail(400, "validation_failed", "Request does not match schema.") } as const;
    body = parsed.data;
  } catch {
    return { ok: false, response: fail(400, "invalid_json", "Request body must be valid JSON.") } as const;
  }
  const now = (deps.now ?? (() => new Date()))();
  const b = body as { workerId: string; requestMs: number; capacity: number; activeJobs: number; version?: string; arch?: string; scannerVersions?: Record<string, string> };
  if (Math.abs(now.getTime() - b.requestMs) > MAX_CLOCK_SKEW_MS) {
    return { ok: false, response: fail(401, "timestamp_expired", "Request timestamp outside the allowed window.") } as const;
  }
  if (!deps.store.recordWorkerHeartbeat || !(await deps.store.recordWorkerHeartbeat(b, now))) {
    return { ok: false, response: fail(409, "replayed_request", "Request timestamp was already used.") } as const;
  }
  return { ok: true, body, now } as const;
}

/**
 * POST /api/internal/worker/claim — returns at most one unit of work for a free worker slot.
 * Verifications come first (a user is waiting on them and their slot is already reserved).
 */
export async function handleWorkerClaim(req: Request, deps: WorkerApiDeps): Promise<Response> {
  const auth = await authenticate(req, ClaimSchema, deps);
  if (!auth.ok) return auth.response;
  const { body, now } = auth;
  const idle = { work: null, pollAfterMs: 2000 };
  if (body.activeJobs >= body.capacity) return ok(idle);

  await deps.store.reapStale(now, deps.config).catch(() => undefined);

  if (body.accept.includes("verify") && deps.store.claimNextVerification) {
    const v = await deps.store.claimNextVerification(body.workerId, deps.config, now);
    if (v) {
      log("info", "warm_worker_claimed", { kind: "verify", jobId: v.job.id, remediationId: v.remediation.id, workerId: body.workerId });
      return ok({ work: { kind: "verify", lease: v.lease, spec: await buildVerificationSpec(v.job, v.remediation, deps.store, getAuthDeps(deps.config)) }, pollAfterMs: 0 });
    }
  }
  if (body.accept.includes("scan") && deps.store.claimNextScan) {
    const c = await deps.store.claimNextScan({ kind: "warm", workerId: body.workerId }, deps.config, now);
    if (c) {
      const queuedMs = now.getTime() - c.job.createdAt.getTime();
      log("info", "warm_worker_claimed", { kind: "scan", jobId: c.job.id, workerId: body.workerId, queuedMs });
      return ok({
        work: {
          kind: "scan",
          jobId: c.job.id,
          repositoryUrl: await repositoryUrlForWorker(c.job.id, c.job.repositoryUrl, getAuthDeps(deps.config)),
          lease: c.lease,
          acceptedAt: c.job.createdAt.toISOString(),
        },
        pollAfterMs: 0,
      });
    }
  }
  return ok(idle);
}

/**
 * POST /api/internal/worker/heartbeat — renews the worker's leases. A lease that renews nothing has
 * been lost (expired and re-queued, or finished), and the worker must abandon that work.
 */
export async function handleWorkerHeartbeat(req: Request, deps: WorkerApiDeps): Promise<Response> {
  const auth = await authenticate(req, HeartbeatSchema, deps);
  if (!auth.ok) return auth.response;
  const { body, now } = auth;
  const own = `${WARM_LEASE_PREFIX}${body.workerId}:`;
  const leases: Record<string, boolean> = {};
  for (const lease of body.leases) {
    leases[lease] = lease.startsWith(own) && deps.store.renewLease ? (await deps.store.renewLease(lease, now)) > 0 : false;
  }
  return ok({ leases });
}
