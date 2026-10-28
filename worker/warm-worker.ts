/**
 * Persistent warm scanner worker. Run with: npm run worker:warm
 *
 * Connects outbound to the VibeShield API over HTTPS (no inbound job-control port), claims scans and
 * Auto-Fix verifications through the signed internal worker API, and runs them with the scanner
 * binaries installed once on this host. It never has database credentials: every state change goes
 * through the same signed callbacks and lease checks as the GitHub Actions worker.
 *
 * Required env: VIBESHIELD_API_URL, WARM_WORKER_SECRET, WORKER_ID.
 * Optional env: WORKER_CAPACITY (1), WORKER_IDLE_POLL_MS (5000), WORKER_HEARTBEAT_MS (10000),
 *   WORKER_ARCHIVE_CACHE_DIR, WORKER_ARCHIVE_CACHE_MAX_MB (1024), WORKER_ARCHIVE_CACHE_TTL_HOURS (24),
 *   WORKER_HEALTH_PORT (loopback-only health endpoint), WORKER_SHUTDOWN_GRACE_MS (60000), GITHUB_TOKEN.
 */
import { createServer } from "node:http";
import { arch, tmpdir } from "node:os";
import path from "node:path";
import { getConfig } from "../src/server/config";
import { JOB_ID_RE } from "../src/server/job-store";
import { detectScannerVersions } from "../src/server/scanners/engine";
import { redactText } from "../src/server/scanners/redact";
import { verifyRemediationOnSnapshot } from "../src/server/remediation/verify";
import type { BaselineFinding } from "../src/server/remediation/sandbox";
import type { RescanComparison } from "../src/server/remediation/types";
import { createArchiveCache } from "../src/server/worker/archive-cache";
import { executeScanJob } from "../src/server/worker/scan-executor";
import { postSigned } from "../src/server/worker/signed-http";

const VERSION = "warm-worker/0.3";
const env = (name: string) => process.env[name]?.trim() || undefined;
const int = (name: string, fallback: number) => {
  const n = Number.parseInt(env(name) ?? "", 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const API = env("VIBESHIELD_API_URL")?.replace(/\/+$/, "");
const SECRET = env("WARM_WORKER_SECRET");
const WORKER_ID = env("WORKER_ID");
if (!API || !SECRET || !WORKER_ID || !/^[a-z0-9][a-z0-9-]{0,39}$/.test(WORKER_ID)) {
  console.error("VIBESHIELD_API_URL, WARM_WORKER_SECRET and a lowercase WORKER_ID are required.");
  process.exit(1);
}
const apiUrl = new URL(API);
if (apiUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "host.docker.internal"].includes(apiUrl.hostname)) {
  console.error("VIBESHIELD_API_URL must use HTTPS (plain HTTP is only allowed for local development).");
  process.exit(1);
}

const CAPACITY = Math.min(int("WORKER_CAPACITY", 1), 4);
const IDLE_POLL_MS = int("WORKER_IDLE_POLL_MS", 5000);
const HEARTBEAT_MS = int("WORKER_HEARTBEAT_MS", 10_000);
const SHUTDOWN_GRACE_MS = int("WORKER_SHUTDOWN_GRACE_MS", 60_000);
const config = getConfig();
const archives = createArchiveCache({
  dir: env("WORKER_ARCHIVE_CACHE_DIR") ?? path.join(tmpdir(), "vibeshield-archive-cache"),
  maxBytes: int("WORKER_ARCHIVE_CACHE_MAX_MB", 1024) * 1024 * 1024,
  ttlMs: int("WORKER_ARCHIVE_CACHE_TTL_HOURS", 24) * 3600_000,
});

type ActiveJob = { kind: "scan" | "verify"; id: string; lease: string; startedAt: number };
const active = new Map<string, ActiveJob>();
let stopping = false;
let lastRequestMs = 0;
let lastClaimOkAt: string | null = null;
let scannerVersions: Record<string, string> = {};

const log = (event: string, fields: Record<string, unknown> = {}) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), event, workerId: WORKER_ID, ...fields }));

/** Strictly increasing per-worker request timestamp: the API rejects anything not newer (replays). */
function nextRequestMs(): number {
  lastRequestMs = Math.max(Date.now(), lastRequestMs + 1);
  return lastRequestMs;
}

function identity() {
  return {
    workerId: WORKER_ID!,
    requestMs: nextRequestMs(),
    capacity: CAPACITY,
    activeJobs: active.size,
    version: VERSION,
    arch: `${process.platform}-${arch()}`,
    scannerVersions,
  };
}

async function api<T>(route: string, body: Record<string, unknown>): Promise<T> {
  const res = await postSigned(`${API}${route}`, SECRET!, body, { attempts: 1, timeoutMs: 15_000 });
  const json = (await res.json().catch(() => null)) as { data?: T; error?: { code: string } } | null;
  if (!res.ok || !json?.data) throw new Error(`${route} -> HTTP ${res.status} ${json?.error?.code ?? ""}`.trim());
  return json.data;
}

type ScanWork = { kind: "scan"; jobId: string; repositoryUrl: string; lease: string; acceptedAt: string };
type VerifyWork = {
  kind: "verify";
  lease: string;
  spec: {
    scanJobId: string;
    remediationId: string;
    owner: string;
    repo: string;
    commitSha: string;
    unifiedDiff: string;
    targetedFingerprints: string[];
    baselineFindings: BaselineFinding[];
    queuedAt: string;
    /** Private repositories only: short-lived archive URL. Never logged or cached. */
    archiveUrl?: string;
  };
};

async function runScan(work: ScanWork) {
  if (!JOB_ID_RE.test(work.jobId)) return;
  const claimedAt = new Date().toISOString();
  const callbackUrl = `${API}/api/scans/${encodeURIComponent(work.jobId)}/callback`;
  // Announce the start immediately; the shared executor then reports each phase.
  await postSigned(callbackUrl, SECRET!, { type: "progress", jobId: work.jobId, lease: work.lease, phase: "worker_started", at: claimedAt }, { attempts: 1 }).catch(() => undefined);
  const outcome = await executeScanJob({
    jobId: work.jobId,
    repositoryUrl: work.repositoryUrl,
    callbackUrl,
    secret: SECRET!,
    lease: work.lease,
    runnerStartedAt: claimedAt,
    config,
    archives,
    log: (line) => log("scan_log", { jobId: work.jobId, line }),
  });
  log("scan_finished", { jobId: work.jobId, outcome, pickupMs: Date.parse(claimedAt) - Date.parse(work.acceptedAt) });
}

async function runVerification(work: VerifyWork) {
  const { spec } = work;
  if (!JOB_ID_RE.test(spec.scanJobId) || !/^[0-9a-f-]{36}$/.test(spec.remediationId)) return;
  const url = `${API}/api/scans/${encodeURIComponent(spec.scanJobId)}/remediation/${encodeURIComponent(spec.remediationId)}/verification`;
  const t0 = Date.now();
  const report = async (rescanStatus: "verified" | "needs_review" | "failed", summary: RescanComparison) => {
    const res = await postSigned(url, SECRET!, { scanJobId: spec.scanJobId, remediationId: spec.remediationId, lease: work.lease, rescanStatus, summary });
    log("verification_reported", { remediationId: spec.remediationId, rescanStatus, http: res.status });
  };
  try {
    const result = await verifyRemediationOnSnapshot({
      owner: spec.owner,
      repo: spec.repo,
      commitSha: spec.commitSha,
      unifiedDiff: spec.unifiedDiff,
      targetedFingerprints: spec.targetedFingerprints,
      baselineFindings: spec.baselineFindings,
      config,
      // Private snapshots are downloaded fresh and never enter the on-disk archive cache.
      ...(spec.archiveUrl ? { archiveUrl: spec.archiveUrl } : { archives }),
    });
    const queuedAt = Date.parse(spec.queuedAt);
    result.summary.timings = {
      ...result.summary.timings,
      queueMs: Number.isFinite(queuedAt) ? Math.max(0, t0 - queuedAt) : undefined,
      totalMs: Date.now() - t0,
    };
    await report(result.rescanStatus, result.summary);
  } catch (err) {
    await report("failed", {
      targetResolved: false,
      originalFindingsCount: 0,
      postRescanFindingsCount: 0,
      newFindingsCount: 0,
      resolvedFingerprints: [],
      remainingFingerprints: [],
      regressions: [],
      reason: "worker_failed",
      detail: redactText(err instanceof Error ? err.message : String(err)).slice(0, 280),
      timings: { totalMs: Date.now() - t0 },
    }).catch(() => log("verification_report_failed", { remediationId: spec.remediationId }));
  }
}

function start(work: ScanWork | VerifyWork) {
  const id = work.kind === "scan" ? work.jobId : work.spec.remediationId;
  active.set(work.lease, { kind: work.kind, id, lease: work.lease, startedAt: Date.now() });
  log("claimed", { kind: work.kind, id });
  const run = work.kind === "scan" ? runScan(work) : runVerification(work);
  void run
    .catch((err) => log("job_crashed", { kind: work.kind, id, error: redactText(err instanceof Error ? err.message : String(err)).slice(0, 200) }))
    .finally(() => active.delete(work.lease));
}

/** Claims work while a slot is free: immediately after any claim, backing off to IDLE_POLL_MS when idle. */
async function claimLoop() {
  let idleDelay = 500;
  while (!stopping) {
    let delay = idleDelay;
    if (active.size < CAPACITY) {
      try {
        const res = await api<{ work: ScanWork | VerifyWork | null; pollAfterMs: number }>("/api/internal/worker/claim", {
          ...identity(),
          accept: ["verify", "scan"],
        });
        lastClaimOkAt = new Date().toISOString();
        if (res.work) {
          start(res.work);
          idleDelay = 500;
          delay = 0;
        } else {
          idleDelay = Math.min(IDLE_POLL_MS, idleDelay * 2);
          delay = idleDelay;
        }
      } catch (err) {
        log("claim_failed", { error: err instanceof Error ? err.message : "unknown" });
        delay = Math.min(IDLE_POLL_MS * 2, 15_000);
      }
    } else {
      delay = 1000;
    }
    await new Promise((r) => setTimeout(r, delay));
  }
}

/** Renews leases of running work. A lease the server no longer honours means the work was superseded. */
async function heartbeatLoop() {
  while (!stopping || active.size > 0) {
    await new Promise((r) => setTimeout(r, HEARTBEAT_MS));
    if (active.size === 0) continue;
    try {
      const res = await api<{ leases: Record<string, boolean> }>("/api/internal/worker/heartbeat", {
        ...identity(),
        leases: [...active.keys()],
      });
      for (const [lease, renewed] of Object.entries(res.leases)) {
        if (!renewed && active.has(lease)) log("lease_lost", { id: active.get(lease)!.id });
      }
    } catch (err) {
      log("heartbeat_failed", { error: err instanceof Error ? err.message : "unknown" });
    }
  }
}

function startHealthServer() {
  const port = int("WORKER_HEALTH_PORT", 0);
  if (!port) return;
  createServer((req, res) => {
    const ready = !stopping && Boolean(lastClaimOkAt);
    const body = JSON.stringify({ status: ready ? "ready" : stopping ? "stopping" : "starting", workerId: WORKER_ID, version: VERSION, capacity: CAPACITY, activeJobs: active.size, lastClaimOkAt, scannerVersions });
    res.writeHead(req.url === "/healthz" ? (ready ? 200 : 503) : 404, { "Content-Type": "application/json" }).end(body);
  }).listen(port, "127.0.0.1"); // loopback only: never a public control port
}

async function main() {
  // Refuse to claim work unless every scanner is really installed: a missing binary must never look like a clean scan.
  const versions = await detectScannerVersions(true);
  if (Object.values(versions).some((v) => !v || v === "unavailable")) {
    log("scanners_unavailable", { versions });
    process.exit(1);
  }
  scannerVersions = Object.fromEntries(Object.entries(versions).map(([k, v]) => [k, String(v)]));
  log("worker_started", { capacity: CAPACITY, idlePollMs: IDLE_POLL_MS, scannerVersions, api: apiUrl.origin });
  startHealthServer();

  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    log("shutdown_requested", { signal, activeJobs: active.size });
    // Unfinished leases expire server-side and the jobs are re-queued for another attempt.
    setTimeout(() => process.exit(0), SHUTDOWN_GRACE_MS).unref();
    const wait = setInterval(() => {
      if (active.size === 0) {
        clearInterval(wait);
        log("shutdown_complete");
        process.exit(0);
      }
    }, 250);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  void heartbeatLoop();
  await claimLoop();
}

main().catch((err) => {
  console.error("Warm worker crashed:", err instanceof Error ? redactText(err.message) : "unknown");
  process.exit(1);
});
