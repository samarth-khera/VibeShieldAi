"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  Eye,
  KeyRound,
  Layers,
  Loader2,
  Package,
  RotateCw,
  Search,
  SearchX,
  ShieldCheck,
  ShieldX,
  Sparkles,
} from "lucide-react";
import { SeverityBadge, severityStyles } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import {
  fetchFindings,
  fetchScan,
  reportStateOf,
  retryScan,
  type PublicFinding,
  type PublicScanJob,
  listRemediations,
  type PublicRemediation,
} from "@/lib/scan-client";
import { findingFixStatus } from "@/lib/remediation-eligibility";
import { useAdaptivePoll } from "@/lib/use-adaptive-poll";
import { cn } from "@/lib/utils";
import { RealFindingDrawer } from "./real-finding-drawer";

type Severity = "critical" | "high" | "medium" | "low" | "info";
const ACTIVE_SCAN_STATUSES: PublicScanJob["status"][] = ["queued", "retrieving", "scanning"];

function formatMs(ms: number): string {
  if (ms < 1000) return `${Math.max(0, Math.round(ms))}ms`;
  const s = ms / 1000;
  return s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

const between = (from?: string | null, to?: string | null) =>
  from && to ? Math.max(0, Date.parse(to) - Date.parse(from)) : null;

/** One line of real stage timings; queue wait is reported separately from active scan time. */
function describeStageTimings(job: PublicScanJob): string {
  const d = job.scanCoverage?.stageDurations ?? {};
  const p = job.scanCoverage?.progress ?? {};
  const parts: string[] = [];
  const queue = between(job.createdAt, p.worker_startedAt);
  const setup = between(p.worker_startedAt, p.retrievingAt);
  if (queue != null) parts.push(`Queue wait ${formatMs(queue)}`);
  if (setup != null) parts.push(`Runner setup ${formatMs(setup)}`);
  parts.push(`Retrieval ${formatMs((d.metadataMs ?? 0) + (d.downloadMs ?? 0))}`);
  parts.push(`Extraction ${formatMs(d.extractionMs ?? 0)}`);
  const sc = job.scanners;
  const perScanner = sc
    ? ` (Gitleaks ${formatMs(sc.gitleaks.durationMs ?? 0)}, Semgrep ${formatMs(sc.semgrep.durationMs ?? 0)}, OSV ${formatMs(sc.osvScanner.durationMs ?? 0)})`
    : "";
  parts.push(`Scanning ${formatMs(d.scanningMs ?? 0)}${perScanner}`);
  if (d.callbackMs) parts.push(`Callback ${formatMs(d.callbackMs)}`);
  return parts.join(" · ");
}

function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

const PHASES = [
  { key: "queued", label: "Queued", title: "Queued — waiting for a GitHub Actions runner" },
  { key: "worker_started", label: "Runner started", title: "Runner started — preparing scanners" },
  { key: "retrieving", label: "Retrieving", title: "Retrieving repository metadata and archive" },
  { key: "extracting", label: "Extracting", title: "Extracting repository snapshot" },
  { key: "scanning", label: "Scanning", title: "Running Gitleaks, Semgrep, and OSV-Scanner" },
] as const;

function ScanProgressBanner({ job, repoName }: { job: PublicScanJob; repoName: string }) {
  const now = useNow(1000);
  const p = job.scanCoverage?.progress ?? {};
  const reached: Record<string, string | undefined> = {
    queued: job.createdAt,
    worker_started: p.worker_startedAt,
    retrieving: p.retrievingAt,
    extracting: p.extractingAt,
    scanning: p.scanningAt,
  };
  let current = 0;
  PHASES.forEach((phase, i) => {
    if (reached[phase.key]) current = i;
  });
  const created = Date.parse(job.createdAt);
  const workerStarted = p.worker_startedAt ? Date.parse(p.worker_startedAt) : null;
  const queueWait = (workerStarted ?? now) - created;

  return (
    <div className="mt-6 rounded-xl border border-accent/40 bg-accent/5 p-6 sm:p-8" role="status" aria-live="polite">
      <div className="flex flex-col items-center justify-center gap-4 text-center">
        <Loader2 className="size-8 animate-spin text-accent" aria-hidden />
        <div>
          <h2 className="font-display text-2xl font-bold">{PHASES[current].title}…</h2>
          <p className="mt-1 font-mono text-xs text-muted">{repoName}</p>
        </div>
        <ol className="flex flex-wrap items-center justify-center gap-2 font-mono text-[11px]">
          {PHASES.map((phase, i) => (
            <li
              key={phase.key}
              className={cn(
                "rounded-full border px-2.5 py-1",
                i < current && "border-accent/40 text-accent",
                i === current && "border-accent bg-accent/15 font-semibold text-accent",
                i > current && "border-line text-muted",
              )}
            >
              {phase.label}
            </li>
          ))}
        </ol>
        {job.queue?.waitingForSlot && (
          <p className="font-mono text-xs text-foreground">
            All worker slots are busy — your scan is accepted and
            {job.queue.position ? ` #${job.queue.position} in line.` : " waiting in line."}
          </p>
        )}
        {current === PHASES.length - 1 && <ScannerChips job={job} now={now} />}
        <p className="font-mono text-xs text-muted">
          Queue wait {formatMs(queueWait)}
          {workerStarted != null && ` · Worker active ${formatMs(now - workerStarted)}`}
          {job.executor && ` · ${job.executor === "warm-worker" ? "Warm worker" : "GitHub Actions runner"}`}
        </p>
      </div>
    </div>
  );
}

const SCANNERS = [
  { key: "gitleaks", label: "Gitleaks" },
  { key: "semgrep", label: "Semgrep" },
  { key: "osvScanner", label: "OSV-Scanner" },
] as const;

/** Live per-scanner state; findings from finished scanners are already listed below. */
function ScannerChips({ job, now }: { job: PublicScanJob; now: number }) {
  const started = job.scanCoverage?.progress?.scanningAt ? Date.parse(job.scanCoverage.progress.scanningAt) : null;
  return (
    <ul className="flex flex-wrap justify-center gap-2 font-mono text-[11px]" aria-label="Scanner status">
      {SCANNERS.map(({ key, label }) => {
        const s = job.scanners?.[key];
        const state = s?.status === "completed" || s?.status === "failed" ? s.status : "running";
        return (
          <li
            key={key}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md border px-2 py-1",
              state === "completed" && "border-accent/40 text-accent",
              state === "failed" && "border-sev-high/50 text-sev-high",
              state === "running" && "border-line text-muted",
            )}
          >
            {state === "running" ? <Loader2 className="size-3 animate-spin" aria-hidden /> : state === "completed" ? <CheckCircle2 className="size-3" aria-hidden /> : <AlertCircle className="size-3" aria-hidden />}
            {label}{" "}
            {state === "running"
              ? started != null ? `running ${formatMs(now - started)}` : "running"
              : `${state} ${formatMs(s?.durationMs ?? 0)}`}
          </li>
        );
      })}
    </ul>
  );
}
const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

const GITHUB_RETURN_NOTICES: Record<string, string> = {
  connected: "GitHub connected. Repository access is checked again with GitHub before anything is written.",
  installed: "GitHub confirmed the VibeShield app installation. Access for this repository is shown in the Auto-Fix panel.",
  install_requested: "Installation requested. An organization owner must approve the VibeShield app on GitHub before it can be used.",
  installation_not_verified: "GitHub did not confirm an installation visible to your account. No access was granted.",
  cancelled: "GitHub authorization was cancelled. Nothing was connected.",
  connect_first: "Connect GitHub first, then authorize the repository.",
  authorization_expired: "Your GitHub authorization expired. Connect GitHub again.",
  error: "GitHub authorization did not complete. Nothing was connected; you can try again.",
  not_configured: "GitHub authorization is not configured on this deployment yet.",
};

/** After returning from GitHub: reopen the finding in Auto-Fix mode and report the outcome. */
function applyGithubReturn(
  setSelectedId: (id: string) => void,
  setMode: (m: "review" | "autofix") => void,
  setNotice: (n: string) => void,
) {
  const url = new URL(window.location.href);
  const finding = url.searchParams.get("finding");
  const outcome = url.searchParams.get("github");
  if (url.searchParams.get("mode") === "autofix") setMode("autofix");
  if (finding && /^[A-Za-z0-9_-]{1,64}$/.test(finding)) setSelectedId(finding);
  if (outcome) setNotice(GITHUB_RETURN_NOTICES[outcome] ?? GITHUB_RETURN_NOTICES.error);
  if (finding || outcome) {
    for (const k of ["finding", "mode", "github", "reason"]) url.searchParams.delete(k);
    window.history.replaceState(null, "", url.pathname + url.search);
  }
}

export function RealReportView({ jobId }: { jobId: string }) {
  const [job, setJob] = useState<PublicScanJob | null>(null);
  const [findings, setFindings] = useState<PublicFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState<Severity | "all">("all");
  const [category, setCategory] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mode, setMode] = useState<"review" | "autofix">("review");
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set());
  // The server's stored fix decisions (a generated diff, or the reason it needs manual review).
  const [remediations, setRemediations] = useState<PublicRemediation[]>([]);
  useEffect(() => {
    if (mode !== "autofix") return;
    let cancelled = false;
    listRemediations(jobId)
      .then((list) => {
        if (!cancelled) setRemediations(list);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [jobId, mode]);
  const onRemediationUpdated = useCallback((r: PublicRemediation) => {
    setRemediations((prev) => [...prev.filter((x) => x.id !== r.id), r]);
  }, []);
  const decisionFor = useMemo(() => {
    const latest = new Map<string, PublicRemediation>();
    for (const r of [...remediations].filter((x) => x.status !== "rejected").sort((a, b) => a.createdAt.localeCompare(b.createdAt))) {
      for (const fp of r.findingFingerprints) latest.set(fp, r);
    }
    return (fingerprint: string) => latest.get(fingerprint) ?? null;
  }, [remediations]);
  const lastTrigger = useRef<HTMLElement | null>(null);
  const [githubNotice, setGithubNotice] = useState<string | null>(null);
  const returnHandled = useRef(false);

  // Findings are refetched only when the worker published new results (revision changed), and
  // once more when the scan reaches its final state.
  const loadedRevision = useRef<string | null>(null);
  const loadData = useCallback(async () => {
    try {
      const j = await fetchScan(jobId);

      const final = ["completed", "completed_with_warnings"].includes(j.status);
      const partial = j.status === "scanning" && (j.scanCoverage?.progress?.revision ?? 0) > 0;
      const revision = `${j.status}:${j.scanCoverage?.progress?.revision ?? 0}`;
      // Fetch the findings for a new revision before committing the job, so a finished report is
      // never rendered with the previous (possibly empty) findings, which would look like "0 findings".
      let nextFindings: PublicFinding[] | null = null;
      if ((final || partial) && loadedRevision.current !== revision) {
        nextFindings = (await fetchFindings(jobId, { limit: 200 })).findings;
        loadedRevision.current = revision;
      }
      setJob(j);
      if (nextFindings) setFindings(nextFindings);
      setLoading(false);
      if (!returnHandled.current) {
        returnHandled.current = true;
        applyGithubReturn(setSelectedId, setMode, setGithubNotice);
      }
      return j;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scan report.");
      setLoading(false);
      return null;
    }
  }, [jobId]);

  const poll = useCallback(async () => {
    const current = await loadData();
    return Boolean(current && ACTIVE_SCAN_STATUSES.includes(current.status));
  }, [loadData]);
  useAdaptivePoll(poll, true);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const s = (f.severity as Severity) || "medium";
      if (s in c) c[s]++;
    }
    return c;
  }, [findings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings
      .filter((f) => sev === "all" || f.severity === sev)
      .filter((f) => category === "all" || f.category === category)
      .filter(
        (f) =>
          !q ||
          `${f.title} ${f.filePath} ${f.id} ${f.ruleId} ${f.category} ${f.vulnerabilityId ?? ""}`
            .toLowerCase()
            .includes(q),
      )
      .sort((a, b) => {
        const orderA = sevOrder.indexOf(a.severity as Severity);
        const orderB = sevOrder.indexOf(b.severity as Severity);
        return orderA - orderB;
      });
  }, [findings, sev, category, query]);

  const close = useCallback(() => {
    setSelectedId(null);
    window.setTimeout(() => lastTrigger.current?.focus(), 0);
  }, []);

  const toggleSelect = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectAllEligible = useCallback(() => {
    const eligible = new Set<string>();
    for (const f of filtered) {
      if (findingFixStatus(f, decisionFor(f.fingerprint)).eligible) eligible.add(f.id);
    }
    setSelectedFindingIds(eligible);
  }, [filtered, decisionFor]);

  // Only fixes the server confirmed (or that need no server check) count as eligible; lockfile
  // findings without a decision yet are counted separately, never as eligible.
  const selectedFixCounts = useMemo(() => {
    let eligible = 0;
    let pending = 0;
    for (const f of findings) {
      if (!selectedFindingIds.has(f.id)) continue;
      const status = findingFixStatus(f, decisionFor(f.fingerprint));
      if (status.eligible) eligible++;
      else if (status.kind === "decided_on_preview") pending++;
    }
    return { eligible, pending };
  }, [findings, selectedFindingIds, decisionFor]);

  const readOnly = job?.viewer ? !job.viewer.isOwner : false;
  const selected = useMemo(() => findings.find((f) => f.id === selectedId) ?? null, [findings, selectedId]);

  if (loading && !job) {
    return (
      <div className="mx-auto flex min-h-[60vh] max-w-6xl items-center justify-center px-6">
        <div className="flex flex-col items-center gap-3 font-mono text-sm text-muted">
          <Loader2 className="size-6 animate-spin text-accent" />
          Loading security scan report…
        </div>
      </div>
    );
  }

  if (error || !job) {
    return (
      <div className="mx-auto max-w-6xl px-6 py-16">
        <Link href="/" className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-muted hover:text-accent">
          <ArrowLeft className="size-4" aria-hidden /> Back to homepage
        </Link>
        <div className="mt-8 rounded-xl border border-sev-critical/30 bg-sev-critical/5 p-8 text-center">
          <AlertCircle className="mx-auto size-10 text-sev-critical" />
          <h1 className="mt-4 font-display text-2xl font-bold">Unable to load scan report</h1>
          <p className="mt-2 text-sm text-muted">{error ?? "Scan job not found."}</p>
          <Button href="/" variant="secondary" className="mt-6">
            Return to homepage
          </Button>
        </div>
      </div>
    );
  }

  const isScanning = ACTIVE_SCAN_STATUSES.includes(job.status);
  // What this report may claim: only "complete" is a verified result; failed/cancelled scanned nothing.
  const state = reportStateOf(job);
  const notScanned = state === "failed" || state === "cancelled";
  const isPartial = state === "partial";
  const scannerLabel = (status: string | null) => status ?? (notScanned ? "not run" : "pending");
  const incompleteScanners = job.incompleteScanners ?? [];
  // Size and safety limits fail the same way on every retry, so no retry is offered for them.
  const limitFailure = ["archive_too_large", "repo_too_large", "file_count", "unpacked_size", "unsafe_entry", "unsafe_path"].includes(
    job.failure?.category ?? "",
  );
  const repoName = `${job.repository.owner}/${job.repository.name}`;

  return (
    <div className="relative pb-20">
      <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-96" aria-hidden />
      <div className="relative mx-auto max-w-6xl px-6 py-10">
        <Link href="/" className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-muted hover:text-accent">
          <ArrowLeft className="size-4" aria-hidden /> Back to homepage
        </Link>

        {readOnly && (
          <div role="note" className="mt-4 rounded-lg border border-line bg-surface p-3 text-sm text-muted">
            <span className="font-semibold text-foreground">Read-only report.</span> Only the browser session that started this
            scan can generate, approve, verify or publish fixes. Start your own scan to work on fixes.
          </div>
        )}

        {githubNotice && (
          <div role="status" className="mt-4 rounded-lg border border-line bg-surface p-3 text-sm text-foreground">
            {githubNotice}
          </div>
        )}

        {/* Live scanning progress banner if scan is still active */}
        {isScanning && <ScanProgressBanner job={job} repoName={repoName} />}

        {/* Header */}
        <header className="mt-6 flex flex-col gap-6 rounded-xl border border-line-bright bg-surface p-6 sm:flex-row sm:items-start sm:justify-between sm:p-8">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              {isScanning ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-sev-medium/50 bg-sev-medium/10 px-3 py-1 font-mono text-xs font-semibold text-sev-medium">
                  <Loader2 className="size-3.5 animate-spin" /> PARTIAL — SCAN STILL RUNNING
                </span>
              ) : state === "complete" ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1 font-mono text-xs font-semibold text-accent">
                  <ShieldCheck className="size-3.5" /> VERIFIED SCAN REPORT
                </span>
              ) : isPartial ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-sev-medium/50 bg-sev-medium/10 px-3 py-1 font-mono text-xs font-semibold text-sev-medium">
                  <AlertTriangle className="size-3.5" /> PARTIAL SCAN — INCOMPLETE COVERAGE
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-sev-critical/50 bg-sev-critical/10 px-3 py-1 font-mono text-xs font-semibold text-sev-critical">
                  <ShieldX className="size-3.5" /> {state === "cancelled" ? "SCAN CANCELLED — NOT SCANNED" : "SCAN FAILED — NOT SCANNED"}
                </span>
              )}
              <span className="font-mono text-xs text-muted">
                {job.completedAt
                  ? `${notScanned ? "Ended" : "Scanned"} ${new Date(job.completedAt).toLocaleString()}`
                  : "In progress"}
              </span>
            </div>
            <h1 className="mt-4 break-words font-display text-3xl font-bold tracking-tight sm:text-4xl">
              {repoName}
            </h1>
            <p className="mt-2 font-mono text-xs text-muted">
              branch {job.repository.defaultBranch ?? "main"} · commit {job.repository.commitSha?.slice(0, 7) ?? "—"} ·{" "}
              {notScanned ? "no files analyzed" : `${job.retrieval?.fileCount ?? 0} files analyzed`}
            </p>
          </div>

          <div className="shrink-0 sm:text-right">
            <div className={cn("font-display text-5xl font-bold leading-none", notScanned ? "text-muted" : "text-accent")}>
              {notScanned ? "—" : findings.length}
            </div>
            <div className="mt-1 font-mono text-[11px] uppercase tracking-wider text-muted">
              {isScanning
                ? "Findings so far"
                : notScanned
                  ? "Not scanned"
                  : isPartial
                    ? `Finding${findings.length === 1 ? "" : "s"} · partial coverage`
                    : `Verified Finding${findings.length === 1 ? "" : "s"}`}
            </div>
          </div>
        </header>

        {/* Failed or cancelled: say plainly that nothing was scanned */}
        {notScanned && (
          <div role="alert" className="mt-4 flex items-start gap-3 rounded-xl border border-sev-critical/40 bg-sev-critical/5 p-4 text-sm text-foreground">
            <ShieldX className="mt-0.5 size-5 shrink-0 text-sev-critical" aria-hidden />
            <div className="flex-1">
              <p className="font-semibold">
                {state === "cancelled" ? "This scan was cancelled before it finished." : "This repository was not scanned."}
              </p>
              {job.failure?.message && <p className="mt-1 text-sm">{job.failure.message}</p>}
              {job.failure?.category && <p className="mt-1 font-mono text-[11px] text-muted">Reason code: {job.failure.category}</p>}
              <p className="mt-2 text-xs text-muted">
                No security scanner completed, so the absence of findings says nothing about this repository. This is not a clean result.
              </p>
            </div>
            {job.retryable && !readOnly && !limitFailure && (
              <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => void retryScan(job.id).then(() => loadData())}>
                <RotateCw className="size-3.5" /> Retry Scan
              </Button>
            )}
          </div>
        )}

        {/* Warning banner if partial scan failure occurred */}
        {isPartial && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-sev-medium/40 bg-sev-medium/5 p-4 text-sm text-foreground">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-sev-medium" />
            <div className="flex-1">
              <p className="font-semibold">Partial Scan Warning</p>
              <p className="mt-0.5 text-xs text-muted">
                {incompleteScanners.length
                  ? `Did not complete: ${incompleteScanners.join(", ")}. `
                  : "One or more scanners did not complete. "}
                Results below come from the scanners that finished, so coverage is incomplete and an empty list is not a clean result.
              </p>
            </div>
            {job.retryable && (
              <Button
                variant="secondary"
                className="h-8 px-3 text-xs"
                onClick={() => void retryScan(job.id).then(() => loadData())}
              >
                <RotateCw className="size-3.5" /> Retry Scan
              </Button>
            )}
          </div>
        )}

        {/* Scanner Engine Metrics */}
        {job.scanners && (
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-line bg-surface p-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-semibold text-foreground">
                  <KeyRound className="size-4 text-accent" /> Gitleaks
                </span>
                <span className={cn("text-[11px] uppercase", job.scanners.gitleaks.status === "completed" ? "text-accent" : "text-sev-medium")}>
                  {scannerLabel(job.scanners.gitleaks.status)}
                </span>
              </div>
              <p className="mt-2 text-muted">Secret &amp; credential detection</p>
              <p className="mt-1 text-[11px] text-muted/70">
                Duration: {job.scanners.gitleaks.durationMs ? `${job.scanners.gitleaks.durationMs}ms` : "—"}
              </p>
            </div>

            <div className="rounded-xl border border-line bg-surface p-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-semibold text-foreground">
                  <Layers className="size-4 text-accent" /> Semgrep
                </span>
                <span className={cn("text-[11px] uppercase", job.scanners.semgrep.status === "completed" ? "text-accent" : "text-sev-medium")}>
                  {scannerLabel(job.scanners.semgrep.status)}
                </span>
              </div>
              <p className="mt-2 text-muted">Static code security rules</p>
              <p className="mt-1 text-[11px] text-muted/70">
                Duration: {job.scanners.semgrep.durationMs ? `${job.scanners.semgrep.durationMs}ms` : "—"}
              </p>
            </div>

            <div className="rounded-xl border border-line bg-surface p-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-semibold text-foreground">
                  <Package className="size-4 text-accent" /> OSV-Scanner
                </span>
                <span className={cn("text-[11px] uppercase", job.scanners.osvScanner.status === "completed" ? "text-accent" : "text-sev-medium")}>
                  {scannerLabel(job.scanners.osvScanner.status)}
                </span>
              </div>
              <p className="mt-2 text-muted">Dependency vulnerabilities</p>
              <p className="mt-1 text-[11px] text-muted/70">
                Duration: {job.scanners.osvScanner.durationMs ? `${job.scanners.osvScanner.durationMs}ms` : "—"}
              </p>
            </div>
          </div>
        )}

        {/* Coverage & Limitations Note (mid-scan, scanCoverage only carries progress heartbeats) */}
        {job.scanCoverage?.scannersRun && (
          <div className="mt-4 rounded-xl border border-line-bright bg-surface/60 p-4 font-mono text-xs text-muted">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span>
                Coverage: {job.scanCoverage.lockfilesFound?.length ? `Manifests analyzed (${job.scanCoverage.lockfilesFound.join(", ")})` : "No dependency lockfiles in snapshot"}
              </span>
              <span>Engines: Gitleaks · Semgrep · OSV-Scanner</span>
            </div>
            {job.scanCoverage.stageDurations && (
              <p className="mt-2 text-[11px] text-muted">{describeStageTimings(job)}</p>
            )}
            {!!job.scanCoverage.limitations?.length && (
              <p className="mt-2 text-[11px] text-sev-medium">
                Note: {job.scanCoverage.limitations.join(" · ")}
              </p>
            )}
          </div>
        )}

        {!notScanned && (
        <>
        {/* Severity Summary Tiles */}
        <ul className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-5" aria-label="Severity summary">
          {sevOrder.map((s) => {
            const active = sev === s;
            const style = severityStyles[s === "info" ? "low" : s];
            return (
              <li key={s}>
                <button
                  onClick={() => setSev(active ? "all" : s)}
                  aria-pressed={active}
                  className={cn(
                    "w-full rounded-xl border bg-surface p-4 text-left transition-all duration-300 hover:-translate-y-0.5 hover:bg-elevated",
                    active
                      ? "border-accent shadow-[0_0_24px_var(--accent-glow-subtle)]"
                      : "border-line hover:border-line-bright",
                  )}
                >
                  <span className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-muted">
                    <span className={cn("size-2 rounded-full", style.dot)} aria-hidden />
                    {s}
                  </span>
                  <span className={cn("mt-2 block font-display text-3xl font-bold", style.text)}>
                    {counts[s]}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>

        {/* Remediation Mode Switcher */}
        <div className="mt-8 rounded-xl border border-line-bright bg-surface p-5 sm:p-6 shadow-sm">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] uppercase tracking-wider text-accent font-semibold">
                  Remediation Workflow
                </span>
                <span className="rounded bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent font-bold">
                  Phase 6.5
                </span>
              </div>
              <h2 className="mt-1 font-display text-xl font-bold tracking-tight">
                {mode === "review" ? "Mode A — Review Only" : "Mode B — AI Auto-Fix"}
              </h2>
              <p className="mt-1 text-xs text-muted max-w-2xl leading-relaxed">
                {mode === "review"
                  ? "Read-only inspection. Browse findings, view AI root-cause analysis, and preview generated unified diffs without modifying repository files."
                  : "Interactive remediation. Select eligible findings, review exact diffs, provide explicit approval, verify changes in an isolated sandbox with automated security rescan, and open a dedicated PR."}
              </p>
            </div>

            <div className="flex shrink-0 items-center rounded-lg border border-line bg-surface-subtle p-1 font-mono text-xs">
              <button
                type="button"
                onClick={() => setMode("review")}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition-all cursor-pointer",
                  mode === "review"
                    ? "bg-accent text-background shadow font-bold"
                    : "text-muted hover:text-foreground"
                )}
              >
                <Eye className="size-3.5" /> Review Only
              </button>
              <button
                type="button"
                onClick={() => setMode("autofix")}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition-all cursor-pointer",
                  mode === "autofix"
                    ? "bg-accent text-background shadow font-bold"
                    : "text-muted hover:text-foreground"
                )}
              >
                <Sparkles className="size-3.5" /> AI Auto-Fix
              </button>
            </div>
          </div>

          {mode === "autofix" && (
            <div className="mt-4 pt-4 border-t border-line/60 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex flex-wrap items-center gap-3 text-muted">
                <span className="inline-flex items-center gap-1 text-accent font-medium">
                  <CheckCircle2 className="size-3.5" /> Safe to Auto-Fix
                </span>
                <span className="inline-flex items-center gap-1 text-sev-medium font-medium">
                  <AlertTriangle className="size-3.5" /> Potentially Breaking
                </span>
                <span className="inline-flex items-center gap-1 text-sev-critical font-medium">
                  <KeyRound className="size-3.5" /> Secret Rotation Required
                </span>
              </div>
              <div className="font-mono text-[11px] text-muted">
                Branch target: <code className="text-foreground">vibeshield/fixes/{jobId.slice(0, 8)}</code> (default branch protected)
              </div>
            </div>
          )}
        </div>

        {/* Findings Section */}
        <section aria-label="Findings" className="mt-8">
          <div className="flex flex-col gap-3 sm:flex-row">
            <label className="relative flex-1">
              <span className="sr-only">Search findings</span>
              <Search className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search title, file path, rule ID, or CVE"
                className="h-11 w-full rounded-full border border-line-bright bg-surface pl-11 pr-4 font-mono text-sm outline-none placeholder:text-muted/70 focus:border-accent"
              />
            </label>

            <label className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-muted">
              Category
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="h-11 rounded-full border border-line-bright bg-surface px-4 text-sm normal-case tracking-normal text-foreground"
              >
                <option value="all">All Categories</option>
                <option value="Secrets">Secrets</option>
                <option value="Code Analysis">Code Analysis</option>
                <option value="Dependencies">Dependencies</option>
              </select>
            </label>

            <label className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-muted">
              Severity
              <select
                value={sev}
                onChange={(e) => setSev(e.target.value as Severity | "all")}
                className="h-11 rounded-full border border-line-bright bg-surface px-4 text-sm normal-case tracking-normal text-foreground"
              >
                <option value="all">All severities</option>
                {sevOrder.map((s) => (
                  <option key={s} value={s}>
                    {s.toUpperCase()} ({counts[s]})
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
            <p className="font-mono text-xs uppercase tracking-wider text-muted" aria-live="polite">
              Showing {filtered.length} of {findings.length} findings
            </p>

            {mode === "autofix" && findings.length > 0 && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={selectAllEligible}
                  className="font-mono text-[11px] text-accent hover:underline cursor-pointer"
                >
                  Select All Eligible
                </button>
                <span className="text-line text-xs">|</span>
                <button
                  type="button"
                  onClick={() => setSelectedFindingIds(new Set())}
                  className="font-mono text-[11px] text-muted hover:underline cursor-pointer"
                >
                  Clear Selection
                </button>
              </div>
            )}
          </div>

          {/* Mode B Batch Selection Action Bar */}
          {mode === "autofix" && selectedFindingIds.size > 0 && (
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-accent/40 bg-accent/5 p-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-foreground">
                  {selectedFindingIds.size} findings selected
                </span>
                <span className="font-mono text-muted text-[11px]">
                  ({selectedFixCounts.eligible} eligible for automated fix
                  {selectedFixCounts.pending > 0 ? ` · ${selectedFixCounts.pending} checked when previewed` : ""})
                </span>
              </div>
              <Button
                size="sm"
                className="h-8 text-xs"
                onClick={() => {
                  const firstId = Array.from(selectedFindingIds)[0];
                  if (firstId) setSelectedId(firstId);
                }}
              >
                <Sparkles className="size-3.5" /> Review &amp; Auto-Fix Selected
              </Button>
            </div>
          )}

          {/* No findings: never presented as clean until every scanner completed */}
          {findings.length === 0 && state !== "complete" ? (
            <div className="mt-6 rounded-xl border border-dashed border-line-bright p-12 text-center">
              {isScanning ? (
                <Loader2 className="mx-auto size-8 animate-spin text-accent" aria-hidden />
              ) : (
                <AlertTriangle className="mx-auto size-8 text-sev-medium" aria-hidden />
              )}
              <h2 className="mt-3 font-display text-lg font-bold">
                {isScanning ? "No findings yet — scan still running" : "No findings from the scanners that completed"}
              </h2>
              <p className="mx-auto mt-2 max-w-lg text-sm text-muted">
                {isScanning
                  ? "Findings appear here as each scanner finishes. This is not a clean result until all three scanners complete."
                  : "At least one scanner did not complete, so coverage is incomplete and this is not a clean result."}
              </p>
            </div>
          ) : findings.length === 0 ? (
            <div className="mt-6 rounded-xl border border-accent/30 bg-accent/5 p-12 text-center">
              <ShieldCheck className="mx-auto size-12 text-accent" aria-hidden />
              <h2 className="mt-4 font-display text-2xl font-bold">No Security Findings Detected</h2>
              <p className="mx-auto mt-2 max-w-lg text-sm leading-relaxed text-muted">
                All 3 security scanners executed successfully on the repository snapshot and did not identify exposed secrets, static pattern violations, or known vulnerable dependencies in recognized manifests.
              </p>
              <div className="mt-6 inline-flex flex-wrap items-center justify-center gap-3 rounded-lg border border-line bg-surface p-3 font-mono text-xs text-muted">
                <span>✓ Gitleaks: 0 exposed secrets</span>
                <span>✓ Semgrep: 0 rule violations</span>
                <span>✓ OSV-Scanner: 0 known vulns</span>
              </div>
              <p className="mt-4 font-mono text-[11px] text-muted">
                Clean results indicate only that no findings were detected within the active rules and coverage.
              </p>
            </div>
          ) : filtered.length === 0 ? (
            <div className="mt-6 rounded-xl border border-dashed border-line-bright p-12 text-center">
              <SearchX className="mx-auto size-8 text-accent" aria-hidden />
              <h2 className="mt-3 font-display text-lg font-bold">No findings match current filters</h2>
              <Button
                variant="secondary"
                className="mt-4"
                onClick={() => {
                  setSev("all");
                  setCategory("all");
                  setQuery("");
                }}
              >
                Reset filters
              </Button>
            </div>
          ) : (
            <ul className="mt-4 divide-y divide-line overflow-hidden rounded-xl border border-line bg-surface">
              {filtered.map((f) => {
                const fix = findingFixStatus(f, decisionFor(f.fingerprint));
                const isSelectedForBatch = selectedFindingIds.has(f.id);

                return (
                  <li key={f.id}>
                    <div className="group flex w-full items-center justify-between gap-4 p-5 text-left transition-colors duration-300 hover:bg-elevated">
                      {mode === "autofix" && (
                        <button
                          type="button"
                          role="checkbox"
                          aria-checked={isSelectedForBatch}
                          onClick={(e) => toggleSelect(f.id, e)}
                          className={cn(
                            "flex size-5 shrink-0 items-center justify-center rounded border transition-colors cursor-pointer",
                            isSelectedForBatch
                              ? "border-accent bg-accent/20 text-accent"
                              : "border-line bg-surface hover:border-accent"
                          )}
                          aria-label={`Select finding ${f.title}`}
                        >
                          {isSelectedForBatch && <CheckCircle2 className="size-3.5 text-accent" />}
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={(e) => {
                          lastTrigger.current = e.currentTarget;
                          setSelectedId(f.id);
                        }}
                        className="flex flex-1 items-center justify-between gap-4 text-left cursor-pointer"
                      >
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={f.severity === "info" ? "low" : f.severity} />
                            <span className="font-mono text-[11px] uppercase tracking-wider text-muted">
                              {f.scanner} · {f.category}
                            </span>
                            <span className="font-mono text-[11px] text-muted">· {f.ruleId}</span>
                            {f.vulnerabilityId && (
                              <span className="rounded bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
                                {f.vulnerabilityId}
                              </span>
                            )}

                            {/* Fix status: the server's stored decision when there is one */}
                            <span title={fix.reason} data-fix-status={fix.kind}>
                              {fix.kind === "fix_ready" || fix.kind === "safe" ? (
                                <span className="inline-flex items-center gap-1 rounded bg-accent/15 px-2 py-0.5 font-mono text-[10px] text-accent font-semibold">
                                  <CheckCircle2 className="size-3" /> {fix.label}
                                </span>
                              ) : fix.kind === "potentially_breaking" ? (
                                <span className="inline-flex items-center gap-1 rounded bg-sev-medium/15 px-2 py-0.5 font-mono text-[10px] text-sev-medium font-semibold">
                                  <AlertTriangle className="size-3" /> {fix.label}
                                </span>
                              ) : fix.kind === "rotate_credential" ? (
                                <span className="inline-flex items-center gap-1 rounded bg-sev-critical/15 px-2 py-0.5 font-mono text-[10px] text-sev-critical font-semibold">
                                  <KeyRound className="size-3" /> {fix.label}
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 rounded bg-surface-subtle border border-line px-2 py-0.5 font-mono text-[10px] text-muted">
                                  {fix.label}
                                </span>
                              )}
                            </span>
                          </div>
                          <p className="mt-2 font-semibold text-foreground">{f.title}</p>
                          <p className="mt-0.5 break-all font-mono text-xs text-muted">
                            {f.filePath}
                            {f.startLine ? `:${f.startLine}` : ""}
                          </p>
                        </div>
                        <ChevronRight className="size-5 shrink-0 text-muted transition-transform duration-300 group-hover:translate-x-1 group-hover:text-accent" aria-hidden />
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          <div className="mt-8 rounded-lg border border-line/60 bg-surface/40 p-4 font-mono text-[11px] text-muted">
            <p>
              🔒 Security &amp; Privacy: Evidence is strictly redacted. Discovered secret values and credentials are never stored, logged, or sent to external services.
            </p>
          </div>
        </section>
        </>
        )}

        <RealFindingDrawer
          jobId={jobId}
          finding={selected}
          onClose={close}
          mode={mode}
          readOnly={readOnly}
          onRemediationUpdated={onRemediationUpdated}
        />
      </div>
    </div>
  );
}
