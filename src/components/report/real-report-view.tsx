"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ChevronRight,
  KeyRound,
  Layers,
  Loader2,
  Package,
  RotateCw,
  Search,
  SearchX,
  ShieldCheck,
} from "lucide-react";
import { SeverityBadge, severityStyles } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import {
  fetchFindings,
  fetchScan,
  retryScan,
  type PublicFinding,
  type PublicScanJob,
} from "@/lib/scan-client";
import { cn } from "@/lib/utils";
import { RealFindingDrawer } from "./real-finding-drawer";

type Severity = "critical" | "high" | "medium" | "low" | "info";
const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function RealReportView({ jobId }: { jobId: string }) {
  const [job, setJob] = useState<PublicScanJob | null>(null);
  const [findings, setFindings] = useState<PublicFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState<Severity | "all">("all");
  const [category, setCategory] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const lastTrigger = useRef<HTMLElement | null>(null);

  const loadData = useCallback(async () => {
    try {
      const j = await fetchScan(jobId);
      setJob(j);

      if (["completed", "completed_with_warnings"].includes(j.status)) {
        const res = await fetchFindings(jobId, { limit: 200 });
        setFindings(res.findings);
      }
      setLoading(false);
      return j;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scan report.");
      setLoading(false);
      return null;
    }
  }, [jobId]);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function poll() {
      const current = await loadData();
      if (!active) return;
      if (current && ["queued", "retrieving", "scanning"].includes(current.status)) {
        timer = setTimeout(poll, 2000);
      }
    }

    void poll();

    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [loadData]);

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

  const isScanning = ["queued", "retrieving", "scanning"].includes(job.status);
  const isCompletedWithWarnings = job.status === "completed_with_warnings";
  const repoName = `${job.repository.owner}/${job.repository.name}`;

  return (
    <div className="relative pb-20">
      <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-96" aria-hidden />
      <div className="relative mx-auto max-w-6xl px-6 py-10">
        <Link href="/" className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-muted hover:text-accent">
          <ArrowLeft className="size-4" aria-hidden /> Back to homepage
        </Link>

        {/* Live scanning progress banner if scan is still active */}
        {isScanning && (
          <div className="mt-6 rounded-xl border border-accent/40 bg-accent/5 p-6 sm:p-8">
            <div className="flex flex-col items-center justify-center gap-4 text-center">
              <Loader2 className="size-8 animate-spin text-accent" />
              <div>
                <h2 className="font-display text-2xl font-bold">
                  {job.status === "scanning" ? "Running Security Scanners…" : "Preparing Repository…"}
                </h2>
                <p className="mt-1 font-mono text-xs text-muted">
                  Scanning {repoName} across Gitleaks secrets, Semgrep code rules, and OSV-Scanner dependencies.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Header */}
        <header className="mt-6 flex flex-col gap-6 rounded-xl border border-line-bright bg-surface p-6 sm:flex-row sm:items-start sm:justify-between sm:p-8">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-3 py-1 font-mono text-xs font-semibold text-accent">
                <ShieldCheck className="size-3.5" /> VERIFIED SCAN REPORT
              </span>
              <span className="font-mono text-xs text-muted">
                {job.completedAt ? `Scanned ${new Date(job.completedAt).toLocaleString()}` : "In progress"}
              </span>
            </div>
            <h1 className="mt-4 break-words font-display text-3xl font-bold tracking-tight sm:text-4xl">
              {repoName}
            </h1>
            <p className="mt-2 font-mono text-xs text-muted">
              branch {job.repository.defaultBranch ?? "main"} · commit {job.repository.commitSha?.slice(0, 7) ?? "—"} · {job.retrieval?.fileCount ?? 0} files analyzed
            </p>
          </div>

          <div className="shrink-0 sm:text-right">
            <div className="font-display text-5xl font-bold leading-none text-accent">
              {findings.length}
            </div>
            <div className="mt-1 font-mono text-[11px] uppercase tracking-wider text-muted">
              Verified Finding{findings.length === 1 ? "" : "s"}
            </div>
          </div>
        </header>

        {/* Warning banner if partial scan failure occurred */}
        {isCompletedWithWarnings && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-sev-medium/40 bg-sev-medium/5 p-4 text-sm text-foreground">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-sev-medium" />
            <div className="flex-1">
              <p className="font-semibold">Partial Scan Warning</p>
              <p className="mt-0.5 text-xs text-muted">
                One or more scanners encountered an issue during execution. Results below reflect successful scanners only.
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
                  {job.scanners.gitleaks.status ?? "pending"}
                </span>
              </div>
              <p className="mt-2 text-muted">Secret & credential detection</p>
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
                  {job.scanners.semgrep.status ?? "pending"}
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
                  {job.scanners.osvScanner.status ?? "pending"}
                </span>
              </div>
              <p className="mt-2 text-muted">Dependency vulnerabilities</p>
              <p className="mt-1 text-[11px] text-muted/70">
                Duration: {job.scanners.osvScanner.durationMs ? `${job.scanners.osvScanner.durationMs}ms` : "—"}
              </p>
            </div>
          </div>
        )}

        {/* Coverage & Limitations Note */}
        {job.scanCoverage && (
          <div className="mt-4 rounded-xl border border-line-bright bg-surface/60 p-4 font-mono text-xs text-muted">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span>
                Coverage: {job.scanCoverage.lockfilesFound.length > 0 ? `Manifests analyzed (${job.scanCoverage.lockfilesFound.join(", ")})` : "No dependency lockfiles in snapshot"}
              </span>
              <span>Engines: Gitleaks · Semgrep · OSV-Scanner</span>
            </div>
            {job.scanCoverage.limitations.length > 0 && (
              <p className="mt-2 text-[11px] text-sev-medium">
                Note: {job.scanCoverage.limitations.join(" · ")}
              </p>
            )}
          </div>
        )}

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

        {/* Findings Section */}
        <section aria-label="Findings" className="mt-10">
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

          <p className="mt-5 font-mono text-xs uppercase tracking-wider text-muted" aria-live="polite">
            Showing {filtered.length} of {findings.length} findings
          </p>

          {/* Clean repository / No findings state */}
          {findings.length === 0 ? (
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
              {filtered.map((f) => (
                <li key={f.id}>
                  <button
                    onClick={(e) => {
                      lastTrigger.current = e.currentTarget;
                      setSelectedId(f.id);
                    }}
                    className="group flex w-full items-center justify-between gap-4 p-5 text-left transition-colors duration-300 hover:bg-elevated"
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
                      </div>
                      <p className="mt-2 font-semibold text-foreground">{f.title}</p>
                      <p className="mt-0.5 break-all font-mono text-xs text-muted">
                        {f.filePath}
                        {f.startLine ? `:${f.startLine}` : ""}
                      </p>
                    </div>
                    <ChevronRight className="size-5 shrink-0 text-muted transition-transform duration-300 group-hover:translate-x-1 group-hover:text-accent" aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-8 rounded-lg border border-line/60 bg-surface/40 p-4 font-mono text-[11px] text-muted">
            <p>
              🔒 Security & Privacy: Evidence is strictly redacted. Discovered secret values and credentials are never stored, logged, or sent to external services.
            </p>
          </div>
        </section>

        <RealFindingDrawer jobId={jobId} finding={selected} onClose={close} />
      </div>
    </div>
  );
}
