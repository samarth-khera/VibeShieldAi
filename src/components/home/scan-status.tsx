"use client";

import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  CircleDashed,
  KeyRound,
  Layers,
  Loader2,
  Package,
  RotateCw,
  ServerOff,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { PublicScanJob } from "@/lib/scan-client";
import { cn } from "@/lib/utils";

const fmtBytes = (n: number | null) =>
  n == null ? "—" : n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;

export function ScanStatusPanel({
  job,
  stale,
  pollError,
  onStartScan,
  onRetry,
  onRecheck,
  onReset,
}: {
  job: PublicScanJob;
  stale: boolean;
  pollError: boolean;
  onStartScan?: () => void;
  onRetry: () => void;
  onRecheck: () => void;
  onReset: () => void;
}) {
  const isFailed = ["failed", "invalid_repository", "download_failed", "rejected_by_limits", "cancelled"].includes(
    job.status,
  );
  const isScanning = job.status === "scanning";
  const isCompleted = job.status === "completed" || job.status === "completed_with_warnings";
  const isReadyForScan = job.status === "ready_for_scan";

  const repoName = `${job.repository.owner}/${job.repository.name}`;

  return (
    <div
      data-testid="scan-status"
      data-status={job.status}
      className={cn(
        "rounded-xl border p-5 text-sm transition-all [animation:drop-in_0.3s_var(--ease-luxury)]",
        isFailed
          ? "border-sev-critical/40 bg-sev-critical/5"
          : isCompleted
            ? "border-accent/40 bg-accent/5"
            : "border-line-bright bg-surface/90",
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-xs font-semibold text-muted">{repoName}</p>
        {job.repository.commitSha && (
          <span className="font-mono text-[11px] text-muted">
            commit {job.repository.commitSha.slice(0, 7)} · {job.repository.defaultBranch ?? "default"}
          </span>
        )}
      </div>

      {/* Pipeline Stepper */}
      {!isFailed && (
        <div className="mt-4 space-y-3">
          <div className="grid gap-2 sm:grid-cols-3">
            {/* Step 1: Retrieval */}
            <div
              className={cn(
                "flex items-center gap-2 rounded-lg border p-2.5 font-mono text-xs",
                ["retrieving", "queued"].includes(job.status)
                  ? "border-accent bg-accent/10 text-foreground"
                  : job.retrieval
                    ? "border-line bg-surface text-muted"
                    : "border-line/60 text-muted/50",
              )}
            >
              {job.status === "retrieving" ? (
                <Loader2 className="size-4 animate-spin text-accent" aria-hidden />
              ) : job.retrieval || isScanning || isCompleted ? (
                <CheckCircle2 className="size-4 text-accent" aria-hidden />
              ) : (
                <CircleDashed className="size-4" aria-hidden />
              )}
              <span className="font-medium">1. Repository snapshot</span>
            </div>

            {/* Step 2: Security Analysis */}
            <div
              className={cn(
                "flex items-center gap-2 rounded-lg border p-2.5 font-mono text-xs",
                isScanning
                  ? "border-accent bg-accent/10 text-foreground"
                  : isCompleted
                    ? "border-line bg-surface text-muted"
                    : "border-line/60 text-muted/50",
              )}
            >
              {isScanning ? (
                <Loader2 className="size-4 animate-spin text-accent" aria-hidden />
              ) : isCompleted ? (
                <CheckCircle2 className="size-4 text-accent" aria-hidden />
              ) : (
                <CircleDashed className="size-4" aria-hidden />
              )}
              <span className="font-medium">2. 3-Engine Analysis</span>
            </div>

            {/* Step 3: Report */}
            <div
              className={cn(
                "flex items-center gap-2 rounded-lg border p-2.5 font-mono text-xs",
                isCompleted
                  ? "border-accent bg-accent/10 text-accent font-semibold"
                  : "border-line/60 text-muted/50",
              )}
            >
              {isCompleted ? (
                <CheckCircle2 className="size-4 text-accent" aria-hidden />
              ) : (
                <CircleDashed className="size-4" aria-hidden />
              )}
              <span>3. Verified Report</span>
            </div>
          </div>

          {/* Detailed scanner progress during scanning */}
          {(isScanning || isCompleted) && job.scanners && (
            <div className="mt-3 rounded-lg border border-line bg-surface/60 p-3">
              <p className="font-mono text-[11px] uppercase tracking-wider text-muted">Active Security Engines</p>
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                {/* Gitleaks */}
                <div className="flex items-center justify-between rounded border border-line/80 px-2.5 py-1.5 font-mono text-xs">
                  <span className="flex items-center gap-1.5 text-muted">
                    <KeyRound className="size-3.5 text-accent" aria-hidden /> Gitleaks
                  </span>
                  {job.scanners.gitleaks.status === "completed" ? (
                    <span className="text-accent">✓ done</span>
                  ) : job.scanners.gitleaks.status === "failed" ? (
                    <span className="text-sev-critical">⚠ error</span>
                  ) : (
                    <span className="flex items-center gap-1 text-muted">
                      <Loader2 className="size-3 animate-spin text-accent" /> scanning
                    </span>
                  )}
                </div>

                {/* Semgrep */}
                <div className="flex items-center justify-between rounded border border-line/80 px-2.5 py-1.5 font-mono text-xs">
                  <span className="flex items-center gap-1.5 text-muted">
                    <Layers className="size-3.5 text-accent" aria-hidden /> Semgrep
                  </span>
                  {job.scanners.semgrep.status === "completed" ? (
                    <span className="text-accent">✓ done</span>
                  ) : job.scanners.semgrep.status === "failed" ? (
                    <span className="text-sev-critical">⚠ error</span>
                  ) : (
                    <span className="flex items-center gap-1 text-muted">
                      <Loader2 className="size-3 animate-spin text-accent" /> scanning
                    </span>
                  )}
                </div>

                {/* OSV-Scanner */}
                <div className="flex items-center justify-between rounded border border-line/80 px-2.5 py-1.5 font-mono text-xs">
                  <span className="flex items-center gap-1.5 text-muted">
                    <Package className="size-3.5 text-accent" aria-hidden /> OSV-Scanner
                  </span>
                  {job.scanners.osvScanner.status === "completed" ? (
                    <span className="text-accent">✓ done</span>
                  ) : job.scanners.osvScanner.status === "failed" ? (
                    <span className="text-sev-critical">⚠ error</span>
                  ) : (
                    <span className="flex items-center gap-1 text-muted">
                      <Loader2 className="size-3 animate-spin text-accent" /> scanning
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Ready for scan: Explicit action */}
      {isReadyForScan && (
        <div className="mt-4 space-y-3 rounded-lg border border-line bg-surface p-4">
          <p className="font-mono text-xs text-muted">
            Snapshot ready: {job.retrieval?.fileCount ?? 0} files · {fmtBytes(job.retrieval?.unpackedBytes ?? null)}
          </p>
          <p className="text-sm text-foreground">
            Repository retrieved and verified. Ready to execute isolated security scanning.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            {onStartScan && (
              <Button onClick={onStartScan} className="h-8 px-3.5 text-xs">
                <Shield className="size-3.5" aria-hidden /> Run Security Scan Now
              </Button>
            )}
            <Button variant="ghost" onClick={onReset} className="h-8 text-xs text-muted">
              Check another repository
            </Button>
          </div>
        </div>
      )}

      {/* Completed results */}
      {isCompleted && job.summary && (
        <div className="mt-4 space-y-3 rounded-lg border border-line bg-surface p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              {job.summary.total > 0 ? (
                <ShieldAlert className="size-5 text-sev-high" aria-hidden />
              ) : (
                <ShieldCheck className="size-5 text-accent" aria-hidden />
              )}
              <h2 className="font-display font-semibold text-foreground text-sm">
                {job.status === "completed_with_warnings"
                  ? "Scan Completed (With Scanner Warnings)"
                  : job.summary.total > 0
                    ? `Scan Completed — ${job.summary.total} Finding${job.summary.total === 1 ? "" : "s"} Detected`
                    : "Scan Completed — No Findings Detected"}
              </h2>
            </div>
            <Button href={`/report/${job.id}`} className="h-8 px-3.5 text-xs">
              View Security Report <ArrowRight className="size-3.5" aria-hidden />
            </Button>
          </div>

          <div className="grid grid-cols-4 gap-2 pt-1">
            <div className="rounded border border-line p-2 text-center">
              <span className="font-mono text-[10px] uppercase text-muted block">Critical</span>
              <span className="font-display text-lg font-bold text-sev-critical">{job.summary.critical}</span>
            </div>
            <div className="rounded border border-line p-2 text-center">
              <span className="font-mono text-[10px] uppercase text-muted block">High</span>
              <span className="font-display text-lg font-bold text-sev-high">{job.summary.high}</span>
            </div>
            <div className="rounded border border-line p-2 text-center">
              <span className="font-mono text-[10px] uppercase text-muted block">Medium</span>
              <span className="font-display text-lg font-bold text-sev-medium">{job.summary.medium}</span>
            </div>
            <div className="rounded border border-line p-2 text-center">
              <span className="font-mono text-[10px] uppercase text-muted block">Low</span>
              <span className="font-display text-lg font-bold text-sev-low">{job.summary.low}</span>
            </div>
          </div>

          <p className="font-mono text-[11px] text-muted">
            {job.summary.total === 0
              ? "All enabled security rules and dependency databases checked without hits. Clean results indicate only that no findings were detected within active coverage."
              : "Findings have been normalized with redacted evidence. Never commit raw secrets or vulnerable dependencies."}
          </p>

          <div className="pt-1">
            <Button variant="ghost" onClick={onReset} className="h-7 px-0 text-xs text-accent">
              Scan another repository
            </Button>
          </div>
        </div>
      )}

      {/* Worker Offline */}
      {job.status === "queued" && job.workerOnline === false && (
        <p role="status" className="mt-3 flex items-start gap-2 text-sev-high text-xs">
          <ServerOff className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>The security worker is not connected right now. Your job is queued and will process once available.</span>
        </p>
      )}

      {/* Stale Warning */}
      {stale && !isCompleted && !isFailed && (
        <p role="status" className="mt-3 text-muted text-xs">
          Scanning is taking longer than expected. You can keep waiting or submit again.
        </p>
      )}

      {/* Network Poll Error */}
      {pollError && (
        <p role="alert" className="mt-3 flex flex-wrap items-center gap-3 text-sev-high text-xs">
          Lost contact with the server.
          <Button variant="secondary" onClick={onRecheck} className="h-8 px-3 text-xs">
            Check again
          </Button>
        </p>
      )}

      {/* Failed State */}
      {isFailed && (
        <div className="mt-2">
          <p role="alert" className="flex items-start gap-2 font-semibold text-sev-critical">
            <AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>Scan failed: {job.failure?.message ?? "Something went wrong."}</span>
          </p>
          <div className="mt-3 flex flex-wrap gap-3">
            {job.retryable && (
              <Button variant="secondary" onClick={onRetry} className="h-9 px-4 text-xs">
                <RotateCw className="size-3.5" aria-hidden /> Retry Scan
              </Button>
            )}
            <Button variant="ghost" onClick={onReset} className="h-9 px-3 text-xs">
              Try another repository
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
