"use client";

import { AlertCircle, CheckCircle2, CircleDashed, Loader2, RotateCw, ServerOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { PublicScanJob } from "@/lib/scan-client";
import { cn } from "@/lib/utils";

const fmtBytes = (n: number | null) => (n == null ? "—" : n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

const steps = [
  { key: "queued", label: "Queued for processing" },
  { key: "retrieving", label: "Retrieving repository" },
  { key: "ready_for_scan", label: "Ready for security analysis" },
] as const;

export function ScanStatusPanel({
  job,
  stale,
  pollError,
  onRetry,
  onRecheck,
  onReset,
}: {
  job: PublicScanJob;
  stale: boolean;
  pollError: boolean;
  onRetry: () => void;
  onRecheck: () => void;
  onReset: () => void;
}) {
  const failed = !["queued", "retrieving", "ready_for_scan"].includes(job.status);
  const idx = steps.findIndex((s) => s.key === job.status);
  const repoName = `${job.repository.owner}/${job.repository.name}`;

  return (
    <div
      data-testid="scan-status"
      data-status={job.status}
      className={cn(
        "rounded-lg border p-4 text-sm [animation:drop-in_0.3s_var(--ease-luxury)]",
        failed ? "border-sev-critical/40 bg-sev-critical/5" : "border-accent/30 bg-accent/5",
      )}
    >
      <p className="font-mono text-xs text-muted">{repoName}</p>

      {!failed && (
        <ol className="mt-3 space-y-2" aria-label="Retrieval progress">
          {steps.map((s, i) => {
            const done = i < idx || job.status === "ready_for_scan";
            const active = i === idx && job.status !== "ready_for_scan";
            return (
              <li key={s.key} className={cn("flex items-center gap-2.5", done || active ? "text-foreground" : "text-muted/60")} aria-current={active ? "step" : undefined}>
                {done ? (
                  <CheckCircle2 className="size-4 text-accent" aria-hidden />
                ) : active ? (
                  <Loader2 className="size-4 animate-spin text-accent" aria-hidden />
                ) : (
                  <CircleDashed className="size-4" aria-hidden />
                )}
                <span className={cn("font-medium", job.status === "ready_for_scan" && s.key === "ready_for_scan" && "text-accent")}>{s.label}</span>
              </li>
            );
          })}
        </ol>
      )}

      {job.status === "queued" && job.workerOnline === false && (
        <p role="status" className="mt-3 flex items-start gap-2 text-sev-high">
          <ServerOff className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>The retrieval worker is not running right now. Your job is saved and will start when the worker comes back online.</span>
        </p>
      )}
      {stale && job.status !== "ready_for_scan" && !failed && (
        <p role="status" className="mt-3 text-muted">This is taking longer than expected. You can keep waiting or submit again.</p>
      )}
      {pollError && (
        <p role="alert" className="mt-3 flex flex-wrap items-center gap-3 text-sev-high">
          Lost contact with the server.
          <Button variant="secondary" onClick={onRecheck} className="h-8 px-3 text-xs">Check again</Button>
        </p>
      )}

      {job.status === "ready_for_scan" && (
        <div className="mt-3 space-y-1 border-t border-line pt-3">
          <p className="font-mono text-xs text-muted">
            branch {job.repository.defaultBranch ?? "—"} · commit {job.repository.commitSha?.slice(0, 7) ?? "—"} · {job.retrieval?.fileCount ?? "—"} files · {fmtBytes(job.retrieval?.unpackedBytes ?? null)}
          </p>
          <p className="text-muted">
            The repository source was retrieved and passed safety limits. <strong className="text-foreground">No security scan has been run yet</strong> — scanning is not connected in this phase.
          </p>
          <Button variant="ghost" onClick={onReset} className="mt-1 h-8 px-0 text-xs text-accent">Check another repository</Button>
        </div>
      )}

      {failed && (
        <div className="mt-2">
          <p role="alert" className="flex items-start gap-2 font-semibold text-sev-critical">
            <AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>Retrieval failed: {job.failure?.message ?? "Something went wrong."}</span>
          </p>
          <div className="mt-3 flex flex-wrap gap-3">
            {job.retryable && (
              <Button variant="secondary" onClick={onRetry} className="h-9 px-4 text-xs">
                <RotateCw className="size-3.5" aria-hidden /> Retry
              </Button>
            )}
            <Button variant="ghost" onClick={onReset} className="h-9 px-3 text-xs">Try another repository</Button>
          </div>
        </div>
      )}
    </div>
  );
}
