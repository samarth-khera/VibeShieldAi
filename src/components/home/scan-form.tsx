"use client";

import { useId, useState } from "react";
import { AlertCircle, ArrowRight, FileSearch, GitBranch, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, parseGithubUrl } from "@/lib/utils";
import { ScanStatusPanel } from "./scan-status";
import { useScanJob } from "./use-scan-job";
import { TurnstileWidget } from "./turnstile-widget";

export function ScanForm() {
  const id = useId();
  const [value, setValue] = useState("");
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
  const { flow, submit, startScanNow, retry, recheck, reset, setClientError } = useScanJob();

  const busy =
    flow.phase === "validating" ||
    (flow.phase === "job" && ["queued", "retrieving", "scanning"].includes(flow.job.status));
  const hasError = flow.phase === "error";

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    const r = parseGithubUrl(value); // instant client-side feedback; the server re-validates
    if (!r.ok) return setClientError(r.error);
    if (siteKey && !turnstileToken) {
      return setClientError("Please complete the security verification challenge before scanning.");
    }
    void submit(value.trim(), turnstileToken || undefined);
  }

  return (
    <div id="scan" className="w-full max-w-xl">
      <form onSubmit={onSubmit} noValidate>
        <label htmlFor={id} className="sr-only">GitHub repository URL</label>
        <div
          className={cn(
            "flex flex-col gap-2 rounded-xl border bg-surface p-2 transition-colors sm:flex-row sm:items-center sm:rounded-full",
            hasError ? "border-sev-critical" : "border-line-bright focus-within:border-accent",
          )}
        >
          <div className="flex flex-1 items-center gap-2 px-3">
            <GitBranch className="size-5 shrink-0 text-muted" aria-hidden />
            <input
              id={id}
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="https://github.com/owner/repository"
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                if (flow.phase === "error") reset();
              }}
              aria-invalid={hasError}
              aria-describedby={hasError ? `${id}-error` : `${id}-hint`}
              className="h-11 w-full bg-transparent font-mono text-sm outline-none placeholder:text-muted/70"
            />
          </div>
          <Button type="submit" size="lg" disabled={busy}>
            {flow.phase === "validating" ? (
              <><Loader2 className="size-4 animate-spin" aria-hidden /> Validating repository…</>
            ) : busy ? (
              <><Loader2 className="size-4 animate-spin" aria-hidden /> Scanning…</>
            ) : (
              <>Scan Repository <ArrowRight className="size-4" aria-hidden /></>
            )}
          </Button>
        </div>
        {siteKey && (
          <TurnstileWidget
            siteKey={siteKey}
            onVerify={(token) => setTurnstileToken(token)}
            onExpire={() => setTurnstileToken(null)}
          />
        )}
      </form>

      <div aria-live="polite" className="mt-3 min-h-6">
        {flow.phase === "error" && (
          <p id={`${id}-error`} role="alert" className="flex items-center gap-2 text-sm font-medium text-sev-critical">
            <AlertCircle className="size-4 shrink-0" aria-hidden /> {flow.message}
          </p>
        )}

        {flow.phase === "job" && (
          <ScanStatusPanel
            job={flow.job}
            stale={flow.stale}
            pollError={flow.pollError}
            onStartScan={() => void startScanNow(flow.job.id)}
            onRetry={() => void retry(flow.job.id)}
            onRecheck={() => recheck(flow.job.id)}
            onReset={reset}
          />
        )}
      </div>

      <div id={`${id}-hint`} className="mt-1 flex flex-wrap items-center gap-x-5 gap-y-3">
        <Button href="/demo-report" variant="secondary">
          <FileSearch className="size-4" aria-hidden /> View Sample Report (Demo)
        </Button>
        <p className="font-mono text-xs text-muted">
          Real security analysis: Gitleaks secrets · Semgrep rules · OSV-Scanner lockfiles
        </p>
      </div>
    </div>
  );
}
