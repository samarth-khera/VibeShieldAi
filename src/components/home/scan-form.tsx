"use client";

import { useId, useState } from "react";
import { AlertCircle, ArrowRight, FileSearch, GitBranch, Info, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, parseGithubUrl } from "@/lib/utils";

type State =
  | { status: "idle" }
  | { status: "validating" }
  | { status: "error"; message: string }
  | { status: "not-connected"; repo: string };

export function ScanForm() {
  const id = useId();
  const [value, setValue] = useState("");
  const [state, setState] = useState<State>({ status: "idle" });

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setState({ status: "validating" });
    window.setTimeout(() => {
      const r = parseGithubUrl(value);
      setState(r.ok ? { status: "not-connected", repo: `${r.owner}/${r.repo}` } : { status: "error", message: r.error });
    }, 400);
  }

  const hasError = state.status === "error";

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
                if (state.status !== "idle") setState({ status: "idle" });
              }}
              aria-invalid={hasError}
              aria-describedby={hasError ? `${id}-error` : `${id}-hint`}
              className="h-11 w-full bg-transparent font-mono text-sm outline-none placeholder:text-muted/70"
            />
          </div>
          <Button type="submit" size="lg" disabled={state.status === "validating"}>
            {state.status === "validating" ? (
              <><Loader2 className="size-4 animate-spin" aria-hidden /> Checking…</>
            ) : (
              <>Scan Repository <ArrowRight className="size-4" aria-hidden /></>
            )}
          </Button>
        </div>
      </form>

      <div aria-live="polite" className="mt-3 min-h-6">
        {state.status === "error" && (
          <p id={`${id}-error`} role="alert" className="flex items-center gap-2 text-sm font-medium text-sev-critical">
            <AlertCircle className="size-4 shrink-0" aria-hidden /> {state.message}
          </p>
        )}
        {state.status === "not-connected" && (
          <div className="rounded-lg border border-accent/30 bg-accent/5 p-4 text-sm [animation:drop-in_0.3s_var(--ease-luxury)]">
            <p className="flex items-start gap-2 font-semibold text-accent">
              <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span><span className="font-mono">{state.repo}</span> is a valid URL, but live scanning is not connected yet.</span>
            </p>
            <p className="mt-1 pl-6 text-muted">No repository was fetched or scanned. Explore the sample report instead.</p>
          </div>
        )}
      </div>

      <div id={`${id}-hint`} className="mt-1 flex flex-wrap items-center gap-x-5 gap-y-3">
        <Button href="/demo-report" variant="secondary">
          <FileSearch className="size-4" aria-hidden /> View Sample Report
        </Button>
        <p className="font-mono text-xs text-muted">Live scanning is not connected yet · public repos only</p>
      </div>
    </div>
  );
}
