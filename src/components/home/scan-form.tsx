"use client";

import { useId, useState } from "react";
import { AlertCircle, ArrowRight, FileSearch, GitBranch, Info, Loader2, Lock } from "lucide-react";
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
      setState(
        r.ok
          ? { status: "not-connected", repo: `${r.owner}/${r.repo}` }
          : { status: "error", message: r.error },
      );
    }, 450);
  }

  const hasError = state.status === "error";

  return (
    <div id="scan" className="w-full max-w-xl">
      <form onSubmit={onSubmit} noValidate aria-describedby={`${id}-hint`}>
        <label htmlFor={id} className="sr-only">
          GitHub repository URL
        </label>
        <div
          className={cn(
            "flex flex-col gap-2 rounded-3xl border bg-white p-2 shadow-[0_18px_40px_-20px_rgba(80,70,200,0.4)] transition-colors sm:flex-row sm:items-center sm:rounded-full",
            hasError ? "border-[#d6336c]" : "border-border focus-within:border-brand",
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
              className="h-11 w-full bg-transparent text-sm outline-none placeholder:text-[#9a9db4]"
            />
          </div>
          <Button type="submit" size="lg" disabled={state.status === "validating"}>
            {state.status === "validating" ? (
              <>
                <Loader2 className="size-4 animate-spin" aria-hidden /> Checking…
              </>
            ) : (
              <>
                Scan repository <ArrowRight className="size-4" aria-hidden />
              </>
            )}
          </Button>
        </div>
      </form>

      <div aria-live="polite" className="mt-3 min-h-6">
        {state.status === "error" && (
          <p id={`${id}-error`} role="alert" className="flex items-center gap-2 text-sm font-medium text-[#b4235a]">
            <AlertCircle className="size-4" aria-hidden /> {state.message}
          </p>
        )}
        {state.status === "not-connected" && (
          <div className="rounded-2xl border border-brand/25 bg-brand-soft p-4 text-sm [animation:drop-in_0.25s_ease-out]">
            <p className="flex items-start gap-2 font-semibold text-brand-ink">
              <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span>
                <span className="font-mono">{state.repo}</span> looks like a valid URL — but live scanning isn&apos;t connected yet.
              </span>
            </p>
            <p className="mt-1 pl-6 text-muted">
              No repository was fetched or scanned. This milestone is frontend only. See what a report will look like:
            </p>
            <Button href="/demo-report" variant="secondary" className="mt-3 ml-6">
              <FileSearch className="size-4" aria-hidden /> View demo report
            </Button>
          </div>
        )}
      </div>

      <p id={`${id}-hint`} className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span className="inline-flex items-center gap-1.5">
          <Lock className="size-3.5" aria-hidden /> Public repo URLs only for now
        </span>
        <span>Nothing is uploaded in this preview</span>
        <Button href="/demo-report" variant="ghost" className="h-auto !px-2 !py-1 text-xs text-brand-ink">
          or view a demo report →
        </Button>
      </p>
    </div>
  );
}
