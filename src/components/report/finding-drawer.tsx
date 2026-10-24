"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy, FileCode2, ShieldAlert, Wrench, X } from "lucide-react";
import { SeverityBadge } from "@/components/ui/badges";
import type { Finding } from "@/lib/demo-data";

export function FindingDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!finding) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") return onClose();
      if (e.key !== "Tab" || !panelRef.current) return;
      const f = panelRef.current.querySelectorAll<HTMLElement>("button, [href], [tabindex]:not([tabindex='-1'])");
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
    };
  }, [finding, onClose]);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/70 [animation:fade-in_0.25s_ease-out]" onClick={onClose} aria-hidden />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-line-bright bg-surface [animation:slide-in-right_0.4s_var(--ease-luxury)]"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-surface/95 px-6 py-5 backdrop-blur">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-[11px] uppercase tracking-wider text-muted">{finding.rule} · demo</span>
            </div>
            <h2 id="drawer-title" className="mt-3 font-display text-xl font-bold">{finding.title}</h2>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            aria-label="Close details"
            className="grid size-9 shrink-0 place-items-center rounded-full border border-line-bright transition-colors hover:border-accent hover:text-accent"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-8 px-6 py-6">
          <section>
            <p className="flex items-center gap-2 break-all font-mono text-sm text-accent">
              <FileCode2 className="size-4 shrink-0" aria-hidden /> {finding.file}:{finding.line}
            </p>
            <p className="mt-3 text-sm leading-relaxed text-muted">{finding.summary}</p>
          </section>

          <section>
            <h3 className="flex items-center gap-2 font-display font-bold">
              <ShieldAlert className="size-4 text-sev-critical" aria-hidden /> Potential impact
            </h3>
            <p className="mt-2 text-sm leading-relaxed text-muted">{finding.impact}</p>
          </section>

          <section>
            <div className="flex items-center justify-between">
              <h3 className="font-display font-bold">Evidence</h3>
              <button
                onClick={() => {
                  navigator.clipboard?.writeText(`${finding.file}:${finding.line}`);
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1500);
                }}
                className="inline-flex items-center gap-1.5 rounded-full border border-line-bright px-3 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors hover:border-accent hover:text-accent"
              >
                {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                {copied ? "Copied" : "Copy location"}
              </button>
            </div>
            {finding.evidence.map((block, i) => (
              <pre key={i} tabIndex={0} className="mt-3 overflow-x-auto rounded-lg border border-line bg-background p-4 font-mono text-xs leading-6">
                {block.lines.map((line, j) => {
                  const n = block.startLine + j;
                  const hot = n === block.highlight;
                  return (
                    <div key={j} className={hot ? "-mx-4 border-l-2 border-accent bg-accent/10 px-4" : "px-0"}>
                      <span className="mr-4 inline-block w-6 select-none text-right text-muted">{n}</span>
                      {line || " "}
                    </div>
                  );
                })}
              </pre>
            ))}
            <p className="mt-2 text-xs text-muted">Sensitive values are masked. Illustrative demo evidence only.</p>
          </section>

          <section>
            <h3 className="flex items-center gap-2 font-display font-bold">
              <Wrench className="size-4 text-accent" aria-hidden /> Recommended remediation
            </h3>
            <ol className="mt-3 space-y-3">
              {finding.remediation.map((r, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="grid size-6 shrink-0 place-items-center rounded-full border border-accent/40 font-mono text-xs text-accent">{i + 1}</span>
                  <span className="text-muted">{r}</span>
                </li>
              ))}
            </ol>
            {finding.reference && <p className="mt-5 font-mono text-[11px] uppercase tracking-wider text-muted">Ref: {finding.reference}</p>}
          </section>
        </div>
      </aside>
    </div>
  );
}
