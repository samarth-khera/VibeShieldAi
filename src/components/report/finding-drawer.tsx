"use client";

import { useEffect, useRef } from "react";
import { Copy, Check, FileCode2, ShieldAlert, Wrench, X } from "lucide-react";
import { useState } from "react";
import { SeverityBadge } from "@/components/ui/badges";
import type { Finding } from "@/lib/demo-data";

export function FindingDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!finding) return;
    const prev = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      prev?.focus();
    };
  }, [finding, onClose]);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div
        className="absolute inset-0 bg-[#1f2230]/35 [animation:fade-in_0.2s_ease-out]"
        onClick={onClose}
        aria-hidden
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col overflow-y-auto bg-white shadow-2xl [animation:slide-in-right_0.3s_cubic-bezier(0.22,1,0.36,1)]"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-border bg-white/95 px-6 py-5 backdrop-blur">
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-xs text-muted">{finding.id} · Demo</span>
            </div>
            <h2 id="drawer-title" className="mt-2 font-display text-xl font-bold">
              {finding.title}
            </h2>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            aria-label="Close details"
            className="grid size-9 shrink-0 place-items-center rounded-full border border-border hover:bg-brand-soft"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-7 px-6 py-6">
          <section>
            <p className="flex items-center gap-2 font-mono text-sm text-brand-ink">
              <FileCode2 className="size-4" aria-hidden /> {finding.file}:{finding.line}
            </p>
            <p className="mt-2 text-sm text-muted">{finding.summary}</p>
          </section>

          <section>
            <h3 className="flex items-center gap-2 font-display font-bold">
              <ShieldAlert className="size-4 text-[#d6336c]" aria-hidden /> Impact
            </h3>
            <p className="mt-2 text-sm text-muted">{finding.impact}</p>
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
                className="inline-flex items-center gap-1.5 rounded-full border border-border px-3 py-1 text-xs font-medium hover:bg-brand-soft"
              >
                {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                {copied ? "Copied" : "Copy location"}
              </button>
            </div>
            {finding.evidence.map((block, i) => (
              <pre
                key={i}
                className="mt-3 overflow-x-auto rounded-2xl border border-border bg-[#faf9ff] p-4 font-mono text-xs leading-6"
              >
                {block.lines.map((line, j) => {
                  const n = block.startLine + j;
                  const hot = n === block.highlight;
                  return (
                    <div key={j} className={hot ? "-mx-4 bg-[#fde8f0] px-4" : ""}>
                      <span className="mr-4 inline-block w-6 select-none text-right text-muted">{n}</span>
                      {line || " "}
                    </div>
                  );
                })}
              </pre>
            ))}
            <p className="mt-2 text-xs text-muted">Sensitive values are masked. Evidence is illustrative demo data.</p>
          </section>

          <section>
            <h3 className="flex items-center gap-2 font-display font-bold">
              <Wrench className="size-4 text-brand" aria-hidden /> Suggested remediation
            </h3>
            <ol className="mt-3 space-y-2">
              {finding.remediation.map((r, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="grid size-6 shrink-0 place-items-center rounded-full bg-brand-soft text-xs font-bold text-brand-ink">
                    {i + 1}
                  </span>
                  <span className="text-muted">{r}</span>
                </li>
              ))}
            </ol>
            {finding.reference && <p className="mt-4 text-xs text-muted">Reference: {finding.reference}</p>}
          </section>
        </div>
      </aside>
    </div>
  );
}
