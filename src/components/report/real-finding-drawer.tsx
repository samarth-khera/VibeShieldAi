"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy, ExternalLink, FileCode2, Wrench, X } from "lucide-react";
import { SeverityBadge } from "@/components/ui/badges";
import type { PublicFinding } from "@/lib/scan-client";

export function RealFindingDrawer({
  finding,
  onClose,
}: {
  finding: PublicFinding | null;
  onClose: () => void;
}) {
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
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
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

  const loc = finding.startLine ? `${finding.filePath}:${finding.startLine}` : finding.filePath;

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/70 [animation:fade-in_0.25s_ease-out]" onClick={onClose} aria-hidden />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="real-drawer-title"
        className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-line-bright bg-surface [animation:slide-in-right_0.4s_var(--ease-luxury)]"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-surface/95 px-6 py-5 backdrop-blur">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity === "info" ? "low" : finding.severity} />
              <span className="font-mono text-[11px] uppercase tracking-wider text-muted">
                {finding.scanner} · {finding.category}
              </span>
              {finding.vulnerabilityId && (
                <span className="font-mono text-[11px] font-semibold text-accent">
                  {finding.vulnerabilityId}
                </span>
              )}
            </div>
            <h2 id="real-drawer-title" className="mt-3 font-display text-xl font-bold">
              {finding.title}
            </h2>
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

        <div className="space-y-7 px-6 py-6">
          <section>
            <div className="flex items-center justify-between">
              <p className="flex items-center gap-2 break-all font-mono text-sm text-accent">
                <FileCode2 className="size-4 shrink-0" aria-hidden /> {loc}
              </p>
              <button
                onClick={() => {
                  navigator.clipboard?.writeText(loc);
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1500);
                }}
                className="inline-flex items-center gap-1.5 rounded-full border border-line-bright px-3 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors hover:border-accent hover:text-accent"
              >
                {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="mt-3 text-sm leading-relaxed text-muted whitespace-pre-line">{finding.description}</p>
          </section>

          {/* Rule Details */}
          <section className="rounded-lg border border-line bg-background/50 p-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-muted block text-[10px] uppercase">Scanner</span>
                <span className="font-semibold text-foreground">{finding.scanner}</span>
              </div>
              <div>
                <span className="text-muted block text-[10px] uppercase">Rule Identifier</span>
                <span className="font-semibold text-foreground break-all">{finding.ruleId}</span>
              </div>
              {finding.packageInfo && (
                <div className="col-span-2 pt-2 border-t border-line">
                  <span className="text-muted block text-[10px] uppercase">Affected Dependency</span>
                  <span className="font-semibold text-foreground">
                    {finding.packageInfo.name}@{finding.packageInfo.version}
                  </span>
                </div>
              )}
            </div>
          </section>

          {/* Redacted Evidence */}
          {finding.redactedEvidence && (
            <section>
              <h3 className="font-display font-bold text-sm">Evidence (Redacted)</h3>
              <pre
                tabIndex={0}
                className="mt-2 overflow-x-auto rounded-lg border border-line bg-background p-4 font-mono text-xs leading-6 text-foreground"
              >
                {finding.redactedEvidence}
              </pre>
              <p className="mt-1 font-mono text-[11px] text-muted">
                Secrets and tokens are strictly masked. Raw credentials are never stored.
              </p>
            </section>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <section>
              <h3 className="flex items-center gap-2 font-display font-bold text-sm">
                <Wrench className="size-4 text-accent" aria-hidden /> Remediation guidance
              </h3>
              <div className="mt-3 rounded-lg border border-line bg-surface/50 p-4 text-sm text-foreground">
                <p className="whitespace-pre-line leading-relaxed">{finding.remediation}</p>
              </div>
            </section>
          )}

          {/* External References */}
          {finding.vulnerabilityId && (
            <section className="border-t border-line pt-4">
              <h3 className="font-mono text-xs uppercase tracking-wider text-muted">Advisory link</h3>
              <a
                href={
                  finding.vulnerabilityId.startsWith("GHSA-")
                    ? `https://github.com/advisories/${finding.vulnerabilityId}`
                    : `https://nvd.nist.gov/vuln/detail/${finding.vulnerabilityId}`
                }
                target="_blank"
                rel="noreferrer"
                className="mt-2 inline-flex items-center gap-1.5 font-mono text-xs text-accent hover:underline"
              >
                {finding.vulnerabilityId} advisory details <ExternalLink className="size-3" />
              </a>
            </section>
          )}
        </div>
      </aside>
    </div>
  );
}
