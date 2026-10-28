"use client";

import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileCode2,
  HelpCircle,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Terminal,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import { SeverityBadge } from "@/components/ui/badges";
import {
  explainFindingWithAi,
  type AiFindingExplanation,
  type PublicFinding,
} from "@/lib/scan-client";
import { RemediationPanel } from "./remediation-panel";

export function RealFindingDrawer({
  jobId,
  finding,
  onClose,
  mode = "review",
  readOnly = false,
}: {
  jobId: string;
  finding: PublicFinding | null;
  onClose: () => void;
  mode?: "review" | "autofix";
  /** Not the browser that started the scan: show results, offer no actions. */
  readOnly?: boolean;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLElement>(null);
  const [copiedLoc, setCopiedLoc] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  // AI Analyst state keyed by finding id
  const [analyzedMap, setAnalyzedMap] = useState<
    Record<
      string,
      {
        explanation: AiFindingExplanation;
        isCached: boolean;
        model: string;
      }
    >
  >({});
  const [isExplaining, setIsExplaining] = useState(false);
  const [aiUnavailable, setAiUnavailable] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const activeAi = finding
    ? analyzedMap[finding.id] ||
      (finding.aiExplanation?.explanation
        ? {
            explanation: finding.aiExplanation.explanation,
            isCached: true,
            model: finding.aiExplanation.model || "configured AI provider",
          }
        : null)
    : null;


  const aiExplanation = activeAi?.explanation ?? null;
  const isCached = activeAi?.isCached ?? false;
  const modelUsed = activeAi?.model ?? null;

  // Manage drawer focus and body scroll lock
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

  const handleExplain = async () => {
    if (isExplaining) return;
    setIsExplaining(true);
    setAiError(null);
    setAiUnavailable(false);

    try {
      const res = await explainFindingWithAi(jobId, finding.id);
      if (res.available) {
        setAnalyzedMap((prev) => ({
          ...prev,
          [finding.id]: {
            explanation: res.explanation,
            isCached: res.cached,
            model: res.model,
          },
        }));
      } else {
        if (res.code === "ai_not_configured") {
          setAiUnavailable(true);
        } else {
          const ref = res.diagnostic?.correlationId;
          setAiError(ref ? `${res.message} (reference ${ref}, ${res.diagnostic?.category ?? res.code})` : res.message);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to obtain AI analysis.";
      setAiError(msg);
    } finally {
      setIsExplaining(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/70 [animation:fade-in_0.25s_ease-out]" onClick={onClose} aria-hidden />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="real-drawer-title"
        className="absolute right-0 top-0 flex h-full w-full max-w-2xl flex-col overflow-y-auto border-l border-line-bright bg-surface [animation:slide-in-right_0.4s_var(--ease-luxury)]"
      >
        {/* Header */}
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
          {/* Target Location */}
          <section>
            <div className="flex items-center justify-between">
              <p className="flex items-center gap-2 break-all font-mono text-sm text-accent">
                <FileCode2 className="size-4 shrink-0" aria-hidden /> {loc}
              </p>
              <button
                onClick={() => {
                  navigator.clipboard?.writeText(loc);
                  setCopiedLoc(true);
                  window.setTimeout(() => setCopiedLoc(false), 1500);
                }}
                className="inline-flex items-center gap-1.5 rounded-full border border-line-bright px-3 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors hover:border-accent hover:text-accent"
              >
                {copiedLoc ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                {copiedLoc ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="mt-3 text-sm leading-relaxed text-muted whitespace-pre-line">{finding.description}</p>
          </section>

          {/* Scanner Details Grid */}
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

          {/* AI Security Analyst Section */}
          <section className="rounded-xl border border-accent/30 bg-surface/80 p-5 shadow-lg shadow-accent/5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <div className="grid size-8 place-items-center rounded-lg bg-accent/10 text-accent">
                  <Sparkles className="size-4" />
                </div>
                <div>
                  <h3 className="font-display text-sm font-bold text-foreground">AI Security Analyst</h3>
                  <p className="text-[11px] text-muted">Grounded remediation &amp; exploitability analysis</p>
                </div>
              </div>

              {!aiExplanation && !isExplaining && readOnly && (
                <p className="text-[11px] text-muted">Only the browser that started this scan can request an explanation.</p>
              )}
              {!aiExplanation && !isExplaining && !readOnly && (
                <button
                  onClick={handleExplain}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-background shadow transition-all hover:bg-accent/90 hover:shadow-accent/20"
                >
                  <Sparkles className="size-3.5" /> Explain with AI
                </button>
              )}
            </div>

            {/* Loading state */}
            {isExplaining && (
              <div className="mt-4 flex flex-col items-center justify-center rounded-lg border border-line bg-background/50 py-8 text-center">
                <RefreshCw className="size-6 animate-spin text-accent" />
                <p className="mt-3 text-xs font-medium text-foreground">
                  Analyzing finding with AI Security Analyst{modelUsed ? ` (${modelUsed})` : ""}...
                </p>
                <p className="mt-1 text-[11px] text-muted">
                  Grounding guidance in scanner evidence and evaluating exploitability prerequisites.
                </p>
              </div>
            )}

            {/* AI Unavailable state */}
            {aiUnavailable && !isExplaining && (
              <div className="mt-4 rounded-lg border border-line bg-background/80 p-4">
                <div className="flex items-start gap-3">
                  <HelpCircle className="size-5 shrink-0 text-muted" />
                  <div>
                    <h4 className="text-xs font-semibold text-foreground">AI Security Analyst Unavailable</h4>
                    <p className="mt-1 text-xs leading-relaxed text-muted">
                      The configured AI inference provider is currently offline or not configured on the server.
                      Automated scanner findings and static remediation remain fully accessible below.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Error state */}
            {aiError && !isExplaining && (
              <div className="mt-4 rounded-lg border border-sev-critical/30 bg-sev-critical/5 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <AlertTriangle className="size-4 shrink-0 text-sev-critical" />
                    <div>
                      <p className="text-xs text-sev-critical leading-relaxed">{aiError}</p>
                      <p className="mt-1 text-[11px] text-muted">
                        Automated scanner findings and code evidence remain fully available.
                      </p>
                    </div>
                  </div>
                  {!aiError.toLowerCase().includes("quota") && (
                    <button
                      onClick={handleExplain}
                      disabled={isExplaining}
                      className="shrink-0 rounded border border-sev-critical/40 px-2.5 py-1 text-[11px] font-semibold text-sev-critical hover:bg-sev-critical/10 disabled:opacity-50"
                    >
                      Retry
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* Render AI Explanation Content */}
            {aiExplanation && !isExplaining && (
              <div className="mt-5 space-y-5 border-t border-line/60 pt-4">
                {/* Meta header (model & cache badge) */}
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-muted">
                  <span className="flex items-center gap-1.5">
                    <Terminal className="size-3 text-accent" /> {modelUsed || "configured AI provider"}
                  </span>
                  {isCached && (
                    <span className="inline-flex items-center gap-1 rounded bg-accent/10 px-2 py-0.5 text-accent font-semibold">
                      <Zap className="size-3" /> Cached Analysis
                    </span>
                  )}
                </div>

                {/* Plain-English Summary */}
                <div>
                  <h4 className="font-display text-xs font-bold uppercase tracking-wider text-accent">
                    Plain-English Summary
                  </h4>
                  <p className="mt-1.5 text-xs leading-relaxed text-foreground whitespace-pre-line">
                    {aiExplanation.summary}
                  </p>
                </div>

                {/* Why It Matters */}
                <div>
                  <h4 className="font-display text-xs font-bold uppercase tracking-wider text-muted">
                    Why It Matters
                  </h4>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted whitespace-pre-line">
                    {aiExplanation.whyItMatters}
                  </p>
                </div>

                {/* Potential Impact */}
                <div className="rounded-lg border border-line bg-background/50 p-3.5">
                  <h4 className="flex items-center gap-1.5 font-display text-xs font-bold text-foreground">
                    <ShieldAlert className="size-3.5 text-sev-high" /> Potential Impact
                  </h4>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted whitespace-pre-line">
                    {aiExplanation.impact}
                  </p>
                </div>

                {/* Exploitability Conditions */}
                <div className="rounded-lg border border-line bg-background/50 p-3.5">
                  <h4 className="font-display text-xs font-bold text-foreground">
                    Exploitability Conditions
                  </h4>
                  <p className="mt-1.5 text-xs leading-relaxed text-muted whitespace-pre-line">
                    {aiExplanation.exploitabilityConditions}
                  </p>
                </div>

                {/* Step-by-Step Remediation */}
                <div>
                  <h4 className="flex items-center gap-1.5 font-display text-xs font-bold uppercase tracking-wider text-accent">
                    <Wrench className="size-3.5" /> Step-by-Step Remediation
                  </h4>
                  <ol className="mt-2.5 space-y-2">
                    {aiExplanation.remediationSteps.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-xs text-foreground">
                        <span className="grid size-4 shrink-0 place-items-center rounded-full bg-accent/20 text-[10px] font-bold text-accent">
                          {idx + 1}
                        </span>
                        <span className="leading-relaxed">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                {/* Code Example / Patch */}
                {aiExplanation.codeExample && (
                  <div>
                    <div className="flex items-center justify-between">
                      <h4 className="font-display text-xs font-bold uppercase tracking-wider text-muted">
                        {aiExplanation.codeExample.title || "Remediated Code Example"}
                      </h4>
                      <button
                        onClick={() => {
                          if (!aiExplanation.codeExample?.code) return;
                          navigator.clipboard?.writeText(aiExplanation.codeExample.code);
                          setCopiedCode(true);
                          window.setTimeout(() => setCopiedCode(false), 1500);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-line px-2 py-0.5 font-mono text-[10px] uppercase text-muted hover:text-accent"
                      >
                        {copiedCode ? <Check className="size-3" /> : <Copy className="size-3" />}
                        {copiedCode ? "Copied" : "Copy Code"}
                      </button>
                    </div>
                    <pre
                      tabIndex={0}
                      className="mt-2 overflow-x-auto rounded-lg border border-line bg-background p-4 font-mono text-xs leading-5 text-accent"
                    >
                      {aiExplanation.codeExample.code}
                    </pre>
                  </div>
                )}

                {/* Verification Steps */}
                <div>
                  <h4 className="flex items-center gap-1.5 font-display text-xs font-bold uppercase tracking-wider text-accent">
                    <CheckCircle2 className="size-3.5 text-accent" /> Verification Checklist
                  </h4>
                  <ul className="mt-2.5 space-y-1.5">
                    {aiExplanation.verificationSteps.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-xs text-muted">
                        <span className="mt-0.5 text-accent font-bold">✓</span>
                        <span className="leading-relaxed">{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Uncertainties / Missing Evidence */}
                {aiExplanation.uncertainties && aiExplanation.uncertainties.length > 0 && (
                  <div className="rounded-lg border border-line/60 bg-background/40 p-3">
                    <h4 className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-muted">
                      <HelpCircle className="size-3" /> Important Uncertainties
                    </h4>
                    <ul className="mt-1.5 space-y-1 text-[11px] text-muted/80">
                      {aiExplanation.uncertainties.map((u, idx) => (
                        <li key={idx} className="list-disc list-inside">
                          {u}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Grounding Disclaimer */}
                <p className="font-mono text-[10px] text-muted/70 leading-relaxed italic border-t border-line/40 pt-3">
                  ⚠️ {aiExplanation.disclaimer}
                </p>
              </div>
            )}
          </section>

          {/* Standard Scanner Remediation (fallback) */}
          {finding.remediation && (
            <section>
              <h3 className="flex items-center gap-2 font-display font-bold text-sm">
                <Wrench className="size-4 text-accent" aria-hidden /> Scanner Guidance
              </h3>
              <div className="mt-3 rounded-lg border border-line bg-surface/50 p-4 text-sm text-foreground">
                <p className="whitespace-pre-line leading-relaxed">{finding.remediation}</p>
              </div>
            </section>
          )}

          {/* AI Remediation & Auto-Fix Panel */}
          <section>
            <RemediationPanel jobId={jobId} finding={finding} mode={mode} readOnly={readOnly} />
          </section>

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
