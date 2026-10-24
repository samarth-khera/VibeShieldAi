"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ChevronRight, Search, SearchX } from "lucide-react";
import { demoFindings, demoRepo, type Severity } from "@/lib/demo-data";
import { DemoBadge, SeverityBadge, severityStyles } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { FindingDrawer } from "./finding-drawer";

const sevOrder: Severity[] = ["critical", "high", "medium", "low"];

export function ReportView() {
  const [sev, setSev] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const lastTrigger = useRef<HTMLElement | null>(null);

  const counts = useMemo(
    () => Object.fromEntries(sevOrder.map((s) => [s, demoFindings.filter((f) => f.severity === s).length])) as Record<Severity, number>,
    [],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return demoFindings
      .filter((f) => sev === "all" || f.severity === sev)
      .filter((f) => !q || `${f.title} ${f.file} ${f.id} ${f.rule} ${f.category}`.toLowerCase().includes(q))
      .sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  }, [sev, query]);

  const close = useCallback(() => {
    setSelectedId(null);
    window.setTimeout(() => lastTrigger.current?.focus(), 0);
  }, []);
  useEffect(() => {
    document.title = "Sample Report — VibeShield AI";
  }, []);
  const selected = demoFindings.find((f) => f.id === selectedId) ?? null;

  return (
    <div className="relative">
      <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-96" aria-hidden />
      <div className="relative mx-auto max-w-6xl px-6 py-10">
        <Link href="/" className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-muted hover:text-accent">
          <ArrowLeft className="size-4" aria-hidden /> Back to homepage
        </Link>

        <header className="mt-6 flex flex-col gap-6 rounded-xl border border-line-bright bg-surface p-6 sm:flex-row sm:items-start sm:justify-between sm:p-8">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <DemoBadge>Demo report</DemoBadge>
              <span className="font-mono text-xs text-muted">{demoRepo.scannedAt}</span>
            </div>
            <h1 className="mt-4 break-words font-display text-3xl font-bold tracking-tight sm:text-4xl">
              {demoRepo.owner}/{demoRepo.name}
            </h1>
            <p className="mt-2 font-mono text-xs text-muted">
              branch {demoRepo.branch} · commit {demoRepo.commit} · {demoRepo.filesAnalyzed} files · {demoRepo.linesAnalyzed} lines (illustrative)
            </p>
          </div>
          <div className="shrink-0 sm:text-right">
            <div className="font-display text-5xl font-bold leading-none text-accent">{demoRepo.score}</div>
            <div className="mt-1 font-mono text-[11px] uppercase tracking-wider text-muted">
              Sample risk score · {demoFindings.length} findings
            </div>
          </div>
        </header>

        <ul className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Severity summary">
          {sevOrder.map((s) => {
            const active = sev === s;
            return (
              <li key={s}>
                <button
                  onClick={() => setSev(active ? "all" : s)}
                  aria-pressed={active}
                  className={cn(
                    "w-full rounded-xl border bg-surface p-5 text-left transition-all duration-300 hover:-translate-y-0.5 hover:bg-elevated",
                    active ? "border-accent shadow-[0_0_24px_var(--accent-glow-subtle)]" : "border-line hover:border-line-bright",
                  )}
                >
                  <span className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-muted">
                    <span className={cn("size-2 rounded-full", severityStyles[s].dot)} aria-hidden />
                    {severityStyles[s].label}
                  </span>
                  <span className={cn("mt-2 block font-display text-4xl font-bold", severityStyles[s].text)}>{counts[s]}</span>
                </button>
              </li>
            );
          })}
        </ul>

        <section aria-label="Findings" className="mt-10">
          <div className="flex flex-col gap-3 sm:flex-row">
            <label className="relative flex-1">
              <span className="sr-only">Search findings</span>
              <Search className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search title, file, rule or ID"
                className="h-11 w-full rounded-full border border-line-bright bg-surface pl-11 pr-4 font-mono text-sm outline-none placeholder:text-muted/70 focus:border-accent"
              />
            </label>
            <label className="flex items-center gap-3 font-mono text-xs uppercase tracking-wider text-muted">
              Severity
              <select
                value={sev}
                onChange={(e) => setSev(e.target.value as Severity | "all")}
                className="h-11 rounded-full border border-line-bright bg-surface px-4 text-sm normal-case tracking-normal text-foreground"
              >
                <option value="all">All severities</option>
                {sevOrder.map((s) => (
                  <option key={s} value={s}>{severityStyles[s].label}</option>
                ))}
              </select>
            </label>
          </div>

          <p className="mt-5 font-mono text-xs uppercase tracking-wider text-muted" aria-live="polite">
            Showing {filtered.length} of {demoFindings.length} findings
          </p>

          {filtered.length === 0 ? (
            <div className="mt-4 rounded-xl border border-dashed border-line-bright p-12 text-center">
              <SearchX className="mx-auto size-8 text-accent" aria-hidden />
              <p className="mt-3 font-display text-lg font-bold">No findings match these filters</p>
              <Button variant="secondary" className="mt-4" onClick={() => { setSev("all"); setQuery(""); }}>
                Reset filters
              </Button>
            </div>
          ) : (
            <ul className="mt-4 divide-y divide-line overflow-hidden rounded-xl border border-line bg-surface">
              {filtered.map((f) => (
                <li key={f.id}>
                  <button
                    onClick={(e) => { lastTrigger.current = e.currentTarget; setSelectedId(f.id); }}
                    className="group flex w-full items-center justify-between gap-4 p-5 text-left transition-colors duration-300 hover:bg-elevated"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-mono text-[11px] uppercase tracking-wider text-muted">{f.category}</span>
                        <span className="font-mono text-[11px] text-muted">· {f.rule}</span>
                      </div>
                      <p className="mt-2 font-semibold">{f.title}</p>
                      <p className="mt-0.5 break-all font-mono text-xs text-muted">{f.file}:{f.line}</p>
                    </div>
                    <ChevronRight className="size-5 shrink-0 text-muted transition-transform duration-300 group-hover:translate-x-1 group-hover:text-accent" aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-6 font-mono text-[11px] uppercase tracking-wider text-muted">
            All findings, paths, line numbers and values on this page are illustrative demo data. Secrets are masked. No real scan was performed.
          </p>
        </section>

        <FindingDrawer finding={selected} onClose={close} />
      </div>
    </div>
  );
}
