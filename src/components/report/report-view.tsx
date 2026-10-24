"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { ChevronRight, Search, SearchX } from "lucide-react";
import { categories, demoFindings, demoRepo, type Category, type Severity } from "@/lib/demo-data";
import { DemoBadge, SeverityBadge, severityStyles } from "@/components/ui/badges";
import { cn } from "@/lib/utils";
import { FindingDrawer } from "./finding-drawer";

const sevOrder: Severity[] = ["critical", "high", "medium", "low"];
type Tab = "All" | Category;
type Sort = "severity" | "file";

export function ReportView() {
  const [tab, setTab] = useState<Tab>("All");
  const [sev, setSev] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("severity");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const counts = useMemo(
    () => Object.fromEntries(sevOrder.map((s) => [s, demoFindings.filter((f) => f.severity === s).length])) as Record<Severity, number>,
    [],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return demoFindings
      .filter((f) => (tab === "All" || f.category === tab) && (sev === "all" || f.severity === sev))
      .filter((f) => !q || `${f.title} ${f.file} ${f.id}`.toLowerCase().includes(q))
      .sort((a, b) =>
        sort === "severity"
          ? sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity)
          : a.file.localeCompare(b.file),
      );
  }, [tab, sev, query, sort]);

  const close = useCallback(() => setSelectedId(null), []);
  const selected = demoFindings.find((f) => f.id === selectedId) ?? null;
  const reset = () => {
    setTab("All");
    setSev("all");
    setQuery("");
  };

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <nav aria-label="Breadcrumb" className="text-sm text-muted">
        <Link href="/" className="hover:text-brand-ink">Home</Link> <span aria-hidden>/</span> Demo report
      </nav>

      <header className="mt-4 flex flex-col gap-4 rounded-3xl border border-border bg-white p-6 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <DemoBadge />
            <span className="text-xs text-muted">{demoRepo.scannedAt}</span>
          </div>
          <h1 className="mt-2 font-display text-2xl font-extrabold sm:text-3xl">
            {demoRepo.owner}/{demoRepo.name}
          </h1>
          <p className="mt-1 font-mono text-xs text-muted">
            {demoRepo.branch} @ {demoRepo.commit} · {demoRepo.filesAnalyzed} files · {demoRepo.linesAnalyzed} lines (illustrative)
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="font-display text-4xl font-extrabold leading-none">{demoRepo.score}</div>
            <div className="text-xs text-muted">Sample score / 100</div>
          </div>
        </div>
      </header>

      <ul className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4" aria-label="Severity summary">
        {sevOrder.map((s) => {
          const active = sev === s;
          return (
            <li key={s}>
              <button
                onClick={() => setSev(active ? "all" : s)}
                aria-pressed={active}
                className={cn(
                  "w-full rounded-2xl border bg-white p-4 text-left transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_14px_30px_-20px_rgba(80,70,200,0.6)]",
                  active ? "border-brand ring-2 ring-brand/20" : "border-border",
                )}
              >
                <span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted">
                  <span className={cn("size-2 rounded-full", severityStyles[s].dot)} aria-hidden />
                  {severityStyles[s].label}
                </span>
                <span className="mt-1 block font-display text-3xl font-extrabold">{counts[s]}</span>
              </button>
            </li>
          );
        })}
      </ul>

      <section aria-label="Findings" className="mt-8">
        <div role="tablist" aria-label="Finding category" className="flex gap-2 overflow-x-auto pb-1">
          {(["All", ...categories] as Tab[]).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={tab === t}
              onClick={() => setTab(t)}
              className={cn(
                "shrink-0 rounded-full border px-4 py-2 text-sm font-semibold transition-colors",
                tab === t
                  ? "border-transparent bg-gradient-to-r from-[#6d5dfc] to-[#4f8dff] text-white"
                  : "border-border bg-white text-muted hover:text-brand-ink",
              )}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row">
          <label className="relative flex-1">
            <span className="sr-only">Search findings</span>
            <Search className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by title, file or ID"
              className="h-11 w-full rounded-full border border-border bg-white pl-11 pr-4 text-sm outline-none focus:border-brand"
            />
          </label>
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Severity</span>
            <select
              value={sev}
              onChange={(e) => setSev(e.target.value as Severity | "all")}
              className="h-11 rounded-full border border-border bg-white px-4 text-sm"
            >
              <option value="all">All</option>
              {sevOrder.map((s) => (
                <option key={s} value={s}>{severityStyles[s].label}</option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <span className="text-muted">Sort</span>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as Sort)}
              className="h-11 rounded-full border border-border bg-white px-4 text-sm"
            >
              <option value="severity">Severity</option>
              <option value="file">File path</option>
            </select>
          </label>
        </div>

        <p className="mt-4 text-sm text-muted" aria-live="polite">
          Showing {filtered.length} of {demoFindings.length} findings
        </p>

        {filtered.length === 0 ? (
          <div className="mt-4 rounded-3xl border border-dashed border-border bg-white/70 p-12 text-center">
            <SearchX className="mx-auto size-8 text-brand" aria-hidden />
            <p className="mt-3 font-display text-lg font-bold">No findings match these filters</p>
            <button onClick={reset} className="mt-3 text-sm font-semibold text-brand-ink underline underline-offset-4">
              Reset filters
            </button>
          </div>
        ) : (
          <ul className="mt-4 space-y-3">
            {filtered.map((f) => (
              <li key={f.id}>
                <button
                  onClick={() => setSelectedId(f.id)}
                  className="group flex w-full items-center justify-between gap-4 rounded-2xl border border-border bg-white p-5 text-left transition-all duration-200 hover:-translate-y-0.5 hover:border-brand/40 hover:shadow-[0_18px_36px_-24px_rgba(80,70,200,0.6)]"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="rounded-full bg-brand-soft px-2.5 py-0.5 text-xs font-medium text-brand-ink">{f.category}</span>
                      <span className="font-mono text-xs text-muted">{f.id}</span>
                    </div>
                    <p className="mt-2 font-semibold">{f.title}</p>
                    <p className="mt-0.5 truncate font-mono text-xs text-muted">
                      {f.file}:{f.line}
                    </p>
                  </div>
                  <ChevronRight className="size-5 shrink-0 text-muted transition-transform group-hover:translate-x-1 group-hover:text-brand" aria-hidden />
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <FindingDrawer finding={selected} onClose={close} />
    </div>
  );
}
