import { Radar } from "lucide-react";
import { DemoBadge, SeverityBadge, severityStyles } from "@/components/ui/badges";
import type { Severity } from "@/lib/demo-data";
import { cn } from "@/lib/utils";

const rows: { sev: Severity; title: string; file: string; status: string }[] = [
  { sev: "critical", title: "Hard-coded payment key", file: "src/lib/payments.ts:7", status: "Open" },
  { sev: "high", title: "SQL built from user input", file: "api/notes/search/route.ts:21", status: "Open" },
  { sev: "high", title: "Vulnerable dependency", file: "package.json:24", status: "Triaged" },
  { sev: "medium", title: "Wildcard CORS + credentials", file: "src/middleware.ts:12", status: "Open" },
];
const summary: { sev: Severity; n: number }[] = [
  { sev: "critical", n: 1 },
  { sev: "high", n: 2 },
  { sev: "medium", n: 1 },
  { sev: "low", n: 1 },
];

export function DashboardPreview() {
  const c = 2 * Math.PI * 34;
  return (
    <div className="relative mx-auto w-full max-w-md animate-float" role="img" aria-label="Animated preview of a security dashboard showing demo data">
      <div className="absolute -inset-8 -z-10 bg-[radial-gradient(closest-side,var(--accent-glow-subtle),transparent)]" aria-hidden />
      <div className="relative overflow-hidden rounded-xl border border-line-bright bg-surface shadow-[0_40px_80px_-40px_rgba(198,255,61,0.18)]" aria-hidden>
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <div className="flex items-center gap-2 font-mono text-xs">
            <Radar className="size-4 text-accent" /> acme-demo/ai-notes-app
          </div>
          <DemoBadge>Demo data</DemoBadge>
        </div>

        <div className="relative p-5">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-10 animate-scan bg-gradient-to-b from-transparent via-accent/10 to-transparent" />

          <div className="mb-1 flex items-center justify-between font-mono text-[11px] uppercase tracking-wider text-muted">
            <span className="flex items-center gap-2">
              <span className="size-2 animate-pulse-dot rounded-full bg-accent" /> Simulated scan
            </span>
            <span>148 / 148 files</span>
          </div>
          <div className="h-1 overflow-hidden rounded-full bg-elevated">
            <div className="h-full w-full origin-left rounded-full bg-accent [animation:bar-grow_2.4s_var(--ease-luxury)_both]" />
          </div>

          <div className="mt-5 flex items-center gap-5">
            <div className="relative size-[88px] shrink-0">
              <svg viewBox="0 0 80 80" className="size-[88px] -rotate-90">
                <circle cx="40" cy="40" r="34" fill="none" stroke="#1c1c1c" strokeWidth="6" />
                <circle cx="40" cy="40" r="34" fill="none" stroke="var(--accent)" strokeWidth="6" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * 0.46} />
              </svg>
              <div className="absolute inset-0 grid place-items-center text-center">
                <div>
                  <div className="font-display text-2xl font-bold leading-none">54</div>
                  <div className="font-mono text-[10px] text-muted">/100</div>
                </div>
              </div>
            </div>
            <div>
              <p className="font-mono text-[11px] uppercase tracking-wider text-muted">Sample risk summary</p>
              <p className="font-display text-lg font-bold">Needs attention</p>
              <p className="text-xs text-muted">5 illustrative findings</p>
            </div>
          </div>

          <ul className="mt-5 grid grid-cols-4 gap-2">
            {summary.map((s) => (
              <li key={s.sev} className="rounded-md border border-line bg-elevated px-2 py-2 text-center">
                <div className={cn("font-display text-lg font-bold", severityStyles[s.sev].text)}>{s.n}</div>
                <div className="font-mono text-[10px] uppercase text-muted">{s.sev}</div>
              </li>
            ))}
          </ul>

          <ul className="mt-4 divide-y divide-line rounded-md border border-line">
            {rows.map((r) => (
              <li key={r.title} className="flex items-center justify-between gap-3 px-3 py-2.5">
                <div className="min-w-0">
                  <p className="truncate text-[13px] font-medium">{r.title}</p>
                  <p className="truncate font-mono text-[11px] text-muted">{r.file}</p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <SeverityBadge severity={r.sev} />
                  <span className="font-mono text-[10px] text-muted">{r.status}</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
