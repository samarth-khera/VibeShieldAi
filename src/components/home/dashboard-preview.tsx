import { CheckCircle2, Radar } from "lucide-react";
import { DemoBadge, SeverityBadge } from "@/components/ui/badges";
import type { Severity } from "@/lib/demo-data";

const rows: { sev: Severity; title: string; file: string }[] = [
  { sev: "critical", title: "Hard-coded payment key", file: "src/lib/payments.ts:7" },
  { sev: "high", title: "SQL built from user input", file: "api/notes/search/route.ts:21" },
  { sev: "high", title: "Vulnerable dependency", file: "package.json:24" },
  { sev: "medium", title: "Wildcard CORS + credentials", file: "src/middleware.ts:12" },
];

const summary: { sev: Severity; n: number }[] = [
  { sev: "critical", n: 1 },
  { sev: "high", n: 2 },
  { sev: "medium", n: 1 },
  { sev: "low", n: 1 },
];

export function DashboardPreview() {
  const circumference = 2 * Math.PI * 36;
  return (
    <div className="relative mx-auto w-full max-w-md animate-float motion-reduce:animate-none" aria-label="Demo security dashboard preview">
      <div className="absolute -inset-6 -z-10 rounded-[3rem] bg-gradient-to-br from-[#d9d3ff] to-[#d3e6ff] opacity-70 blur-2xl" aria-hidden />
      <div className="overflow-hidden rounded-3xl border border-border bg-white shadow-[0_30px_70px_-30px_rgba(70,60,190,0.45)]">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Radar className="size-4 text-brand" aria-hidden /> acme-demo/ai-notes-app
          </div>
          <DemoBadge />
        </div>

        <div className="relative p-5">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-16 animate-scan bg-gradient-to-b from-transparent via-brand/10 to-transparent motion-reduce:hidden" aria-hidden />
          <div className="flex items-center gap-5">
            <div className="relative size-24 shrink-0">
              <svg viewBox="0 0 88 88" className="size-24 -rotate-90" aria-hidden>
                <circle cx="44" cy="44" r="36" fill="none" stroke="#ecebfa" strokeWidth="8" />
                <circle
                  cx="44" cy="44" r="36" fill="none" stroke="url(#g)" strokeWidth="8" strokeLinecap="round"
                  strokeDasharray={circumference} strokeDashoffset={circumference * (1 - 0.54)}
                />
                <defs>
                  <linearGradient id="g" x1="0" x2="1">
                    <stop offset="0" stopColor="#6d5dfc" />
                    <stop offset="1" stopColor="#4f8dff" />
                  </linearGradient>
                </defs>
              </svg>
              <div className="absolute inset-0 grid place-items-center text-center">
                <div>
                  <div className="font-display text-2xl font-extrabold leading-none">54</div>
                  <div className="text-[10px] text-muted">/ 100</div>
                </div>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-muted">Sample score</p>
              <p className="font-display text-lg font-bold">Needs attention</p>
              <p className="mt-1 flex items-center gap-1.5 text-xs text-muted">
                <span className="size-2 animate-pulse-dot rounded-full bg-brand motion-reduce:animate-none" aria-hidden />
                Illustrative analysis in progress
              </p>
            </div>
          </div>

          <ul className="mt-5 grid grid-cols-4 gap-2" aria-label="Severity summary (demo)">
            {summary.map((s) => (
              <li key={s.sev} className="rounded-xl border border-border bg-[#faf9ff] px-2 py-2 text-center">
                <div className="font-display text-lg font-bold">{s.n}</div>
                <div className="text-[10px] capitalize text-muted">{s.sev}</div>
              </li>
            ))}
          </ul>

          <ul className="mt-4 space-y-2">
            {rows.map((r) => (
              <li key={r.title} className="flex items-center justify-between gap-3 rounded-xl border border-border px-3 py-2.5">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold">{r.title}</p>
                  <p className="truncate font-mono text-[11px] text-muted">{r.file}</p>
                </div>
                <SeverityBadge severity={r.sev} />
              </li>
            ))}
          </ul>

          <p className="mt-4 flex items-center gap-1.5 text-xs text-muted">
            <CheckCircle2 className="size-3.5 text-brand" aria-hidden /> All values above are demo data.
          </p>
        </div>
      </div>
    </div>
  );
}
