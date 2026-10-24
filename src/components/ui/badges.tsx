import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/demo-data";

export const severityStyles: Record<Severity, { label: string; chip: string; dot: string; text: string }> = {
  critical: { label: "Critical", chip: "bg-sev-critical/10 text-sev-critical border-sev-critical/30", dot: "bg-sev-critical", text: "text-sev-critical" },
  high: { label: "High", chip: "bg-sev-high/10 text-sev-high border-sev-high/30", dot: "bg-sev-high", text: "text-sev-high" },
  medium: { label: "Medium", chip: "bg-sev-medium/10 text-sev-medium border-sev-medium/30", dot: "bg-sev-medium", text: "text-sev-medium" },
  low: { label: "Low", chip: "bg-sev-low/10 text-sev-low border-sev-low/30", dot: "bg-sev-low", text: "text-sev-low" },
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = severityStyles[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wider",
        s.chip,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", s.dot)} aria-hidden />
      {s.label}
    </span>
  );
}

export function DemoBadge({ className, children = "Demo data" }: { className?: string; children?: React.ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wider text-accent",
        className,
      )}
    >
      {children}
    </span>
  );
}
