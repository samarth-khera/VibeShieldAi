import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/demo-data";

export const severityStyles: Record<Severity, { label: string; chip: string; dot: string }> = {
  critical: { label: "Critical", chip: "bg-[#fde8f0] text-[#b4235a] border-[#f7c6d9]", dot: "bg-[#d6336c]" },
  high: { label: "High", chip: "bg-[#fff0e3] text-[#b84708] border-[#fbd5b5]", dot: "bg-[#e8590c]" },
  medium: { label: "Medium", chip: "bg-[#fdf5df] text-[#8a5a0b] border-[#f3e0a8]", dot: "bg-[#d9a21b]" },
  low: { label: "Low", chip: "bg-[#e6f1ff] text-[#1f5fae] border-[#bfdaf8]", dot: "bg-[#2b7bd6]" },
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = severityStyles[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        s.chip,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", s.dot)} aria-hidden />
      {s.label}
    </span>
  );
}

export function DemoBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-brand/25 bg-brand-soft px-2.5 py-0.5 text-xs font-semibold text-brand-ink",
        className,
      )}
    >
      Demo data
    </span>
  );
}
