import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export function Logo({ className }: { className?: string }) {
  return (
    <Link href="/" className={cn("flex items-center gap-2.5 font-display text-lg font-extrabold tracking-tight", className)}>
      <span className="grid size-9 place-items-center rounded-xl bg-gradient-to-br from-[#6d5dfc] to-[#4f8dff] text-white shadow-[0_6px_16px_-6px_rgba(95,90,252,0.8)]">
        <ShieldCheck className="size-5" aria-hidden />
      </span>
      VibeShield<span className="text-brand">AI</span>
    </Link>
  );
}
