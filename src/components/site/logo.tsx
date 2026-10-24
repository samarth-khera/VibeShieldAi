import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export function Logo({ className }: { className?: string }) {
  return (
    <Link href="/" className={cn("flex items-center gap-2.5 font-display text-lg font-bold tracking-tight", className)}>
      <span className="grid size-8 place-items-center rounded-md bg-accent text-accent-fg">
        <ShieldCheck className="size-[18px]" aria-hidden />
      </span>
      VibeShield<span className="text-accent">AI</span>
    </Link>
  );
}
