import { ArrowRight } from "lucide-react";
import { Reveal } from "@/components/ui/reveal";
import { Button } from "@/components/ui/button";

export function SampleCta() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-12">
      <Reveal>
        <div className="relative overflow-hidden rounded-xl border border-line-bright bg-surface p-10 sm:p-16">
          <div className="absolute -right-24 -top-24 size-80 bg-[radial-gradient(closest-side,var(--accent-glow-subtle),transparent)]" aria-hidden />
          <div className="accent-line absolute inset-x-0 top-0 h-px" aria-hidden />
          <p className="relative font-mono text-xs uppercase tracking-widest text-accent">{"// Sample report"}</p>
          <h2 className="relative mt-3 max-w-2xl font-display text-3xl font-bold tracking-tight sm:text-5xl">
            See what a VibeShield report looks like.
          </h2>
          <p className="relative mt-4 max-w-xl text-muted">
            Filter findings, inspect masked evidence and read remediation guidance in an interactive report built on illustrative demo data.
          </p>
          <Button href="/demo-report" size="lg" className="relative mt-8">
            View Sample Report <ArrowRight className="size-4" aria-hidden />
          </Button>
        </div>
      </Reveal>
    </section>
  );
}
