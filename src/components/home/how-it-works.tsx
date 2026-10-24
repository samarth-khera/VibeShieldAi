import { FileCheck2, GitBranch, ScanSearch } from "lucide-react";
import { Reveal } from "@/components/ui/reveal";
import { SectionHeading } from "./features";

const steps = [
  { icon: GitBranch, title: "Paste a repository", body: "Provide a GitHub repository URL for the project you want reviewed." },
  { icon: ScanSearch, title: "Analyze", body: "Secrets, code, dependencies and configuration are checked (not yet connected in this preview)." },
  { icon: FileCheck2, title: "Fix with clarity", body: "Get severity-ranked findings with file paths, evidence and remediation steps." },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="mx-auto max-w-6xl px-6 py-20">
      <Reveal>
        <SectionHeading eyebrow="How it works" title="From repo to remediation in three steps" />
      </Reveal>
      <ol className="relative mt-14 grid gap-6 md:grid-cols-3">
        <div className="absolute left-[16%] right-[16%] top-8 hidden h-px bg-gradient-to-r from-transparent via-brand/40 to-transparent md:block" aria-hidden />
        {steps.map((s, i) => (
          <Reveal as="li" key={s.title} delay={i * 100}>
            <div className="relative h-full rounded-3xl border border-border bg-white p-7 text-center transition-all duration-300 hover:-translate-y-1 hover:border-brand/40">
              <span className="relative z-10 mx-auto grid size-16 place-items-center rounded-2xl bg-gradient-to-br from-[#6d5dfc] to-[#4f8dff] text-white shadow-[0_12px_24px_-10px_rgba(95,90,252,0.7)]">
                <s.icon className="size-7" aria-hidden />
              </span>
              <p className="mt-4 text-xs font-semibold uppercase tracking-widest text-brand">Step {i + 1}</p>
              <h3 className="mt-1 font-display text-xl font-bold">{s.title}</h3>
              <p className="mt-2 text-sm text-muted">{s.body}</p>
            </div>
          </Reveal>
        ))}
      </ol>
    </section>
  );
}
