import { ChevronDown } from "lucide-react";
import { Reveal } from "@/components/ui/reveal";
import { Button } from "@/components/ui/button";
import { SectionHeading } from "./features";

const faqs = [
  { q: "Does VibeShield AI scan real repositories today?", a: "Not yet. This is a frontend-only milestone. The URL field validates format only and the demo report uses illustrative sample data." },
  { q: "What will it look for?", a: "Exposed secrets, insecure code patterns, vulnerable dependencies and risky configuration in AI-generated projects." },
  { q: "Will my code be stored?", a: "Nothing is sent anywhere in this preview. Data handling for the live scanner will be documented before it launches." },
  { q: "Are the findings in the demo report real?", a: "No. Every finding, path, score and package is made up to illustrate the report layout." },
];

export function DemoCta() {
  return (
    <section className="mx-auto max-w-6xl px-6 py-12">
      <Reveal>
        <div className="rounded-[2rem] border border-border bg-gradient-to-br from-white to-[#ecebff] p-10 text-center shadow-[0_30px_60px_-40px_rgba(80,70,200,0.5)] sm:p-14">
          <h2 className="font-display text-3xl font-extrabold tracking-tight sm:text-4xl">See what a report looks like</h2>
          <p className="mx-auto mt-3 max-w-xl text-muted">Explore an interactive sample report with filters, severity breakdowns and per-finding remediation.</p>
          <Button href="/demo-report" size="lg" className="mt-7">
            View demo report
          </Button>
        </div>
      </Reveal>
    </section>
  );
}

export function Faq() {
  return (
    <section id="faq" className="mx-auto max-w-3xl px-6 py-20">
      <Reveal>
        <SectionHeading eyebrow="FAQ" title="Questions, answered" />
      </Reveal>
      <Reveal className="mt-10 space-y-3">
        {faqs.map((f) => (
          <details key={f.q} className="group rounded-2xl border border-border bg-white px-6 py-4 transition-colors open:border-brand/40">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-semibold [&::-webkit-details-marker]:hidden">
              {f.q}
              <ChevronDown className="size-5 shrink-0 text-brand transition-transform duration-200 group-open:rotate-180" aria-hidden />
            </summary>
            <p className="mt-3 text-sm text-muted">{f.a}</p>
          </details>
        ))}
      </Reveal>
    </section>
  );
}
