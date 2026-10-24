import { Reveal } from "@/components/ui/reveal";
import { SectionHeading } from "./features";

const steps = [
  { n: "01", title: "Submit a repository", body: "Submit a public GitHub repository URL.", status: "Input validation available today" },
  { n: "02", title: "Analyze", body: "Analyze the repository with security scanners.", status: "Planned — not connected yet" },
  { n: "03", title: "Review & fix", body: "Review prioritized findings and recommended fixes.", status: "Explore via the sample report" },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="mx-auto max-w-6xl px-6 py-24">
      <Reveal>
        <SectionHeading eyebrow="How it works" title="From repository to remediation" />
      </Reveal>
      <ol className="mt-14 grid gap-px overflow-hidden rounded-xl border border-line bg-line md:grid-cols-3">
        {steps.map((s, i) => (
          <Reveal as="li" key={s.n} delay={i * 100} className="bg-surface">
            <div className="h-full p-8 transition-colors duration-300 hover:bg-elevated">
              <p className="font-display text-5xl font-bold text-line-bright">{s.n}</p>
              <h3 className="mt-6 font-display text-xl font-bold">{s.title}</h3>
              <p className="mt-2 text-sm text-muted">{s.body}</p>
              <p className="mt-5 inline-block rounded-full border border-line-bright px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-muted">
                {s.status}
              </p>
            </div>
          </Reveal>
        ))}
      </ol>
    </section>
  );
}
