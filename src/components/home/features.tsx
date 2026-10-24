import { Code2, KeyRound, Package, Settings2 } from "lucide-react";
import { Reveal } from "@/components/ui/reveal";

const features = [
  {
    icon: KeyRound,
    title: "Secret detection",
    body: "Spot API keys, tokens and credentials that AI assistants paste into source files, with values masked in reports.",
  },
  {
    icon: Code2,
    title: "Code analysis",
    body: "Flag insecure patterns such as injectable queries, unsafe eval and missing validation in generated code.",
  },
  {
    icon: Package,
    title: "Dependency review",
    body: "Surface outdated or vulnerable packages that generated manifests quietly pull in.",
  },
  {
    icon: Settings2,
    title: "Configuration checks",
    body: "Catch permissive CORS, debug flags and risky defaults before they reach production.",
  },
];

export function SectionHeading({ eyebrow, title, body }: { eyebrow: string; title: string; body?: string }) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="text-sm font-semibold uppercase tracking-widest text-brand">{eyebrow}</p>
      <h2 className="mt-3 font-display text-3xl font-extrabold tracking-tight sm:text-4xl">{title}</h2>
      {body && <p className="mt-4 text-muted">{body}</p>}
    </div>
  );
}

export function Features() {
  return (
    <section id="features" className="mx-auto max-w-6xl px-6 py-20">
      <Reveal>
        <SectionHeading
          eyebrow="Features"
          title="Review AI-written code with a security mindset"
          body="Four focused areas of analysis, presented as clear, actionable findings."
        />
      </Reveal>
      <ul className="mt-12 grid gap-5 sm:grid-cols-2">
        {features.map((f, i) => (
          <Reveal as="li" key={f.title} delay={i * 80}>
            <div className="group h-full rounded-3xl border border-border bg-white p-7 transition-all duration-300 hover:-translate-y-1 hover:border-brand/40 hover:shadow-[0_24px_50px_-28px_rgba(80,70,200,0.55)]">
              <span className="grid size-12 place-items-center rounded-2xl bg-brand-soft text-brand transition-colors duration-300 group-hover:bg-gradient-to-br group-hover:from-[#6d5dfc] group-hover:to-[#4f8dff] group-hover:text-white">
                <f.icon className="size-6" aria-hidden />
              </span>
              <h3 className="mt-5 font-display text-xl font-bold">{f.title}</h3>
              <p className="mt-2 text-muted">{f.body}</p>
            </div>
          </Reveal>
        ))}
      </ul>
    </section>
  );
}
