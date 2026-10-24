import { Bot, Code2, FileText, KeyRound, Package, Settings2 } from "lucide-react";
import { Reveal } from "@/components/ui/reveal";

const features = [
  { icon: KeyRound, title: "Secret Detection", body: "Identify potentially exposed API keys and credentials in source files." },
  { icon: Code2, title: "Code Security", body: "Highlight supported insecure code patterns such as injectable queries." },
  { icon: Package, title: "Dependency Audits", body: "Surface known vulnerabilities in supported dependency manifests." },
  { icon: Settings2, title: "Configuration Review", body: "Identify selected insecure configuration patterns before release." },
  { icon: FileText, title: "Actionable Reports", body: "Understand severity, evidence and impact for every finding." },
  { icon: Bot, title: "AI Remediation Guidance", body: "Explain findings in plain language and suggest possible fixes." },
];

export function SectionHeading({ eyebrow, title, body }: { eyebrow: string; title: string; body?: string }) {
  return (
    <div className="max-w-2xl">
      <p className="font-mono text-xs uppercase tracking-widest text-accent">{`// ${eyebrow}`}</p>
      <h2 className="mt-3 font-display text-3xl font-bold tracking-tight sm:text-5xl">{title}</h2>
      {body && <p className="mt-4 text-muted">{body}</p>}
    </div>
  );
}

export function Features() {
  return (
    <section id="features" className="mx-auto max-w-6xl px-6 py-24">
      <Reveal>
        <SectionHeading eyebrow="Features" title="Review AI-written code with a security mindset" />
      </Reveal>
      <ul className="mt-14 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-3">
        {features.map((f, i) => (
          <Reveal as="li" key={f.title} delay={(i % 3) * 80} className="bg-background">
            <div className="group h-full bg-surface p-8 transition-colors duration-300 hover:bg-elevated">
              <span className="grid size-11 place-items-center rounded-md border border-line-bright text-accent transition-all duration-300 group-hover:border-accent group-hover:bg-accent group-hover:text-accent-fg group-hover:shadow-[0_0_24px_var(--accent-glow)]">
                <f.icon className="size-5" aria-hidden />
              </span>
              <h3 className="mt-6 font-display text-xl font-bold">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{f.body}</p>
            </div>
          </Reveal>
        ))}
      </ul>
    </section>
  );
}
