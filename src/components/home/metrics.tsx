import { Reveal } from "@/components/ui/reveal";

const metrics = [
  { value: "4", label: "Security check areas", note: "Secrets, code, dependencies, configuration" },
  { value: "12+", label: "Vulnerability categories", note: "Planned coverage target" },
  { value: "100%", label: "Evidence-backed findings", note: "Design goal: every finding cites a file and line" },
  { value: "1:1", label: "Remediation guidance", note: "Design goal: a suggested fix per finding" },
];

export function Metrics() {
  return (
    <section aria-labelledby="metrics-title" className="mx-auto max-w-6xl px-6 py-12">
      <h2 id="metrics-title" className="sr-only">Product capabilities</h2>
      <ul className="grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
        {metrics.map((m, i) => (
          <Reveal as="li" key={m.label} delay={i * 80} className="bg-surface">
            <div className="h-full p-7">
              <p className="font-display text-5xl font-bold tracking-tight text-accent">{m.value}</p>
              <p className="mt-3 font-semibold">{m.label}</p>
              <p className="mt-1 text-xs text-muted">{m.note}</p>
            </div>
          </Reveal>
        ))}
      </ul>
      <p className="mt-3 font-mono text-[11px] uppercase tracking-wider text-muted">
        Capability targets and design goals, not measured results or customer statistics.
      </p>
    </section>
  );
}
