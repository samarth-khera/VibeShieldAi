import { KeyRound, Code2, Package, Settings2 } from "lucide-react";

const items = [
  { icon: KeyRound, label: "Secrets" },
  { icon: Code2, label: "Code Analysis" },
  { icon: Package, label: "Dependencies" },
  { icon: Settings2, label: "Configuration" },
];

export function Ticker() {
  // Two identical halves → seamless -50% loop. Second half hidden from assistive tech.
  const half = [...items, ...items, ...items];
  return (
    <section aria-label="What VibeShield AI checks" className="py-10">
      <div className="ticker-wrap relative overflow-hidden [mask-image:linear-gradient(90deg,transparent,#000_10%,#000_90%,transparent)]">
        <div className="ticker-track flex w-max animate-ticker">
          {[0, 1].map((copy) => (
            <ul key={copy} aria-hidden={copy === 1} className="flex shrink-0 items-center gap-4 pr-4">
              {half.map((it, i) => (
                <li
                  key={i}
                  className="flex items-center gap-2.5 rounded-full border border-border bg-white px-5 py-2.5 text-sm font-semibold text-foreground shadow-sm"
                >
                  <it.icon className="size-4 text-brand" aria-hidden />
                  {it.label}
                </li>
              ))}
            </ul>
          ))}
        </div>
      </div>
    </section>
  );
}
