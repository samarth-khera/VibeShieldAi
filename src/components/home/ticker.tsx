const words = ["SECRET DETECTION", "CODE ANALYSIS", "DEPENDENCY AUDITS", "CONFIGURATION CHECKS", "SECURITY INSIGHTS"];

export function Ticker() {
  const set = [...words, ...words];
  return (
    <section aria-label="Capabilities" className="border-y border-line bg-surface py-5">
      <div className="marquee-wrap relative overflow-hidden [mask-image:linear-gradient(90deg,transparent,#000_8%,#000_92%,transparent)]">
        <div className="marquee-track flex w-max animate-marquee">
          {[0, 1].map((copy) => (
            <ul key={copy} aria-hidden={copy === 1} className="flex shrink-0 items-center">
              {set.map((w, i) => (
                <li key={i} className="flex items-center font-display text-xl font-bold uppercase tracking-wide text-foreground/90 sm:text-2xl">
                  <span className="px-6 sm:px-8">{w}</span>
                  <span className="text-accent" aria-hidden>✦</span>
                </li>
              ))}
            </ul>
          ))}
        </div>
      </div>
    </section>
  );
}
