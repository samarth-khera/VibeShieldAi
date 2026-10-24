import { Navbar } from "@/components/site/navbar";
import { Footer } from "@/components/site/footer";
import { ScanForm } from "@/components/home/scan-form";
import { DashboardPreview } from "@/components/home/dashboard-preview";
import { Ticker } from "@/components/home/ticker";
import { Metrics } from "@/components/home/metrics";
import { Features } from "@/components/home/features";
import { HowItWorks } from "@/components/home/how-it-works";
import { SampleCta } from "@/components/home/faq-cta";

const headline = ["Find", "the", "security", "holes", "AI", "left", "behind."];

export default function Home() {
  return (
    <>
      <Navbar />
      <main className="flex-1">
        <div className="relative overflow-hidden">
          <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />
          <section className="relative mx-auto grid max-w-6xl items-center gap-16 px-6 pb-20 pt-16 lg:grid-cols-[1.15fr_0.85fr] lg:pt-24">
            <div>
              <p className="hero-rise inline-flex items-center gap-2 rounded-full border border-line-bright px-3.5 py-1.5 font-mono text-xs uppercase tracking-wider text-muted">
                <span className="size-1.5 rounded-full bg-accent" aria-hidden /> Security for AI-generated code
              </p>
              <h1 className="mt-6 font-display text-5xl font-bold leading-[1] tracking-tight sm:text-6xl lg:text-7xl">
                {headline.map((w, i) => (
                  <span
                    key={i}
                    className={`hero-word mr-[0.25em] ${i >= 4 ? "text-accent" : ""}`}
                    style={{ animationDelay: `${i * 70}ms` }}
                  >
                    {w}
                  </span>
                ))}
              </h1>
              <p className="hero-rise mt-7 max-w-xl text-lg leading-relaxed text-muted [animation-delay:500ms]">
                Scan your GitHub repository for exposed secrets, insecure code patterns and vulnerable dependencies. Get clear findings, evidence and actionable fixes.
              </p>
              <div className="hero-rise mt-9 [animation-delay:600ms]">
                <ScanForm />
              </div>
            </div>
            <div className="hero-rise [animation-delay:700ms]">
              <DashboardPreview />
            </div>
          </section>
        </div>
        <Ticker />
        <Metrics />
        <Features />
        <HowItWorks />
        <SampleCta />
      </main>
      <Footer />
    </>
  );
}
