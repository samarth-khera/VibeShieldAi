import { Navbar } from "@/components/site/navbar";
import { Footer } from "@/components/site/footer";
import { ScanForm } from "@/components/home/scan-form";
import { DashboardPreview } from "@/components/home/dashboard-preview";
import { Ticker } from "@/components/home/ticker";
import { Features } from "@/components/home/features";
import { HowItWorks } from "@/components/home/how-it-works";
import { DemoCta, Faq } from "@/components/home/faq-cta";

export default function Home() {
  return (
    <>
      <Navbar />
      <main className="flex-1">
        <section className="mx-auto grid max-w-6xl items-center gap-14 px-6 pb-8 pt-16 lg:grid-cols-[1.1fr_0.9fr] lg:pt-24">
          <div>
            <p className="hero-rise inline-flex items-center gap-2 rounded-full border border-brand/25 bg-white px-3.5 py-1.5 text-xs font-semibold text-brand-ink">
              <span className="size-1.5 rounded-full bg-brand" aria-hidden /> Security analysis for AI-generated code
            </p>
            <h1 className="hero-rise mt-6 font-display text-4xl font-extrabold leading-[1.05] tracking-tight sm:text-5xl lg:text-6xl [animation-delay:80ms]">
              Find the security holes{" "}
              <span className="bg-gradient-to-r from-[#6d5dfc] to-[#4f8dff] bg-clip-text text-transparent">AI left behind.</span>
            </h1>
            <p className="hero-rise mt-6 max-w-xl text-lg text-muted [animation-delay:160ms]">
              AI assistants write code fast — and sometimes leave exposed secrets, unsafe patterns and vulnerable dependencies behind. VibeShield AI is built to surface them before you ship.
            </p>
            <div className="hero-rise mt-9 [animation-delay:240ms]">
              <ScanForm />
            </div>
          </div>
          <div className="hero-rise [animation-delay:320ms]">
            <DashboardPreview />
          </div>
        </section>
        <Ticker />
        <Features />
        <HowItWorks />
        <DemoCta />
        <Faq />
      </main>
      <Footer />
    </>
  );
}
