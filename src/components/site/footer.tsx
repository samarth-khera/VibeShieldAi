import Link from "next/link";
import { Logo } from "./logo";

export function Footer() {
  return (
    <footer className="mt-24 border-t border-border bg-white/60">
      <div className="mx-auto flex max-w-6xl flex-col gap-8 px-6 py-12 md:flex-row md:justify-between">
        <div className="max-w-xs">
          <Logo />
          <p className="mt-3 text-sm text-muted">
            Security analysis for AI-generated projects. This milestone is a frontend preview — live scanning is not connected yet.
          </p>
        </div>
        <nav aria-label="Footer" className="flex gap-12 text-sm">
          <ul className="space-y-2">
            <li className="font-semibold">Product</li>
            <li><Link className="text-muted hover:text-brand-ink" href="/#features">Features</Link></li>
            <li><Link className="text-muted hover:text-brand-ink" href="/#how-it-works">How It Works</Link></li>
            <li><Link className="text-muted hover:text-brand-ink" href="/demo-report">Demo report</Link></li>
          </ul>
          <ul className="space-y-2">
            <li className="font-semibold">Resources</li>
            <li><Link className="text-muted hover:text-brand-ink" href="/#faq">FAQ</Link></li>
            <li><Link className="text-muted hover:text-brand-ink" href="/#scan">Scan a repo</Link></li>
          </ul>
        </nav>
      </div>
      <div className="border-t border-border py-5 text-center text-xs text-muted">
        © 2026 VibeShield AI. Demo data shown on this site is illustrative only.
      </div>
    </footer>
  );
}
