import Link from "next/link";
import { Logo } from "./logo";

export const REPO_URL = "https://github.com/samarth-khera/vibeshield-ai";

export function Footer() {
  return (
    <footer className="mt-24 border-t border-line bg-void">
      <div className="mx-auto flex max-w-6xl flex-col gap-10 px-6 py-14 md:flex-row md:justify-between">
        <div className="max-w-sm">
          <Logo />
          <p className="mt-4 text-sm text-muted">
            Automated scanning cannot guarantee complete security. VibeShield AI findings should be reviewed by a developer. Live scanning is not connected yet; all report data is illustrative.
          </p>
        </div>
        <nav aria-label="Footer" className="flex gap-16 text-sm">
          <ul className="space-y-3">
            <li className="font-mono text-xs uppercase tracking-widest text-muted">Product</li>
            <li><Link className="hover:text-accent" href="/#features">Features</Link></li>
            <li><Link className="hover:text-accent" href="/#how-it-works">How It Works</Link></li>
            <li><Link className="hover:text-accent" href="/demo-report">Sample Report</Link></li>
          </ul>
          <ul className="space-y-3">
            <li className="font-mono text-xs uppercase tracking-widest text-muted">Project</li>
            <li><a className="hover:text-accent" href={REPO_URL} target="_blank" rel="noopener noreferrer">GitHub repository</a></li>
            <li><Link className="hover:text-accent" href="/#scan">Scan Repository</Link></li>
          </ul>
        </nav>
      </div>
      <div className="border-t border-line py-5 text-center font-mono text-xs text-muted">
        © 2026 VibeShield AI
      </div>
    </footer>
  );
}
