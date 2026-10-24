"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Menu, X } from "lucide-react";
import { Logo } from "./logo";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const links = [
  { href: "/#features", label: "Features" },
  { href: "/#how-it-works", label: "How It Works" },
  { href: "/#faq", label: "FAQ" },
  { href: "/demo-report", label: "Demo report" },
];

export function Navbar() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <header className="sticky top-0 z-40 px-3 pt-3 sm:px-6">
      <div
        className={cn(
          "mx-auto max-w-6xl rounded-2xl border bg-white/80 backdrop-blur-md transition-shadow duration-300",
          scrolled ? "border-border shadow-[0_10px_30px_-14px_rgba(70,60,190,0.35)]" : "border-white/70",
        )}
      >
        <nav aria-label="Primary" className="flex h-14 items-center justify-between px-4">
          <Logo />
          <ul className="hidden items-center gap-1 md:flex">
            {links.map((l) => (
              <li key={l.href}>
                <Link
                  href={l.href}
                  className="rounded-full px-4 py-2 text-sm font-medium text-muted transition-colors hover:bg-brand-soft hover:text-brand-ink"
                >
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
          <div className="flex items-center gap-2">
            <Button href="/#scan" className="hidden sm:inline-flex">
              Scan a repo
            </Button>
            <button
              type="button"
              aria-label={open ? "Close menu" : "Open menu"}
              aria-expanded={open}
              aria-controls="mobile-menu"
              onClick={() => setOpen((v) => !v)}
              className="grid size-10 place-items-center rounded-full border border-border bg-white md:hidden"
            >
              {open ? <X className="size-5" /> : <Menu className="size-5" />}
            </button>
          </div>
        </nav>
        {open && (
          <div id="mobile-menu" className="border-t border-border p-3 md:hidden [animation:drop-in_0.2s_ease-out]">
            <ul className="flex flex-col">
              {links.map((l) => (
                <li key={l.href}>
                  <Link
                    href={l.href}
                    onClick={() => setOpen(false)}
                    className="block rounded-xl px-4 py-3 text-sm font-medium hover:bg-brand-soft"
                  >
                    {l.label}
                  </Link>
                </li>
              ))}
            </ul>
            <Button href="/#scan" onClick={() => setOpen(false)} className="mt-2 w-full">
              Scan a repo
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
