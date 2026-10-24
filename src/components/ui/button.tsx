import Link from "next/link";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost";
type Size = "md" | "lg";

const base =
  "inline-flex items-center justify-center gap-2 rounded-full font-semibold whitespace-nowrap transition-all duration-300 ease-[var(--ease-luxury)] active:scale-[0.97] disabled:opacity-60 disabled:pointer-events-none cursor-pointer";
const variants: Record<Variant, string> = {
  primary:
    "bg-accent text-accent-fg hover:bg-accent-hover hover:-translate-y-0.5 hover:shadow-[0_0_32px_var(--accent-glow)]",
  secondary:
    "border border-line-bright bg-transparent text-foreground hover:border-accent hover:text-accent hover:-translate-y-0.5",
  ghost: "text-muted hover:text-foreground",
};
const sizes: Record<Size, string> = { md: "h-10 px-5 text-sm", lg: "h-12 px-7 text-[15px]" };

export function buttonClass(variant: Variant = "primary", size: Size = "md", className?: string) {
  return cn(base, variants[variant], sizes[size], className);
}

type Props = {
  variant?: Variant;
  size?: Size;
  className?: string;
  children: React.ReactNode;
} & (
  | ({ href: string } & Omit<React.ComponentProps<typeof Link>, "className" | "children">)
  | ({ href?: undefined } & React.ButtonHTMLAttributes<HTMLButtonElement>)
);

export function Button({ variant, size, className, children, ...rest }: Props) {
  const cls = buttonClass(variant, size, className);
  if ("href" in rest && rest.href !== undefined) {
    return (
      <Link className={cls} {...(rest as React.ComponentProps<typeof Link>)}>
        {children}
      </Link>
    );
  }
  return (
    <button className={cls} {...(rest as React.ButtonHTMLAttributes<HTMLButtonElement>)}>
      {children}
    </button>
  );
}
