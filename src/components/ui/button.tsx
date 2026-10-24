import Link from "next/link";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost";
type Size = "md" | "lg";

const base =
  "inline-flex items-center justify-center gap-2 rounded-full font-semibold whitespace-nowrap transition-all duration-200 active:scale-[0.97] disabled:opacity-60 disabled:pointer-events-none cursor-pointer";
const variants: Record<Variant, string> = {
  primary:
    "text-white bg-gradient-to-r from-[#6d5dfc] to-[#4f8dff] shadow-[0_8px_20px_-8px_rgba(95,90,252,0.7)] hover:shadow-[0_12px_28px_-8px_rgba(95,90,252,0.85)] hover:-translate-y-0.5",
  secondary:
    "bg-white text-foreground border border-border hover:border-brand/50 hover:-translate-y-0.5 hover:shadow-[0_8px_20px_-10px_rgba(80,70,200,0.35)]",
  ghost: "text-foreground hover:bg-white/70",
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
