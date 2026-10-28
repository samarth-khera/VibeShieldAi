"use client";

import { useState } from "react";
import { Check, Copy, Download, FileCode } from "lucide-react";
import { Button } from "@/components/ui/button";

export function DiffViewer({
  diff,
  patchUrl,
  summary,
}: {
  diff: string;
  patchUrl?: string;
  summary?: string;
}) {
  const [copied, setCopied] = useState(false);

  const lines = diff.split("\n");

  const onCopy = async () => {
    await navigator.clipboard.writeText(diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-line bg-surface-subtle overflow-hidden text-xs font-mono">
      <div className="flex items-center justify-between border-b border-line px-3 py-2 bg-surface">
        <div className="flex items-center gap-2 text-muted">
          <FileCode className="size-4 text-accent" />
          <span className="font-semibold text-foreground">{summary || "Proposed Unified Diff"}</span>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={onCopy} className="h-7 px-2 text-xs">
            {copied ? <Check className="size-3.5 text-accent" /> : <Copy className="size-3.5" />}
            {copied ? "Copied" : "Copy Diff"}
          </Button>
          {patchUrl && (
            <a
              href={patchUrl}
              download
              className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-line hover:border-line-bright hover:bg-surface text-xs font-medium text-foreground transition-colors"
            >
              <Download className="size-3.5" />
              Download .patch
            </a>
          )}
        </div>
      </div>

      <div className="max-h-[350px] overflow-auto p-3 text-[11px] leading-5">
        {lines.map((line, idx) => {
          let lineStyle = "text-muted";
          let bgStyle = "";

          if (line.startsWith("+") && !line.startsWith("+++")) {
            lineStyle = "text-accent";
            bgStyle = "bg-accent/10";
          } else if (line.startsWith("-") && !line.startsWith("---")) {
            lineStyle = "text-sev-critical";
            bgStyle = "bg-sev-critical/10";
          } else if (line.startsWith("@@")) {
            lineStyle = "text-accent-secondary font-bold";
            bgStyle = "bg-surface";
          } else if (line.startsWith("---") || line.startsWith("+++")) {
            lineStyle = "font-bold text-foreground";
          }

          return (
            <div key={idx} className={`flex px-2 py-0.5 rounded ${bgStyle}`}>
              <span className="w-8 shrink-0 select-none text-muted/50">{idx + 1}</span>
              <span className={`select-none w-4 shrink-0 font-bold ${lineStyle}`}>
                {line.startsWith("+") && !line.startsWith("+++")
                  ? "+"
                  : line.startsWith("-") && !line.startsWith("---")
                  ? "-"
                  : " "}
              </span>
              <span className={`whitespace-pre-wrap break-all ${lineStyle}`}>{(/^(---|\+\+\+|@@)/.test(line) ? line : line.slice(1)) || " "}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
