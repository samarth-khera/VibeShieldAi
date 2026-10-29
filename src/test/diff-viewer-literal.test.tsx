// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { DiffViewer } from "@/components/report/diff-viewer";

afterEach(() => cleanup());

const DIFF = [
  "--- a/requirements.txt",
  "+++ b/requirements.txt",
  "@@ -1,4 +1,4 @@",
  " flask>=2.0",
  "-pytest>=8.0",
  "+pytest==9.0.3",
  " if (a != b && c <= d && e === f) return x => y; // a -> b",
  "",
].join("\n");

const css = readFileSync(path.join(process.cwd(), "src/app/globals.css"), "utf8");
const rule = css.match(/\.code-literal\s*\{([^}]*)\}/)?.[1] ?? "";

describe("diff viewer shows operators literally", () => {
  it("renders the exact characters of the stored diff", () => {
    render(<DiffViewer diff={DIFF} />);
    const text = screen.getByTestId("diff-viewer").textContent ?? "";
    for (const op of [">=", "==", "!=", "<=", "===", "=>", "->"]) expect(text).toContain(op);
    expect(text).toContain("pytest>=8.0");
    expect(text).toContain("pytest==9.0.3");
    expect(text).not.toMatch(/[≥≤≠⇒→]/);
  });

  it("the viewer opts out of ligatures and contextual alternates", () => {
    render(<DiffViewer diff={DIFF} />);
    expect(screen.getByTestId("diff-viewer").classList.contains("code-literal")).toBe(true);
    expect(rule).toMatch(/font-variant-ligatures:\s*none/);
    for (const feature of ['"liga" 0', '"calt" 0', '"clig" 0', '"dlig" 0']) expect(rule).toContain(feature);
  });

  it("both the Auto-Fix preview and the pull-request confirmation use this viewer", () => {
    for (const file of ["src/components/report/remediation-panel.tsx", "src/components/report/github-pr-panel.tsx"]) {
      const src = readFileSync(path.join(process.cwd(), file), "utf8");
      expect(src).toMatch(/import \{ DiffViewer \} from "\.\/diff-viewer"/);
      expect(src).toMatch(/<DiffViewer\b/);
    }
  });
});
