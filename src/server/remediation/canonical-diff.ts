import { applyDiffStrict, DiffApplyError, parseDiffByFile } from "./strict-apply";

/**
 * Canonical unified diffs with real context lines.
 *
 * Generated hunks used to carry no context (`@@ -5,1 +5,1 @@`). Standard `git apply` anchors such a
 * hunk to the end of the file, so a downloaded patch failed for any change that was not on the last
 * line. Every remediation diff is therefore re-rendered from the exact before/after file contents at
 * the scanned commit, with up to three context lines, and accepted only if applying it strictly
 * reproduces exactly the same files.
 */
export const DIFF_CONTEXT_LINES = 3;

const NO_EOL = "\\ No newline at end of file";
/** Marks the last line of a file without a trailing newline, so an EOL change is a real change. */
const NO_EOL_TAG = "\u0000no-eol";
/** Above this many cells the middle section is emitted as delete-then-insert instead of a minimal diff. */
const MAX_LCS_CELLS = 4_000_000;

type Op = { t: " " | "-" | "+"; line: string };

function toLines(text: string): string[] {
  if (text === "") return [];
  const eol = text.endsWith("\n");
  const lines = (eol ? text.slice(0, -1) : text).split("\n");
  if (!eol) lines[lines.length - 1] += NO_EOL_TAG;
  return lines;
}

function diffLines(a: string[], b: string[]): Op[] {
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const A = a.slice(pre, a.length - suf);
  const B = b.slice(pre, b.length - suf);
  const middle: Op[] = [];
  if (A.length * B.length > MAX_LCS_CELLS) {
    for (const l of A) middle.push({ t: "-", line: l });
    for (const l of B) middle.push({ t: "+", line: l });
  } else {
    // LCS table over the (small) changed region.
    const w = B.length + 1;
    const dp = new Uint32Array((A.length + 1) * w);
    for (let i = A.length - 1; i >= 0; i--) {
      for (let j = B.length - 1; j >= 0; j--) {
        dp[i * w + j] = A[i] === B[j] ? dp[(i + 1) * w + j + 1] + 1 : Math.max(dp[(i + 1) * w + j], dp[i * w + j + 1]);
      }
    }
    let i = 0;
    let j = 0;
    const dels: Op[] = [];
    const adds: Op[] = [];
    const flush = () => {
      middle.push(...dels.splice(0), ...adds.splice(0));
    };
    while (i < A.length || j < B.length) {
      if (i < A.length && j < B.length && A[i] === B[j]) {
        flush();
        middle.push({ t: " ", line: A[i] });
        i++;
        j++;
      } else if (j < B.length && (i === A.length || dp[i * w + j + 1] >= dp[(i + 1) * w + j])) {
        adds.push({ t: "+", line: B[j++] });
      } else {
        dels.push({ t: "-", line: A[i++] });
      }
    }
    flush();
  }
  return [
    ...a.slice(0, pre).map((line): Op => ({ t: " ", line })),
    ...middle,
    ...a.slice(a.length - suf).map((line): Op => ({ t: " ", line })),
  ];
}

const emit = (op: Op): string[] =>
  op.line.endsWith(NO_EOL_TAG) ? [`${op.t}${op.line.slice(0, -NO_EOL_TAG.length)}`, NO_EOL] : [`${op.t}${op.line}`];

/** One file's section of a unified diff (`--- a/` / `+++ b/` headers and hunks), or "" if unchanged. */
export function renderFileDiff(file: string, original: string, patched: string, context = DIFF_CONTEXT_LINES): string {
  const ops = diffLines(toLines(original), toLines(patched));
  const changes = ops.flatMap((op, idx) => (op.t === " " ? [] : [idx]));
  if (changes.length === 0) return "";

  // Group changes whose surrounding context would touch or overlap into one hunk.
  const groups: [number, number][] = [];
  for (const idx of changes) {
    const last = groups[groups.length - 1];
    if (last && idx - last[1] <= 2 * context) last[1] = idx;
    else groups.push([idx, idx]);
  }

  // Line numbers before each op (1-based numbering is derived when printing).
  const oldBefore: number[] = [];
  const newBefore: number[] = [];
  let o = 0;
  let n = 0;
  for (const op of ops) {
    oldBefore.push(o);
    newBefore.push(n);
    if (op.t !== "+") o++;
    if (op.t !== "-") n++;
  }

  const out = [`--- a/${file}`, `+++ b/${file}`];
  for (const [first, last] of groups) {
    const start = Math.max(0, first - context);
    const end = Math.min(ops.length - 1, last + context);
    const slice = ops.slice(start, end + 1);
    const oldCount = slice.filter((op) => op.t !== "+").length;
    const newCount = slice.filter((op) => op.t !== "-").length;
    const oldStart = oldCount === 0 ? oldBefore[start] : oldBefore[start] + 1;
    const newStart = newCount === 0 ? newBefore[start] : newBefore[start] + 1;
    out.push(`@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`);
    for (const op of slice) out.push(...emit(op));
  }
  return out.join("\n") + "\n";
}

/**
 * Re-renders `diff` against the real files at the scanned commit with context lines. Throws
 * DiffApplyError if the diff does not apply strictly to `originals`, or if the canonical diff would
 * not reproduce exactly the same result (fail closed: no patch is better than an inexact one).
 */
export function canonicalizeDiff(originals: Map<string, string>, diff: string, context = DIFF_CONTEXT_LINES): string {
  const patched = applyDiffStrict(originals, diff);
  const files = [...parseDiffByFile(diff).keys()];
  const canonical = files.map((f) => renderFileDiff(f, originals.get(f)!, patched.get(f)!, context)).join("");

  const check = applyDiffStrict(originals, canonical);
  if (check.size !== patched.size || [...patched].some(([f, content]) => check.get(f) !== content)) {
    throw new DiffApplyError("The canonical diff does not reproduce the generated change exactly.");
  }
  return canonical;
}

/** Files a diff modifies, in diff order (the keys `applyDiffStrict` needs originals for). */
export function diffFiles(diff: string): string[] {
  return [...parseDiffByFile(diff).keys()];
}
