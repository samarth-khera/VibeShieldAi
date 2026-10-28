/**
 * Applies a unified diff to in-memory file contents with the same exactness `git apply` uses during
 * verification: every context and removed line must match the original at the hunk's stated position.
 * Used where no git binary exists (the PR path on Vercel), so the committed change is byte-for-byte the
 * change that was verified. Throws on any mismatch instead of guessing.
 */
export class DiffApplyError extends Error {}

type Hunk = { oldStart: number; oldCount: number; newCount: number; lines: string[] };

const remaining = (h: Hunk | null) => {
  if (!h) return false;
  const oldSeen = h.lines.filter((l) => l[0] === " " || l[0] === "-").length;
  const newSeen = h.lines.filter((l) => l[0] === " " || l[0] === "+").length;
  return oldSeen < h.oldCount || newSeen < h.newCount;
};

export function parseDiffByFile(diff: string): Map<string, Hunk[]> {
  const files = new Map<string, Hunk[]>();
  let current: Hunk[] | null = null;
  let hunk: Hunk | null = null;
  const lines = diff.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Inside a hunk, lines are content until its stated line counts are used up (content may start with "--- ").
    if (remaining(hunk) && /^[ +\\-]/.test(line)) {
      hunk!.lines.push(line);
      continue;
    }
    if (line.startsWith("--- ")) {
      const next = lines[i + 1] ?? "";
      if (!next.startsWith("+++ ")) throw new DiffApplyError("Malformed diff header.");
      const oldPath = line.slice(4).trim();
      const newPath = next.slice(4).trim();
      if (!oldPath.startsWith("a/") || !newPath.startsWith("b/") || oldPath.slice(2) !== newPath.slice(2)) {
        throw new DiffApplyError("Only in-place modifications of existing files are supported.");
      }
      const file = newPath.slice(2);
      if (files.has(file)) throw new DiffApplyError(`File appears twice in diff: ${file}`);
      current = [];
      files.set(file, current);
      hunk = null;
      i++;
      continue;
    }
    const header = line.match(/^@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@/);
    if (header) {
      if (!current) throw new DiffApplyError("Hunk before file header.");
      hunk = {
        oldStart: Number(header[1]),
        oldCount: header[2] === undefined ? 1 : Number(header[2]),
        newCount: header[3] === undefined ? 1 : Number(header[3]),
        lines: [],
      };
      current.push(hunk);
      continue;
    }
    if (hunk && line.startsWith("\\")) hunk.lines.push(line);
  }
  if (files.size === 0) throw new DiffApplyError("Diff contains no file changes.");
  for (const [file, hunks] of files) {
    if (hunks.length === 0) throw new DiffApplyError(`No hunks for ${file}.`);
  }
  return files;
}

function applyHunks(original: string, hunks: Hunk[], file: string): string {
  const orig = original.split("\n");
  const out: string[] = [];
  let idx = 0; // 0-based position in orig
  for (const h of hunks) {
    // A zero-length old range means "insert after line oldStart".
    const start = h.oldCount === 0 ? h.oldStart : h.oldStart - 1;
    if (start < idx || start > orig.length) throw new DiffApplyError(`Hunk out of range in ${file}.`);
    while (idx < start) out.push(orig[idx++]);
    let consumed = 0;
    for (const l of h.lines) {
      const body = l.slice(1);
      if (l.startsWith("\\")) continue;
      if (l.startsWith("+")) {
        out.push(body);
        continue;
      }
      if (orig[idx] !== body) throw new DiffApplyError(`Patch does not match ${file} at line ${idx + 1}.`);
      if (l.startsWith(" ")) out.push(body);
      idx++;
      consumed++;
    }
    const produced = h.lines.filter((l) => l[0] === " " || l[0] === "+").length;
    if (consumed !== h.oldCount || produced !== h.newCount) throw new DiffApplyError(`Hunk length mismatch in ${file}.`);
  }
  while (idx < orig.length) out.push(orig[idx++]);
  return out.join("\n");
}

/** Returns the patched contents for each file in the diff; `originals` must hold every one of them. */
export function applyDiffStrict(originals: Map<string, string>, diff: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const [file, hunks] of parseDiffByFile(diff)) {
    const original = originals.get(file);
    if (original === undefined) throw new DiffApplyError(`Missing original for ${file}.`);
    const patched = applyHunks(original, hunks, file);
    if (patched === original) throw new DiffApplyError(`Patch makes no change to ${file}.`);
    result.set(file, patched);
  }
  return result;
}
