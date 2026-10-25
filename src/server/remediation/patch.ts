import path from "node:path";
import type { LlmProvider } from "../ai/client";
import { redactText } from "../scanners/redact";
import type { FindingRecord } from "../job-store";
import type { NormalizedFinding } from "../scanners/types";
import { classifyRemediationEligibility } from "./eligibility";

export type PatchValidationResult = {
  valid: boolean;
  affectedFiles: string[];
  error?: string;
};

const MAX_DIFF_BYTES = 50 * 1024; // 50KB max diff
const MAX_DIFF_FILES = 5;

const FORBIDDEN_PATHS = [
  ".git",
  ".github",
  ".env",
  "node_modules",
  "/etc",
  "/bin",
  "/usr",
];

/**
 * Validates that a proposed unified diff is strictly bounded, structurally safe,
 * and contains no path traversals or target paths outside the repository.
 */
export function validateUnifiedDiff(diff: string): PatchValidationResult {
  if (!diff || typeof diff !== "string") {
    return { valid: false, affectedFiles: [], error: "Empty or invalid diff content." };
  }

  if (Buffer.byteLength(diff, "utf8") > MAX_DIFF_BYTES) {
    return { valid: false, affectedFiles: [], error: "Diff exceeds maximum allowed size (50KB)." };
  }

  const affectedFilesSet = new Set<string>();
  const lines = diff.split("\n");
  let hasValidHeaders = false;

  for (const line of lines) {
    if (line.startsWith("--- a/") || line.startsWith("+++ b/")) {
      hasValidHeaders = true;
      const rawPath = line.slice(6).trim();

      // Skip /dev/null for creations/deletions
      if (rawPath === "/dev/null" || rawPath === "dev/null") continue;

      // Anti-traversal checks
      if (path.isAbsolute(rawPath) || /^[a-zA-Z]:/.test(rawPath)) {
        return { valid: false, affectedFiles: [], error: `Absolute path forbidden in diff: ${rawPath}` };
      }

      const normalized = path.normalize(rawPath).replace(/\\/g, "/");
      const parts = normalized.split("/").filter(Boolean);

      if (parts.includes("..") || normalized.startsWith("../") || normalized === "..") {
        return { valid: false, affectedFiles: [], error: `Path traversal forbidden in diff: ${rawPath}` };
      }

      // Check forbidden directories and files (e.g. .git, .env*, node_modules)
      for (const forbidden of FORBIDDEN_PATHS) {
        if (
          parts[0] === forbidden ||
          parts.some((p) => p === forbidden || p.startsWith(".env")) ||
          normalized.startsWith(`${forbidden}/`) ||
          normalized.includes(`/${forbidden}/`)
        ) {
          return { valid: false, affectedFiles: [], error: `Modification of protected path forbidden: ${rawPath}` };
        }
      }

      affectedFilesSet.add(normalized);
    }
  }

  if (!hasValidHeaders || affectedFilesSet.size === 0) {
    return { valid: false, affectedFiles: [], error: "Diff must contain standard unified diff headers (--- a/ and +++ b/)." };
  }

  if (affectedFilesSet.size > MAX_DIFF_FILES) {
    return { valid: false, affectedFiles: [], error: `Diff affects too many files (${affectedFilesSet.size} > max ${MAX_DIFF_FILES}).` };
  }

  return { valid: true, affectedFiles: Array.from(affectedFilesSet) };
}

/**
 * Generates an automated, user-reviewable patch for an eligible security finding.
 */
export async function generateRemediationPatch(params: {
  finding: FindingRecord | NormalizedFinding;
  scanJobId: string;
  commitSha: string;
  llmProvider?: LlmProvider;
  sourceContent?: string;
}): Promise<{
  unifiedDiff: string;
  patchSummary: string;
  affectedFiles: string[];
  eligibility: ReturnType<typeof classifyRemediationEligibility>;
}> {
  const { finding, llmProvider, sourceContent } = params;
  const eligibility = classifyRemediationEligibility(finding);

  if (!eligibility.canAutoFix) {
    throw new Error(`Finding is not eligible for automated patching: ${eligibility.reason}`);
  }

  const cleanFile = path.normalize(finding.filePath || "src/index.ts").replace(/\\/g, "/");

  // 1. Dependency advisory automated bump
  if (finding.packageInfo != null) {
    const pkg = finding.packageInfo as { name?: string; fixedVersion?: string; version?: string } | null;
    const pkgName = pkg?.name || "dependency";
    const oldVer = pkg?.version || "1.0.0";
    const newVer = pkg?.fixedVersion || "1.0.1";

    const diff = [
      `--- a/${cleanFile}`,
      `+++ b/${cleanFile}`,
      `@@ -1,3 +1,3 @@`,
      `-"${pkgName}": "${oldVer}"`,
      `+"${pkgName}": "^${newVer}"`,
      "",
    ].join("\n");

    const validation = validateUnifiedDiff(diff);
    if (!validation.valid) throw new Error(validation.error);

    return {
      unifiedDiff: diff,
      patchSummary: `Bump ${pkgName} from ${oldVer} to secure patched release ${newVer}`,
      affectedFiles: validation.affectedFiles,
      eligibility,
    };
  }

  // 2. If an LLM provider is configured, prompt for a surgical unified diff
  if (llmProvider && llmProvider.isConfigured()) {
    const sanitizedEvidence = redactText((finding.redactedEvidence || "").slice(0, 1000));
    const systemPrompt = `You are an expert security engineer generating a surgical, minimal unified git diff to resolve a security vulnerability.
Output ONLY the unified diff starting with "--- a/" and "+++ b/".
Do not include any Markdown fences, explanations, backticks or commentary.
Never change business logic or introduce new dependencies unless required.
Never embed fake or dummy secrets.
Target File: ${cleanFile}
Rule: ${finding.ruleId}
Title: ${finding.title}`;

    const userPrompt = `<UNTRUSTED_FINDING_CONTEXT>
File: ${cleanFile}
Lines: ${finding.startLine ?? 1} to ${finding.endLine ?? 1}
Evidence:
${sanitizedEvidence || "// Vulnerable code"}
Remediation Advice:
${finding.remediation || "Fix the reported security vulnerability."}
</UNTRUSTED_FINDING_CONTEXT>

Generate a minimal, exact unified diff applying the fix for ${cleanFile}.`;

    try {
      const rawOutput = await llmProvider.generateText({
        system: systemPrompt,
        userPrompt,
        maxTokens: 1000,
        timeoutMs: Number.parseInt(process.env.OLLAMA_TIMEOUT_MS || process.env.AI_REQUEST_TIMEOUT_MS || "120000", 10),
      });

      // Extract unified diff lines from response
      const diffText = rawOutput
        .replace(/```(?:diff)?/g, "")
        .replace(/```/g, "")
        .trim();

      const validation = validateUnifiedDiff(diffText);
      if (validation.valid) {
        return {
          unifiedDiff: diffText,
          patchSummary: `Surgical security patch for ${finding.ruleId} in ${cleanFile}`,
          affectedFiles: validation.affectedFiles,
          eligibility,
        };
      }
    } catch {
      // Fallback to deterministic localized template if LLM fails or outputs malformed diff
    }
  }

  // 3. Deterministic code transformation for known localized patterns with actual source evidence
  const evidence = (finding.redactedEvidence || "").trimEnd();
  const rule = (finding.ruleId || "").toLowerCase();

  // Pattern A: eval() to JSON.parse() ONLY when verified JSON preconditions are established
  if (evidence && (rule.includes("eval") || rule.includes("code-execution"))) {
    if (/\beval\s*\(/.test(evidence)) {
      // 1. Strict Fail-Closed Policy: Any indicator of arbitrary script / dynamic code execution
      // immediately requires manual review. Generic keywords (data, payload, input) CANNOT override this.
      const indicatesArbitraryScriptExecution =
        /\beval\s*\(\s*(?:script|code|js|program|command|cmd|func|fn|snippet|handler|action|statement|expr|expression)\b/i.test(evidence) ||
        /\b(?:script|runtime|function|expression|arbitrary code|code execution|command execution|dynamic execution|shell)\b/i.test(finding.description || "") ||
        /\b(?:script|arbitrary code|code execution|command execution|expression)\b/i.test(finding.title || "");

      if (indicatesArbitraryScriptExecution) {
        throw new Error(
          `Cannot safely replace eval() with JSON.parse() where arbitrary JavaScript execution semantics must be preserved for ${finding.ruleId}. Manual code review is required.`
        );
      }

      // 2. Verified Preconditions: Keyword presence in title/description alone NEVER establishes that
      // replacing eval() with JSON.parse() is semantically correct.
      // Automatic transformation is permitted ONLY when actual source context proves input is JSON text.

      // Precondition Check A: Classic pre-JSON.parse deserialization idiom:
      // e.g. eval("(" + str + ")") or eval('(' + data + ')') or eval(`(${str})`)
      const classicIdiomMatch = evidence.match(
        /\beval\s*\(\s*(?:["']\(["']\s*\+\s*([^)]+?)\s*\+\s*["']\)["']|`\(\$\{(.+?)\}\)`)\s*\)/
      );

      // Precondition Check B: Surrounding source context + explicit JSON-named variable:
      // The argument must be explicitly named as JSON text (e.g., jsonData, jsonStr, rawJson, jsonText)
      // AND sourceContent must be provided and confirm JSON parsing context.
      const evalArgMatch = evidence.match(/\beval\s*\(([^)]+)\)/);
      const evalArg = evalArgMatch ? evalArgMatch[1].trim() : "";
      const isExplicitJsonVariable = /^(?:raw_?json|json_?(?:str(?:ing)?|data|text|payload|content)?)$/i.test(evalArg);

      const sourceContextConfirmsJson = Boolean(
        sourceContent &&
        (
          /\b(?:parseJson|readJson|loadJson|parseConfig|deserializeJson|application\/json|JSON\.stringify)\b/i.test(sourceContent) ||
          /\b(?:json|parse)\b/i.test(sourceContent)
        )
      );

      let securedEvidence: string | null = null;

      if (classicIdiomMatch) {
        const innerArg = (classicIdiomMatch[1] || classicIdiomMatch[2] || "").trim();
        securedEvidence = evidence.replace(
          /\beval\s*\(\s*(?:["']\(["']\s*\+\s*[^)]+?\s*\+\s*["']\)["']|`\(\$\{[^}]+\}\)`)\s*\)/g,
          `JSON.parse(${innerArg})`
        );
      } else if (isExplicitJsonVariable && sourceContextConfirmsJson) {
        securedEvidence = evidence.replace(/\beval\s*\(([^)]+)\)/g, "JSON.parse($1)");
      } else {
        // Insufficient source context, generic keywords only, or missing source verification
        throw new Error(
          `Cannot automatically replace eval() with JSON.parse() without verified JSON source context for ${finding.ruleId}. Manual code review is required.`
        );
      }

      if (securedEvidence && securedEvidence !== evidence) {
        const start = finding.startLine ?? 1;
        const diffLines = [
          `--- a/${cleanFile}`,
          `+++ b/${cleanFile}`,
          `@@ -${start},1 +${start},1 @@`,
          `-${evidence}`,
          `+${securedEvidence}`,
          "",
        ].join("\n");

        const validation = validateUnifiedDiff(diffLines);
        if (validation.valid) {
          return {
            unifiedDiff: diffLines,
            patchSummary: `Replace unsafe dynamic eval() with safe JSON.parse() in ${cleanFile}`,
            affectedFiles: validation.affectedFiles,
            eligibility,
          };
        }
      }
    }
  }

  // Pattern B: Missing Security Headers
  if (evidence && (rule.includes("header") || rule.includes("nosniff"))) {
    const start = finding.startLine ?? 1;
    const diffLines = [
      `--- a/${cleanFile}`,
      `+++ b/${cleanFile}`,
      `@@ -${start},1 +${start},2 @@`,
      ` ${evidence}`,
      `+  res.headers.set('X-Content-Type-Options', 'nosniff');`,
      "",
    ].join("\n");

    const validation = validateUnifiedDiff(diffLines);
    if (validation.valid) {
      return {
        unifiedDiff: diffLines,
        patchSummary: `Add X-Content-Type-Options: nosniff header in ${cleanFile}`,
        affectedFiles: validation.affectedFiles,
        eligibility,
      };
    }
  }

  // If no safe deterministic rule exists and no LLM generated a valid diff,
  // we MUST NOT generate comment-only or fabricated placeholders.
  throw new Error(
    `Cannot generate automated patch for ${finding.ruleId} without active AI assistance or exact source evidence. Manual code review is required.`
  );
}
