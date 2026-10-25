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
  const evidence = (finding.redactedEvidence || "").trimEnd();
  const rule = (finding.ruleId || "").toLowerCase();

  // 1. Mandatory Security Policy Gate for Dynamic Code Execution / eval()
  // This gate MUST execute before dependency bump, LLM, or other patch generation paths.
  // A structurally valid LLM-generated diff or generic keyword presence CANNOT bypass this gate.
  const isDynamicCodeExecution =
    rule.includes("eval") ||
    rule.includes("code-execution") ||
    rule.includes("dynamic-code") ||
    rule.includes("script-execution") ||
    /\beval\s*\(/.test(evidence) ||
    /\beval\b/i.test(finding.title || "") ||
    /\beval\b/i.test(finding.description || "") ||
    /\barbitrary code execution\b/i.test(finding.title || "") ||
    /\barbitrary code execution\b/i.test(finding.description || "") ||
    /\bdynamic code execution\b/i.test(finding.title || "") ||
    /\bdynamic code execution\b/i.test(finding.description || "");

  if (isDynamicCodeExecution) {
    if (!/\beval\s*\(/.test(evidence)) {
      throw new Error(
        `Cannot generate automated patch for dynamic code execution finding ${finding.ruleId} without exact source evidence. Manual code review is required.`
      );
    }

    // 1A. Strict Fail-Closed Check: Any indicator of arbitrary script / dynamic code execution
    // immediately requires manual review. Generic keywords (data, payload, input) CANNOT override this.
    const indicatesArbitraryScriptExecution =
      /\beval\s*\(\s*(?:script|code|js|program|command|cmd|func|fn|snippet|handler|action|statement)\b/i.test(evidence) ||
      /\b(?:arbitrary (?:code|script)|code execution|command execution|dynamic execution|shell|untrusted script)\b/i.test(finding.description || "") ||
      /\b(?:arbitrary (?:code|script)|code execution|command execution|dynamic execution|untrusted script)\b/i.test(finding.title || "");

    if (indicatesArbitraryScriptExecution) {
      throw new Error(
        `Cannot safely replace eval() with JSON.parse() where arbitrary JavaScript execution semantics must be preserved for ${finding.ruleId}. Manual code review is required.`
      );
    }

    // 1B. Require source-context proof: Wrapper expressions alone are NOT proof of JSON semantics.
    // If source context is missing, ambiguous, or inconsistent, refuse automatic remediation.
    if (!sourceContent || typeof sourceContent !== "string" || !sourceContent.trim()) {
      throw new Error(
        `Cannot automatically replace eval() with JSON.parse() without verified JSON source context for ${finding.ruleId}. Manual code review is required.`
      );
    }

    const classicIdiomMatch = evidence.match(
      /\beval\s*\(\s*(?:["']\(["']\s*\+\s*([^)]+?)\s*\+\s*["']\)["']|`\(\$\{(.+?)\}\)`)\s*\)/
    );
    const directEvalMatch = evidence.match(/\beval\s*\(([^)]+)\)/);

    const rawArg = (classicIdiomMatch ? (classicIdiomMatch[1] || classicIdiomMatch[2]) : directEvalMatch?.[1])?.trim() || "";
    const cleanVar = rawArg.replace(/^[(\s]+|[)\s]+$/g, "").trim();

    if (!cleanVar || !/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(cleanVar)) {
      throw new Error(
        `Cannot automatically replace eval() with JSON.parse() without verified JSON source context for ${finding.ruleId}. Manual code review is required.`
      );
    }

    if (/\b(?:script|code|js|program|command|cmd|func|fn|snippet|handler|action|statement|expr|expression)\b/i.test(cleanVar)) {
      throw new Error(
        `Cannot safely replace eval() with JSON.parse() where arbitrary JavaScript execution semantics must be preserved for ${finding.ruleId}. Manual code review is required.`
      );
    }

    // Locate local context lines around the finding in sourceContent
    const sourceLines = sourceContent.split("\n");
    const startLine = finding.startLine ?? 1;
    let actualLineIdx = Math.max(0, Math.min(sourceLines.length - 1, startLine - 1));

    if (!sourceLines[actualLineIdx]?.includes("eval")) {
      const foundIdx = sourceLines.findIndex((line) => line.includes("eval"));
      if (foundIdx !== -1) {
        actualLineIdx = foundIdx;
      }
    }

    // Isolate immediate local function/block context (max 10 lines before/after).
    // This strictly prevents unrelated occurrences of json or parse elsewhere in the file from being treated as proof.
    const localStart = Math.max(0, actualLineIdx - 10);
    const localEnd = Math.min(sourceLines.length, actualLineIdx + 11);
    const localContext = sourceLines.slice(localStart, localEnd).join("\n");

    const isExplicitJsonVar = /^(?:raw_?json|json_?(?:str(?:ing)?|data|text|payload|content)?)$/i.test(cleanVar);

    // Verify evidence about the relevant input variable and its data flow
    const localFunctionDenotesJson =
      /\bfunction\s+[a-zA-Z0-9_]*(?:json|config)[a-zA-Z0-9_]*\s*\(/i.test(localContext) ||
      /\b(?:parseJson|readJson|loadJson|parseConfig|deserializeJson|parseLegacyJson)\b/i.test(localContext);

    const cleanVarLines = localContext
      .split("\n")
      .filter((line) => line.includes(cleanVar));

    const localDataFlowShowsJson =
      cleanVarLines.some((line) => /\b(?:json|config|application\/json)\b/i.test(line)) ||
      /\bapplication\/json\b/i.test(localContext) ||
      /\/\/\s*(?:parse|incoming|verify|read)\s+(?:incoming\s+)?json/i.test(localContext) ||
      /\/\*[\s\S]*?(?:json text|json payload|json string|json data)[\s\S]*?\*\//i.test(localContext);

    const localShowsArbitraryExecution =
      /\bfunction\s+(?:run|execute|eval|exec|do|handle)[A-Za-z0-9_]*(?:payload|code|script|action|command)/i.test(localContext);

    const isVerifiedJsonInput =
      !localShowsArbitraryExecution &&
      ((isExplicitJsonVar && (localFunctionDenotesJson || localDataFlowShowsJson)) ||
       (!isExplicitJsonVar && localFunctionDenotesJson && localDataFlowShowsJson));

    if (!isVerifiedJsonInput) {
      throw new Error(
        `Cannot automatically replace eval() with JSON.parse() without verified JSON source context for ${finding.ruleId}. Manual code review is required.`
      );
    }

    // Build the deterministic replacement
    let securedEvidence: string | null = null;
    if (classicIdiomMatch) {
      securedEvidence = evidence.replace(
        /\beval\s*\(\s*(?:["']\(["']\s*\+\s*[^)]+?\s*\+\s*["']\)["']|`\(\$\{[^}]+\}\)`)\s*\)/g,
        `JSON.parse(${cleanVar})`
      );
    } else {
      securedEvidence = evidence.replace(/\beval\s*\(([^)]+)\)/g, `JSON.parse(${cleanVar})`);
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

    throw new Error(
      `Cannot automatically replace eval() with JSON.parse() without verified JSON source context for ${finding.ruleId}. Manual code review is required.`
    );
  }

  // 2. Dependency advisory automated bump (for non-eval findings)
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

  // 3. If an LLM provider is configured, prompt for a surgical unified diff (for non-eval findings)
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

  // 4. Deterministic code transformation for known localized patterns with actual source evidence
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
