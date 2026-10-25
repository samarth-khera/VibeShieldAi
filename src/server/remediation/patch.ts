import path from "node:path";
import ts from "typescript";
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
 * Recursively checks if an AST binding pattern or identifier binds targetName.
 * Handles:
 * - Simple identifier: (data)
 * - Object destructuring: ({ data }), renamed ({ d: data }), nested ({ a: { data } }), default ({ data = "{}" })
 * - Array destructuring: ([ data ]), nested ([[ data ]]), rest (...data)
 */
function parameterBindsName(nameNode: ts.Node | undefined, target: string): boolean {
  if (!nameNode) return false;
  if (ts.isIdentifier(nameNode)) {
    return nameNode.text === target;
  }
  if (ts.isObjectBindingPattern(nameNode) || ts.isArrayBindingPattern(nameNode)) {
    for (const elem of nameNode.elements) {
      if (ts.isOmittedExpression(elem)) continue;
      if (parameterBindsName(elem.name, target)) return true;
    }
  }
  return false;
}

/**
 * Returns the nearest block-like scope container for a node.
 */
function getScopeContainer(node: ts.Node): ts.Node | null {
  let p: ts.Node | undefined = node.parent;
  while (p) {
    if (
      ts.isBlock(p) ||
      ts.isSourceFile(p) ||
      ts.isModuleBlock(p) ||
      ts.isCaseClause(p) ||
      ts.isDefaultClause(p)
    ) {
      return p;
    }
    p = p.parent;
  }
  return null;
}

/**
 * Strictly verifies whether an eval() argument has defensible, proven JSON data flow
 * using TypeScript AST analysis.
 *
 * Requirements:
 * 1. Declaration identity & uniqueness: Exactly one declaration of cleanVar must exist
 *    in the source file, and it must be a `const` variable declaration.
 * 2. Lexical scope: The declaration's scope container must be an ancestor scope of the eval() call.
 *    Variables declared in sibling/child blocks or outside the enclosing scope are refused.
 * 3. Destructured parameters & inputs: If cleanVar is bound as a parameter (including
 *    object/array destructuring patterns) in any enclosing function, it is refused.
 * 4. Data-flow ordering: The declaration must occur strictly before the eval() call in source order.
 * 5. Intervening assignments: Any assignment (`=`, `+=`, etc.) or mutation (`++`, `--`)
 *    to cleanVar anywhere in the file disqualifies automatic remediation.
 * 6. Initializer validation: Must be initialized with either:
 *    a) Direct call to `JSON.stringify(...)` with no untrusted references in arguments.
 *    b) A static string or no-substitution template literal whose content parses as valid JSON object.
 * 7. Fail-closed: Any syntax error, ambiguous scope, or missing proof routes to manual review.
 */
export function verifyJsonSourceProof(
  sourceContent: string,
  cleanVar: string,
  findingLine?: number | null
): boolean {
  if (!cleanVar || !sourceContent || typeof sourceContent !== "string" || !sourceContent.trim()) {
    return false;
  }

  let sourceFile: ts.SourceFile;
  try {
    sourceFile = ts.createSourceFile("source.ts", sourceContent, ts.ScriptTarget.Latest, true);
  } catch {
    return false;
  }

  // 1. Locate all eval(...) calls that reference cleanVar
  const matchingEvalCalls: ts.CallExpression[] = [];
  function findEvalCalls(node: ts.Node) {
    if (
      (ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "eval") ||
      (ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "eval")
    ) {
      let refsCleanVar = false;
      function checkArg(argNode: ts.Node) {
        if (ts.isIdentifier(argNode) && argNode.text === cleanVar) {
          refsCleanVar = true;
        }
        ts.forEachChild(argNode, checkArg);
      }
      node.arguments.forEach(checkArg);
      if (refsCleanVar) {
        matchingEvalCalls.push(node);
      }
    }
    ts.forEachChild(node, findEvalCalls);
  }
  findEvalCalls(sourceFile);

  if (matchingEvalCalls.length === 0) {
    return false;
  }

  let targetEval = matchingEvalCalls[0];
  if (findingLine != null && matchingEvalCalls.length > 1) {
    let minDiff = Infinity;
    for (const call of matchingEvalCalls) {
      const line = sourceFile.getLineAndCharacterOfPosition(call.getStart(sourceFile)).line + 1;
      const diff = Math.abs(line - findingLine);
      if (diff < minDiff) {
        minDiff = diff;
        targetEval = call;
      }
    }
  }

  // 2. Reject if cleanVar is a parameter in any enclosing function (including destructuring)
  let curr: ts.Node | undefined = targetEval.parent;
  while (curr) {
    if (
      ts.isFunctionDeclaration(curr) ||
      ts.isFunctionExpression(curr) ||
      ts.isArrowFunction(curr) ||
      ts.isMethodDeclaration(curr) ||
      ts.isConstructorDeclaration(curr) ||
      ts.isGetAccessorDeclaration(curr) ||
      ts.isSetAccessorDeclaration(curr)
    ) {
      for (const param of curr.parameters) {
        if (parameterBindsName(param.name, cleanVar)) {
          return false;
        }
      }
    }
    curr = curr.parent;
  }

  // 3. Find declarations of cleanVar across the entire file
  const declarations: ts.Node[] = [];
  function findDecls(node: ts.Node) {
    if (ts.isVariableDeclaration(node)) {
      if (parameterBindsName(node.name, cleanVar)) {
        declarations.push(node);
      }
    } else if (
      (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) &&
      node.name &&
      node.name.text === cleanVar
    ) {
      declarations.push(node);
    } else if (ts.isParameter(node)) {
      if (parameterBindsName(node.name, cleanVar)) {
        declarations.push(node);
      }
    }
    ts.forEachChild(node, findDecls);
  }
  findDecls(sourceFile);

  // Exactly one declaration must exist (rejects 0, multiple, shadowed, or ambiguous declarations)
  if (declarations.length !== 1) {
    return false;
  }

  const decl = declarations[0];
  if (!ts.isVariableDeclaration(decl)) {
    return false;
  }

  // Must be declared with `const`
  const varDeclList = decl.parent;
  if (
    !ts.isVariableDeclarationList(varDeclList) ||
    (varDeclList.flags & ts.NodeFlags.Const) === 0
  ) {
    return false;
  }

  // 4. Source ordering: declaration must precede targetEval
  if (decl.getStart(sourceFile) >= targetEval.getStart(sourceFile)) {
    return false;
  }

  // 5. Scope check: declaration scope container must be an ancestor of targetEval
  const declScope = getScopeContainer(decl);
  if (!declScope) {
    return false;
  }

  let isAncestorScope = false;
  let walk: ts.Node | undefined = targetEval.parent;
  while (walk) {
    if (walk === declScope) {
      isAncestorScope = true;
      break;
    }
    walk = walk.parent;
  }
  if (!isAncestorScope) {
    return false;
  }

  // 6. Check for any assignments or mutations to cleanVar anywhere in the source
  let hasAssignmentOrMutation = false;
  function checkAssignments(node: ts.Node) {
    if (ts.isBinaryExpression(node)) {
      const isAssign =
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken ||
        (node.operatorToken.kind >= ts.SyntaxKind.FirstCompoundAssignment &&
          node.operatorToken.kind <= ts.SyntaxKind.LastCompoundAssignment);
      if (isAssign && parameterBindsName(node.left, cleanVar)) {
        hasAssignmentOrMutation = true;
      }
    } else if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      if (ts.isIdentifier(node.operand) && node.operand.text === cleanVar) {
        hasAssignmentOrMutation = true;
      }
    }
    ts.forEachChild(node, checkAssignments);
  }
  checkAssignments(sourceFile);
  if (hasAssignmentOrMutation) {
    return false;
  }

  // 7. Verify initializer: JSON.stringify(...) or valid JSON string literal
  const init = decl.initializer;
  if (!init) {
    return false;
  }

  const untrustedWord = /^(?:req|request|res|response|params|query|body|input|payload|script|code|cmd|command|user|process|window|document|fetch|argv|eval)$/i;

  // Case A: JSON.stringify(...)
  if (
    ts.isCallExpression(init) &&
    ts.isPropertyAccessExpression(init.expression) &&
    ts.isIdentifier(init.expression.expression) &&
    init.expression.expression.text === "JSON" &&
    ts.isIdentifier(init.expression.name) &&
    init.expression.name.text === "stringify"
  ) {
    let hasUntrusted = false;
    function checkUntrusted(node: ts.Node) {
      if (ts.isIdentifier(node) && untrustedWord.test(node.text)) {
        hasUntrusted = true;
      }
      ts.forEachChild(node, checkUntrusted);
    }
    init.arguments.forEach(checkUntrusted);
    return !hasUntrusted;
  }

  // Case B: Static string literal or template literal that parses as valid JSON object
  if (ts.isStringLiteral(init) || ts.isNoSubstitutionTemplateLiteral(init)) {
    try {
      const parsed = JSON.parse(init.text);
      return typeof parsed === "object" && parsed !== null;
    } catch {
      return false;
    }
  }

  return false;
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

    // Strictly verify declaration identity, lexical scope, data-flow ordering,
    // and absence of intervening assignments via TypeScript AST analysis.
    const isVerifiedJsonInput = verifyJsonSourceProof(sourceContent, cleanVar, finding.startLine);

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
