import path from "node:path";
import ts from "typescript";
import type { LlmProvider } from "../ai/client";
import { redactText } from "../scanners/redact";
import type { FindingRecord } from "../job-store";
import type { NormalizedFinding } from "../scanners/types";
import { classifyRemediationEligibility, resolveFindingFixedVersion } from "./eligibility";

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
 * Applies a unified diff string to a string file content in memory.
 */
export function applyUnifiedDiffString(original: string, diff: string): string {
  const origLines = original.split("\n");
  const diffLines = diff.split("\n");

  const result: string[] = [];
  let origIdx = 0;
  let inHunk = false;

  for (let i = 0; i < diffLines.length; i++) {
    const line = diffLines[i];
    if (line.startsWith("@@")) {
      const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) {
        const startLine = Number.parseInt(match[1], 10) - 1;
        while (origIdx < startLine && origIdx < origLines.length) {
          result.push(origLines[origIdx++]);
        }
        inHunk = true;
      }
      continue;
    }

    if (!inHunk) continue;

    if (line.startsWith("-")) {
      origIdx++;
    } else if (line.startsWith("+")) {
      result.push(line.slice(1));
    } else if (line.startsWith(" ")) {
      result.push(line.slice(1));
      origIdx++;
    }
  }

  while (origIdx < origLines.length) {
    result.push(origLines[origIdx++]);
  }

  return result.join("\n");
}

export type ManifestTransformResult = {
  updatedContent: string;
  oldLine: string;
  newLine: string;
  lineIndex: number;
  oldVersion: string;
};

/**
 * Updates a declared dependency version in a Python requirements.txt manifest,
 * strictly preserving comments, indentation, version operators, extras, and environment markers.
 */
export function updatePythonRequirementsContent(
  content: string,
  targetPkgName: string,
  fixedVersion: string,
): ManifestTransformResult | null {
  const lines = content.split("\n");
  const normalize = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");
  const targetNorm = normalize(targetPkgName);

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Separate inline comment
    let mainPart = rawLine;
    let commentPart = "";
    const commentMatch = rawLine.match(/^([^#]*)(#.*)$/);
    if (commentMatch) {
      mainPart = commentMatch[1];
      commentPart = commentMatch[2];
    }

    // Separate environment marker (; ...)
    let reqPart = mainPart;
    let markerPart = "";
    const markerIdx = mainPart.indexOf(";");
    if (markerIdx !== -1) {
      reqPart = mainPart.slice(0, markerIdx);
      markerPart = mainPart.slice(markerIdx);
    }

    // Match dependency name, optional extras, operator, and version constraint
    const reqMatch = reqPart.match(/^(\s*)([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(\[[^\]]*\])?(\s*)(==|~=|>=|<=|!=|===|<|>)(.*)$/);
    if (!reqMatch) continue;

    const [, indent, pkgName, extras = "", spacing, op, versionRest] = reqMatch;
    if (normalize(pkgName) !== targetNorm) continue;

    const oldVersion = versionRest.trim();
    let newOp = op;
    if (op === "==" || op === "===" || op === "~=") {
      newOp = op;
    } else if (op === "<=" || op === "<") {
      newOp = "<=";
    } else if (op === ">=") {
      newOp = "==";
    }

    const versionSpacing = versionRest.match(/^\s*/)?.[0] || "";
    const versionTrailingSpace = versionRest.match(/\s*$/)?.[0] || "";
    const newLine = `${indent}${pkgName}${extras}${spacing}${newOp}${versionSpacing}${fixedVersion}${versionTrailingSpace}${markerPart}${commentPart}`;

    const newLines = [...lines];
    newLines[i] = newLine;

    return {
      updatedContent: newLines.join("\n"),
      oldLine: rawLine,
      newLine,
      lineIndex: i,
      oldVersion,
    };
  }

  return null;
}

/**
 * Updates a declared dependency version in a Node.js package.json manifest,
 * strictly preserving existing prefixes (^, ~, >=), formatting, indentation, and structure.
 */
export function updatePackageJsonContent(
  content: string,
  targetPkgName: string,
  fixedVersion: string,
): ManifestTransformResult | null {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }

  const depSections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
  let foundSection: string | null = null;
  let currentDeclaredVersion: string | null = null;

  for (const sec of depSections) {
    const secObj = parsed[sec];
    if (secObj && typeof secObj === "object" && typeof (secObj as Record<string, unknown>)[targetPkgName] === "string") {
      foundSection = sec;
      currentDeclaredVersion = (secObj as Record<string, unknown>)[targetPkgName] as string;
      break;
    }
  }

  if (!foundSection || !currentDeclaredVersion) {
    return null;
  }

  const prefixMatch = currentDeclaredVersion.match(/^(\^|~|>=|<=|>|<)?/);
  const prefix = prefixMatch?.[1] || "";
  const newDeclaredVersion = `${prefix}${fixedVersion}`;

  const lines = content.split("\n");
  const targetKeyQuote = `"${targetPkgName}"`;
  const staticPairRegex = /^(\s*"[^"]+"\s*:\s*)"([^"]+)"(.*)$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.includes(targetKeyQuote)) continue;

    const m = line.match(staticPairRegex);
    if (m) {
      const colonIndex = line.indexOf(":");
      const keyPart = line.slice(0, colonIndex).trim();
      if (keyPart === targetKeyQuote) {
        const newLine = `${m[1]}"${newDeclaredVersion}"${m[3]}`;
        const newLines = [...lines];
        newLines[i] = newLine;
        return {
          updatedContent: newLines.join("\n"),
          oldLine: line,
          newLine,
          lineIndex: i,
          oldVersion: currentDeclaredVersion,
        };
      }
    }
  }

  return null;
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
 * Unwraps parenthesized expressions, type assertions, as expressions,
 * non-null expressions, and satisfies expressions.
 */
function getUnwrappedExpression(expr: ts.Expression): ts.Expression {
  let curr = expr;
  while (curr) {
    if (
      ts.isParenthesizedExpression(curr) ||
      ts.isAsExpression(curr) ||
      ts.isTypeAssertionExpression(curr) ||
      ts.isNonNullExpression(curr) ||
      ts.isSatisfiesExpression(curr)
    ) {
      curr = curr.expression;
    } else {
      break;
    }
  }
  return curr;
}

/**
 * Resolves a variable name to its single const VariableDeclaration in the file,
 * returning null if there are 0, multiple, mutated, non-const, or destructured declarations.
 */
function findSingleConstVariableDeclaration(
  varName: string,
  sourceFile: ts.SourceFile
): ts.VariableDeclaration | null {
  const declarations: ts.Node[] = [];
  function findDecls(node: ts.Node) {
    if (ts.isVariableDeclaration(node)) {
      if (parameterBindsName(node.name, varName)) {
        declarations.push(node);
      }
    } else if (
      (ts.isFunctionDeclaration(node) ||
        ts.isClassDeclaration(node) ||
        ts.isEnumDeclaration(node) ||
        ts.isInterfaceDeclaration(node) ||
        ts.isTypeAliasDeclaration(node) ||
        ts.isModuleDeclaration(node)) &&
      node.name &&
      ts.isIdentifier(node.name) &&
      node.name.text === varName
    ) {
      declarations.push(node);
    } else if (ts.isParameter(node)) {
      if (parameterBindsName(node.name, varName)) {
        declarations.push(node);
      }
    } else if (ts.isImportClause(node)) {
      if (node.name && node.name.text === varName) {
        declarations.push(node);
      }
      if (node.namedBindings) {
        if (ts.isNamespaceImport(node.namedBindings) && node.namedBindings.name.text === varName) {
          declarations.push(node);
        }
        if (ts.isNamedImports(node.namedBindings)) {
          for (const spec of node.namedBindings.elements) {
            if (spec.name.text === varName) {
              declarations.push(spec);
            }
          }
        }
      }
    }
    ts.forEachChild(node, findDecls);
  }
  findDecls(sourceFile);

  if (declarations.length !== 1) {
    return null;
  }

  const decl = declarations[0];
  if (!ts.isVariableDeclaration(decl)) {
    return null;
  }

  if (!ts.isIdentifier(decl.name) || decl.name.text !== varName) {
    return null;
  }

  const varDeclList = decl.parent;
  if (
    !ts.isVariableDeclarationList(varDeclList) ||
    (varDeclList.flags & ts.NodeFlags.Const) === 0
  ) {
    return null;
  }

  let hasMutation = false;
  function checkAssign(node: ts.Node) {
    if (ts.isBinaryExpression(node)) {
      const isAssign =
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken ||
        (node.operatorToken.kind >= ts.SyntaxKind.FirstCompoundAssignment &&
          node.operatorToken.kind <= ts.SyntaxKind.LastCompoundAssignment);
      if (isAssign && parameterBindsName(node.left, varName)) {
        hasMutation = true;
      }
    } else if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      if (ts.isIdentifier(node.operand) && node.operand.text === varName) {
        hasMutation = true;
      }
    }
    ts.forEachChild(node, checkAssign);
  }
  checkAssign(sourceFile);
  if (hasMutation) {
    return null;
  }

  return decl;
}

interface ProxyResolution {
  isProxy: boolean;
  target?: ts.Expression;
  handler?: ts.Expression;
}

/**
 * Resolves whether an expression is a `new Proxy(target, handler)` constructor call or `Proxy.revocable`,
 * directly or through simple const variable aliases.
 */
function resolveProxy(
  expr: ts.Expression,
  sourceFile?: ts.SourceFile,
  visited = new Set<ts.Node>()
): ProxyResolution {
  const unwrapped = getUnwrappedExpression(expr);
  if (visited.has(unwrapped)) {
    return { isProxy: false };
  }
  visited.add(unwrapped);

  if (ts.isNewExpression(unwrapped)) {
    const callee = getUnwrappedExpression(unwrapped.expression);
    const isProxy =
      (ts.isIdentifier(callee) && callee.text === "Proxy") ||
      (ts.isPropertyAccessExpression(callee) &&
        callee.name.text === "Proxy" &&
        isGlobalObject(callee.expression, sourceFile, visited)) ||
      isGlobalPropertyAccess(callee, "Proxy", sourceFile);
    if (isProxy && unwrapped.arguments && unwrapped.arguments.length >= 1) {
      return {
        isProxy: true,
        target: unwrapped.arguments[0],
        handler: unwrapped.arguments[1],
      };
    }
  }

  // Also support Proxy.revocable(target, handler)
  if (ts.isCallExpression(unwrapped)) {
    const callee = getUnwrappedExpression(unwrapped.expression);
    const isRevocable =
      (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) &&
      getAccessedPropertyName(callee) === "revocable" &&
      ((ts.isIdentifier(callee.expression) && callee.expression.text === "Proxy") ||
        isGlobalPropertyAccess(callee.expression, "Proxy", sourceFile));
    if (isRevocable && unwrapped.arguments.length >= 1) {
      return {
        isProxy: true,
        target: unwrapped.arguments[0],
        handler: unwrapped.arguments[1],
      };
    }
  }

  // Also support pair.proxy where pair = Proxy.revocable(target, handler)
  if (ts.isPropertyAccessExpression(unwrapped) || ts.isElementAccessExpression(unwrapped)) {
    const prop = getAccessedPropertyName(unwrapped);
    if (prop === "proxy") {
      const inner = resolveProxy(unwrapped.expression, sourceFile, visited);
      if (inner.isProxy) {
        return inner;
      }
    }
  }

  if (ts.isIdentifier(unwrapped) && sourceFile) {
    const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
    if (decl && decl.initializer) {
      return resolveProxy(decl.initializer, sourceFile, visited);
    }
  }

  return { isProxy: false };
}

/**
 * Checks whether a proxy handler expression is an empty object literal with no traps.
 */
function isTransparentProxyHandler(
  handler: ts.Expression | undefined,
  sourceFile?: ts.SourceFile,
  visited = new Set<ts.Node>()
): boolean {
  if (!handler) return true;
  const unwrapped = getUnwrappedExpression(handler);
  if (visited.has(unwrapped)) return false;
  visited.add(unwrapped);

  if (ts.isObjectLiteralExpression(unwrapped)) {
    return unwrapped.properties.length === 0;
  }
  if (ts.isIdentifier(unwrapped) && sourceFile) {
    const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
    if (decl && decl.initializer) {
      return isTransparentProxyHandler(decl.initializer, sourceFile, visited);
    }
  }
  return false;
}

/**
 * Checks whether an expression can be statically proven to be a safe, locally defined
 * non-global object literal (e.g. `{ ... }` or a single `const` initialized with an object literal).
 */
function isStaticallyProvenLocalNonGlobalObject(
  expr: ts.Expression,
  sourceFile?: ts.SourceFile,
  visited = new Set<ts.Node>()
): boolean {
  const unwrapped = getUnwrappedExpression(expr);
  if (visited.has(unwrapped)) {
    return false;
  }
  visited.add(unwrapped);

  if (ts.isObjectLiteralExpression(unwrapped)) {
    return true;
  }

  if (ts.isIdentifier(unwrapped) && sourceFile) {
    if (["globalThis", "window", "global", "self", "JSON"].includes(unwrapped.text)) {
      return false;
    }
    const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
    if (decl && decl.initializer) {
      return isStaticallyProvenLocalNonGlobalObject(decl.initializer, sourceFile, visited);
    }
  }

  return false;
}

/**
 * Checks if an expression resolves to a known global root (globalThis, window, global, self),
 * including direct or variable-aliased `new Proxy(globalRoot, ...)` wrappers.
 */
function isGlobalObject(
  expr: ts.Expression,
  sourceFile?: ts.SourceFile,
  visited = new Set<ts.Node>()
): boolean {
  const unwrapped = getUnwrappedExpression(expr);
  if (visited.has(unwrapped)) {
    return false;
  }
  visited.add(unwrapped);

  if (ts.isIdentifier(unwrapped)) {
    if (["globalThis", "window", "global", "self"].includes(unwrapped.text)) {
      return true;
    }
    if (sourceFile) {
      const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
      if (decl && decl.initializer && isGlobalObject(decl.initializer, sourceFile, visited)) {
        return true;
      }
    }
    return false;
  }

  if (ts.isPropertyAccessExpression(unwrapped) || ts.isElementAccessExpression(unwrapped)) {
    const prop = getAccessedPropertyName(unwrapped);
    if (prop && ["globalThis", "window", "global", "self"].includes(prop)) {
      if (isGlobalObject(unwrapped.expression, sourceFile, visited)) {
        return true;
      }
    }
  }

  // Handle direct or aliased new Proxy(globalRoot, ...)
  const proxy = resolveProxy(unwrapped, sourceFile, new Set<ts.Node>());
  if (proxy.isProxy && proxy.target) {
    return isGlobalObject(proxy.target, sourceFile, visited);
  }

  return false;
}

/**
 * Checks if a property name node matches the target string (e.g. "JSON").
 * Handles identifiers, string literals, no-substitution template literals,
 * computed property names like ["JSON"] or [`JSON`], and single const identifiers.
 */
function isPropertyNamed(
  nameNode: ts.Node | undefined,
  target: string,
  sourceFile?: ts.SourceFile
): boolean {
  if (!nameNode) return false;
  const unwrapped = ts.isExpression(nameNode as ts.Node)
    ? getUnwrappedExpression(nameNode as ts.Expression)
    : nameNode;
  if (ts.isIdentifier(unwrapped)) {
    if (unwrapped.text === target) return true;
    if (sourceFile) {
      const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
      if (decl && decl.initializer) {
        return isPropertyNamed(decl.initializer, target, sourceFile);
      }
    }
  }
  if (ts.isStringLiteral(unwrapped) && unwrapped.text === target) return true;
  if (ts.isNoSubstitutionTemplateLiteral(unwrapped) && unwrapped.text === target) return true;
  if (ts.isComputedPropertyName(unwrapped)) {
    const expr = getUnwrappedExpression(unwrapped.expression);
    return isPropertyNamed(expr, target, sourceFile);
  }
  if (ts.isArrayLiteralExpression(unwrapped) && unwrapped.elements.length === 1) {
    const elem = getUnwrappedExpression(unwrapped.elements[0]);
    return isPropertyNamed(elem, target, sourceFile);
  }
  return false;
}

/**
 * Checks if a property key is a statically proven literal that is NOT "JSON".
 */
function isStaticNonJsonLiteral(node: ts.Node | undefined, sourceFile?: ts.SourceFile): boolean {
  if (!node) return false;
  const unwrapped = ts.isExpression(node as ts.Node)
    ? getUnwrappedExpression(node as ts.Expression)
    : node;
  if (ts.isNumericLiteral(unwrapped)) {
    return true;
  }
  if (unwrapped.kind === ts.SyntaxKind.TrueKeyword || unwrapped.kind === ts.SyntaxKind.FalseKeyword) {
    return true;
  }
  if (ts.isStringLiteral(unwrapped) || ts.isNoSubstitutionTemplateLiteral(unwrapped)) {
    return unwrapped.text !== "JSON";
  }
  if (ts.isIdentifier(unwrapped) && sourceFile) {
    const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
    if (decl && decl.initializer) {
      return isStaticNonJsonLiteral(decl.initializer, sourceFile);
    }
  }
  return false;
}

/**
 * Extracts accessed property name from a property access or element access expression.
 * Returns the property name string, or null if it cannot be determined statically.
 */
function getAccessedPropertyName(expr: ts.PropertyAccessExpression | ts.ElementAccessExpression): string | null {
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text;
  }
  if (ts.isElementAccessExpression(expr)) {
    const arg = getUnwrappedExpression(expr.argumentExpression);
    if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
      return arg.text;
    }
  }
  return null;
}

/**
 * Checks whether an expression accesses targetProp on a global object
 * (e.g. globalThis.JSON, window["JSON"], global['JSON'], self[`JSON`]).
 */
function isGlobalPropertyAccess(expr: ts.Expression, targetProp: string, sourceFile?: ts.SourceFile): boolean {
  const unwrapped = getUnwrappedExpression(expr);
  if (ts.isPropertyAccessExpression(unwrapped) || ts.isElementAccessExpression(unwrapped)) {
    const prop = getAccessedPropertyName(unwrapped);
    if (prop === targetProp && isGlobalObject(unwrapped.expression, sourceFile)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether an expression references JSON or a property on JSON,
 * or globalThis.JSON / window["JSON"] / etc., including direct or aliased Proxy wrappers.
 */
function referencesJsonTarget(
  expr: ts.Expression,
  sourceFile?: ts.SourceFile,
  visited = new Set<ts.Node>()
): boolean {
  let curr: ts.Expression | undefined = expr;
  while (curr) {
    const unwrapped = getUnwrappedExpression(curr);
    if (visited.has(unwrapped)) {
      break;
    }
    visited.add(unwrapped);

    if (ts.isIdentifier(unwrapped)) {
      if (unwrapped.text === "JSON") {
        return true;
      }
      if (sourceFile) {
        const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
        if (decl && decl.initializer && referencesJsonTarget(decl.initializer, sourceFile, visited)) {
          return true;
        }
      }
    }
    if (isGlobalPropertyAccess(unwrapped, "JSON", sourceFile)) {
      return true;
    }

    // Handle direct or aliased new Proxy(JSON, ...)
    const proxy = resolveProxy(unwrapped, sourceFile, new Set<ts.Node>());
    if (proxy.isProxy && proxy.target) {
      if (referencesJsonTarget(proxy.target, sourceFile, visited)) {
        return true;
      }
    }

    if (ts.isPropertyAccessExpression(unwrapped) || ts.isElementAccessExpression(unwrapped)) {
      curr = unwrapped.expression;
    } else {
      break;
    }
  }
  return false;
}

/**
 * Evaluates whether an expression passed as a source to Object.assign() or descriptors
 * to Object.defineProperties() can be statically proven NOT to define or modify "JSON".
 * Fails closed (returns false) if the source contains "JSON", spreads of unproven objects,
 * unresolved computed properties, or expressions that cannot be statically verified.
 */
function isStaticallyProvenNotToModifyJson(
  expr: ts.Expression,
  sourceFile: ts.SourceFile,
  visited: Set<ts.Node> = new Set<ts.Node>()
): boolean {
  const unwrapped = getUnwrappedExpression(expr);
  if (visited.has(unwrapped)) {
    return false; // circular or already seen
  }
  visited.add(unwrapped);

  // Primitive literals without own enumerable properties
  if (
    unwrapped.kind === ts.SyntaxKind.NullKeyword ||
    unwrapped.kind === ts.SyntaxKind.UndefinedKeyword ||
    unwrapped.kind === ts.SyntaxKind.TrueKeyword ||
    unwrapped.kind === ts.SyntaxKind.FalseKeyword ||
    ts.isNumericLiteral(unwrapped)
  ) {
    return true;
  }

  // Handle Proxy source: safe only if target is proven safe and handler is transparent
  const proxy = resolveProxy(unwrapped, sourceFile, new Set<ts.Node>());
  if (proxy.isProxy) {
    if (proxy.target && isTransparentProxyHandler(proxy.handler)) {
      return isStaticallyProvenNotToModifyJson(proxy.target, sourceFile, visited);
    }
    return false;
  }

  // Object literal expression: verify every property
  if (ts.isObjectLiteralExpression(unwrapped)) {
    for (const prop of unwrapped.properties) {
      if (
        ts.isPropertyAssignment(prop) ||
        ts.isShorthandPropertyAssignment(prop) ||
        ts.isMethodDeclaration(prop) ||
        ts.isGetAccessorDeclaration(prop) ||
        ts.isSetAccessorDeclaration(prop)
      ) {
        if (isPropertyNamed(prop.name, "JSON", sourceFile)) {
          return false;
        }
        if (ts.isComputedPropertyName(prop.name)) {
          const compExpr = getUnwrappedExpression(prop.name.expression);
          if (isPropertyNamed(compExpr, "JSON", sourceFile)) {
            return false;
          }
          if (!isStaticNonJsonLiteral(compExpr, sourceFile)) {
            // Unresolved computed property -> cannot assume safe
            return false;
          }
        } else if (
          ts.isIdentifier(prop.name) ||
          ts.isStringLiteral(prop.name) ||
          ts.isNoSubstitutionTemplateLiteral(prop.name)
        ) {
          if (prop.name.text === "JSON") {
            return false;
          }
        } else {
          return false;
        }
      } else if (ts.isSpreadAssignment(prop)) {
        // Inspect spread properties: do not assume safe unless expression is statically proven
        if (!isStaticallyProvenNotToModifyJson(prop.expression, sourceFile, visited)) {
          return false;
        }
      } else {
        return false;
      }
    }
    return true;
  }

  // Identifier: resolve to its single const declaration in sourceFile
  if (ts.isIdentifier(unwrapped)) {
    if (unwrapped.text === "JSON") {
      return false;
    }
    const decl = findSingleConstVariableDeclaration(unwrapped.text, sourceFile);
    if (!decl || !decl.initializer) {
      return false;
    }
    return isStaticallyProvenNotToModifyJson(decl.initializer, sourceFile, visited);
  }

  return false;
}

/**
 * Verifies whether the identifier "JSON" is shadowed, overridden, imported,
 * or mutated anywhere in the source file.
 * Returns true if "JSON" is shadowed or overridden (i.e. cannot be proven to be
 * the genuine built-in global object), and false if it remains unshadowed and clean.
 */
function hasJsonShadowOrOverride(sourceFile: ts.SourceFile): boolean {
  let shadowedOrOverridden = false;

  function walk(node: ts.Node) {
    if (shadowedOrOverridden) return;

    // 1. Variable declarations: const JSON = ..., let { JSON } = ...
    if (ts.isVariableDeclaration(node)) {
      if (parameterBindsName(node.name, "JSON")) {
        shadowedOrOverridden = true;
        return;
      }
    }

    // 2. Function, Class, Enum, Module/Namespace, Interface, Type alias declarations
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isClassDeclaration(node) ||
      ts.isEnumDeclaration(node) ||
      ts.isModuleDeclaration(node) ||
      ts.isInterfaceDeclaration(node) ||
      ts.isTypeAliasDeclaration(node)
    ) {
      if (node.name && ts.isIdentifier(node.name) && node.name.text === "JSON") {
        shadowedOrOverridden = true;
        return;
      }
    }

    // 3. Parameters in functions, arrows, methods, accessors, catch clauses
    if (ts.isParameter(node)) {
      if (parameterBindsName(node.name, "JSON")) {
        shadowedOrOverridden = true;
        return;
      }
    }
    if (ts.isCatchClause(node) && node.variableDeclaration) {
      if (parameterBindsName(node.variableDeclaration.name, "JSON")) {
        shadowedOrOverridden = true;
        return;
      }
    }

    // 4. Imports: default, named, namespace, import equals
    if (ts.isImportClause(node)) {
      if (node.name && node.name.text === "JSON") {
        shadowedOrOverridden = true;
        return;
      }
      if (node.namedBindings) {
        if (ts.isNamespaceImport(node.namedBindings) && node.namedBindings.name.text === "JSON") {
          shadowedOrOverridden = true;
          return;
        }
        if (ts.isNamedImports(node.namedBindings)) {
          for (const spec of node.namedBindings.elements) {
            if (spec.name.text === "JSON") {
              shadowedOrOverridden = true;
              return;
            }
          }
        }
      }
    }
    if (ts.isImportEqualsDeclaration(node)) {
      if (node.name.text === "JSON") {
        shadowedOrOverridden = true;
        return;
      }
    }

    // 5. Export specifiers: export { custom as JSON }
    if (ts.isExportSpecifier(node)) {
      if (node.name.text === "JSON") {
        shadowedOrOverridden = true;
        return;
      }
    }

    // 6. Assignments and mutations: JSON = ..., JSON.stringify = ..., globalThis["JSON"] = ..., window["JSON"] = ...
    if (ts.isBinaryExpression(node)) {
      const isAssign =
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken ||
        (node.operatorToken.kind >= ts.SyntaxKind.FirstCompoundAssignment &&
          node.operatorToken.kind <= ts.SyntaxKind.LastCompoundAssignment);
      if (isAssign) {
        if (referencesJsonTarget(node.left, sourceFile)) {
          shadowedOrOverridden = true;
          return;
        }
        if (ts.isPropertyAccessExpression(node.left) || ts.isElementAccessExpression(node.left)) {
          const propName = getAccessedPropertyName(node.left);
          if (propName === "JSON" || !propName) {
            const objProxy = resolveProxy(node.left.expression, sourceFile);
            if (objProxy.isProxy) {
              const isTransparent = isTransparentProxyHandler(objProxy.handler);
              const isProvenLocal = objProxy.target
                ? isStaticallyProvenLocalNonGlobalObject(objProxy.target, sourceFile)
                : false;
              if (!isProvenLocal || !isTransparent) {
                shadowedOrOverridden = true;
                return;
              }
            }
          }
        }
      }
    }

    // 7. Delete expressions: delete JSON.stringify, delete globalThis["JSON"], delete window.JSON
    if (ts.isDeleteExpression(node)) {
      if (referencesJsonTarget(node.expression, sourceFile)) {
        shadowedOrOverridden = true;
        return;
      }
      if (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) {
        const propName = getAccessedPropertyName(node.expression);
        if (propName === "JSON" || !propName) {
          const objProxy = resolveProxy(node.expression.expression, sourceFile);
          if (objProxy.isProxy) {
            const isTransparent = isTransparentProxyHandler(objProxy.handler);
            const isProvenLocal = objProxy.target
              ? isStaticallyProvenLocalNonGlobalObject(objProxy.target, sourceFile)
              : false;
            if (!isProvenLocal || !isTransparent) {
              shadowedOrOverridden = true;
              return;
            }
          }
        }
      }
    }

    // 8. Object / Reflect manipulation calls:
    // Object.defineProperty(globalThis, "JSON", ...)
    // Reflect.defineProperty(globalThis, "JSON", ...)
    // Reflect.set(globalThis, "JSON", ...)
    // Object.defineProperties(globalThis, ...) when defining JSON
    // Object.assign(globalThis, { JSON: ... })
    // and direct target mutations: Object.assign(JSON, ...), Object.defineProperty(JSON, ...), Reflect.set(JSON, ...)
    if (ts.isCallExpression(node)) {
      const callee = getUnwrappedExpression(node.expression);
      if (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) {
        const calleeProp = getAccessedPropertyName(callee);
        const calleeObj = getUnwrappedExpression(callee.expression);
        const isObjectOrReflect =
          (ts.isIdentifier(calleeObj) && (calleeObj.text === "Object" || calleeObj.text === "Reflect")) ||
          isGlobalPropertyAccess(calleeObj, "Object", sourceFile) ||
          isGlobalPropertyAccess(calleeObj, "Reflect", sourceFile);

        if (
          isObjectOrReflect &&
          (calleeProp === "defineProperty" ||
            calleeProp === "defineProperties" ||
            calleeProp === "assign" ||
            calleeProp === "set")
        ) {
          const firstArg = node.arguments[0];
          if (firstArg) {
            // Direct target is JSON itself or global property access (e.g. globalThis.JSON, window["JSON"])
            if (referencesJsonTarget(firstArg, sourceFile)) {
              shadowedOrOverridden = true;
              return;
            }

            // Target is a global root (globalThis, window, global, self, or Proxy wrapping one)
            if (isGlobalObject(firstArg, sourceFile)) {
              if (calleeProp === "defineProperty" || calleeProp === "set") {
                const secondArg = node.arguments[1];
                if (secondArg) {
                  if (isPropertyNamed(secondArg, "JSON", sourceFile)) {
                    shadowedOrOverridden = true;
                    return;
                  }
                  // If secondArg cannot be proven to be a known static non-JSON property,
                  // dynamic global integrity cannot be proven reliably; fail closed.
                  if (!isStaticNonJsonLiteral(secondArg, sourceFile)) {
                    shadowedOrOverridden = true;
                    return;
                  }
                }
              } else if (calleeProp === "defineProperties") {
                const secondArg = node.arguments[1];
                if (!secondArg || !isStaticallyProvenNotToModifyJson(secondArg, sourceFile)) {
                  shadowedOrOverridden = true;
                  return;
                }
              } else if (calleeProp === "assign") {
                const sourceArgs = node.arguments.slice(1);
                for (const sourceArg of sourceArgs) {
                  const exprToCheck = ts.isSpreadElement(sourceArg) ? sourceArg.expression : sourceArg;
                  if (!isStaticallyProvenNotToModifyJson(exprToCheck, sourceFile)) {
                    shadowedOrOverridden = true;
                    return;
                  }
                }
              }
            }

            // Target is a Proxy whose target or mutation behavior cannot be established safely
            const proxy = resolveProxy(firstArg, sourceFile);
            if (proxy.isProxy) {
              const isTransparent = isTransparentProxyHandler(proxy.handler);
              const isProvenLocalObject = proxy.target
                ? isStaticallyProvenLocalNonGlobalObject(proxy.target, sourceFile)
                : false;

              // If proxy target is not a proven local object OR handler has traps/untrusted behavior
              if (!isProvenLocalObject || !isTransparent) {
                if (calleeProp === "defineProperty" || calleeProp === "set") {
                  const secondArg = node.arguments[1];
                  if (!secondArg || isPropertyNamed(secondArg, "JSON", sourceFile) || !isStaticNonJsonLiteral(secondArg, sourceFile)) {
                    shadowedOrOverridden = true;
                    return;
                  }
                } else if (calleeProp === "defineProperties") {
                  const secondArg = node.arguments[1];
                  if (!secondArg || !isStaticallyProvenNotToModifyJson(secondArg, sourceFile)) {
                    shadowedOrOverridden = true;
                    return;
                  }
                } else if (calleeProp === "assign") {
                  const sourceArgs = node.arguments.slice(1);
                  for (const sourceArg of sourceArgs) {
                    const exprToCheck = ts.isSpreadElement(sourceArg) ? sourceArg.expression : sourceArg;
                    if (!isStaticallyProvenNotToModifyJson(exprToCheck, sourceFile)) {
                      shadowedOrOverridden = true;
                      return;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    ts.forEachChild(node, walk);
  }

  walk(sourceFile);
  return shadowedOrOverridden;
}

/**
 * Strictly verifies whether an eval() argument has defensible, proven JSON data flow
 * using TypeScript AST analysis.
 *
 * Requirements:
 * 1. Parser Diagnostics: Any syntax or parse error in the source file fails closed.
 * 2. Unambiguous target call: The eval() call referencing cleanVar must be resolved unambiguously
 *    to findingLine (or be the sole matching call if no line specified). Multiple ambiguous calls fail closed.
 * 3. Declaration identity & uniqueness: Exactly one declaration of cleanVar must exist
 *    in the source file, and it must be a `const` variable declaration.
 * 4. Lexical scope: The declaration's scope container must be an ancestor scope of the eval() call.
 *    Variables declared in sibling/child blocks or outside the enclosing scope are refused.
 * 5. Destructured parameters & inputs: If cleanVar is bound as a parameter (including
 *    object/array destructuring patterns) in any enclosing function, it is refused.
 * 6. Data-flow ordering: The declaration must occur strictly before the eval() call in source order.
 * 7. Intervening assignments: Any assignment (`=`, `+=`, etc.) or mutation (`++`, `--`)
 *    to cleanVar anywhere in the file disqualifies automatic remediation.
 * 8. Initializer validation: Must be initialized with either:
 *    a) Direct call to `JSON.stringify(...)` where the global JSON binding is unshadowed and clean,
 *       and has no untrusted references in arguments.
 *    b) A static string or no-substitution template literal whose content parses as valid JSON object.
 * 9. Fail-closed: Any syntax error, ambiguous scope, shadowed binding, or missing proof routes to manual review.
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

  // 1. Explicitly inspect parser diagnostics; fail closed on any syntax or parse errors
  const parseDiagnostics = (sourceFile as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
  if (Array.isArray(parseDiagnostics) && parseDiagnostics.length > 0) {
    return false;
  }

  // 2. Locate all eval(...) calls that reference cleanVar
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

  // Target call resolution: must resolve unambiguously
  let targetEval: ts.CallExpression;
  if (matchingEvalCalls.length === 1) {
    targetEval = matchingEvalCalls[0];
    if (findingLine != null) {
      const line = sourceFile.getLineAndCharacterOfPosition(targetEval.getStart(sourceFile)).line + 1;
      if (line !== findingLine) {
        return false;
      }
    }
  } else {
    // Multiple matching calls: findingLine must be specified and must resolve to exactly one call on that line
    if (findingLine == null) {
      return false;
    }
    const matchingOnLine = matchingEvalCalls.filter((call) => {
      const line = sourceFile.getLineAndCharacterOfPosition(call.getStart(sourceFile)).line + 1;
      return line === findingLine;
    });
    if (matchingOnLine.length !== 1) {
      return false;
    }
    targetEval = matchingOnLine[0];
  }

  // 3. Reject if cleanVar is a parameter in any enclosing function (including destructuring)
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

  // 4. Find declarations of cleanVar across the entire file
  const declarations: ts.Node[] = [];
  function findDecls(node: ts.Node) {
    if (ts.isVariableDeclaration(node)) {
      if (parameterBindsName(node.name, cleanVar)) {
        declarations.push(node);
      }
    } else if (
      (ts.isFunctionDeclaration(node) ||
        ts.isClassDeclaration(node) ||
        ts.isEnumDeclaration(node) ||
        ts.isInterfaceDeclaration(node) ||
        ts.isTypeAliasDeclaration(node) ||
        ts.isModuleDeclaration(node)) &&
      node.name &&
      ts.isIdentifier(node.name) &&
      node.name.text === cleanVar
    ) {
      declarations.push(node);
    } else if (ts.isParameter(node)) {
      if (parameterBindsName(node.name, cleanVar)) {
        declarations.push(node);
      }
    } else if (ts.isImportClause(node)) {
      if (node.name && node.name.text === cleanVar) {
        declarations.push(node);
      }
      if (node.namedBindings) {
        if (ts.isNamespaceImport(node.namedBindings) && node.namedBindings.name.text === cleanVar) {
          declarations.push(node);
        }
        if (ts.isNamedImports(node.namedBindings)) {
          for (const spec of node.namedBindings.elements) {
            if (spec.name.text === cleanVar) {
              declarations.push(spec);
            }
          }
        }
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

  // 5. Source ordering: declaration must precede targetEval
  if (decl.getStart(sourceFile) >= targetEval.getStart(sourceFile)) {
    return false;
  }

  // 6. Scope check: declaration scope container must be an ancestor of targetEval
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

  // 7. Check for any assignments or mutations to cleanVar anywhere in the source
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

  // 8. Verify initializer: JSON.stringify(...) or valid JSON string literal
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
    // Fail closed if JSON identifier is shadowed or overridden anywhere in the file
    if (hasJsonShadowOrOverride(sourceFile)) {
      return false;
    }

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
  const { finding, llmProvider, sourceContent, commitSha } = params;
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
  const isDependencyFinding =
    finding.packageInfo != null ||
    finding.scanner === "osv-scanner" ||
    finding.category === "Dependencies" ||
    finding.category === "vulnerability";

  if (isDependencyFinding) {
    const pkg = finding.packageInfo as { name?: string; fixedVersion?: string; version?: string; ecosystem?: string } | null;
    const pkgName = pkg?.name;
    const fixedVersion = resolveFindingFixedVersion(finding);

    if (!pkgName || !fixedVersion) {
      throw new Error(
        `Cannot generate automated dependency patch: No confirmed fixed version available for ${pkgName || finding.title || "dependency"}. Manual review is required.`
      );
    }

    if (!sourceContent || typeof sourceContent !== "string" || !sourceContent.trim()) {
      throw new Error(
        `Cannot generate automated patch for ${cleanFile}: Manifest source content is unavailable from scanned commit ${commitSha}. Manual review is required.`
      );
    }

    const fileName = path.basename(cleanFile).toLowerCase();
    const isPythonReq =
      /requirements.*\.txt$/i.test(fileName) ||
      fileName === "requirements.txt" ||
      fileName === "requirements.in";
    const isPackageJson = fileName === "package.json";

    if (!isPythonReq && !isPackageJson) {
      throw new Error(
        `Automated patch generation is not supported for manifest format "${fileName}". Manual code review is required.`
      );
    }

    let transformResult: ManifestTransformResult | null = null;
    if (isPythonReq) {
      transformResult = updatePythonRequirementsContent(sourceContent, pkgName, fixedVersion);
    } else if (isPackageJson) {
      transformResult = updatePackageJsonContent(sourceContent, pkgName, fixedVersion);
    }

    if (!transformResult) {
      throw new Error(
        `Cannot generate automated patch for ${cleanFile}: Dependency "${pkgName}" declaration was not found in manifest. Manual review is required.`
      );
    }

    const lineNum = transformResult.lineIndex + 1;
    const diff = [
      `--- a/${cleanFile}`,
      `+++ b/${cleanFile}`,
      `@@ -${lineNum},1 +${lineNum},1 @@`,
      `-${transformResult.oldLine}`,
      `+${transformResult.newLine}`,
      "",
    ].join("\n");

    const validation = validateUnifiedDiff(diff);
    if (!validation.valid) throw new Error(validation.error);

    // Verify patch applies cleanly to sourceContent
    const applied = applyUnifiedDiffString(sourceContent, diff);
    if (applied !== transformResult.updatedContent) {
      throw new Error(`Patch verification failed: diff does not apply cleanly to ${cleanFile}. Manual review is required.`);
    }

    return {
      unifiedDiff: diff,
      patchSummary: `Bump ${pkgName} from ${transformResult.oldVersion || pkg?.version || "current version"} to secure release ${fixedVersion} in ${cleanFile}`,
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
