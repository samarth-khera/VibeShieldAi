export type RemediationEligibilityType = "safe" | "potentially_breaking" | "unsuitable";

export interface RemediationEligibility {
  eligibility: RemediationEligibilityType;
  canAutoFix: boolean;
  requiresRotation: boolean;
  reason: string;
  warnings: string[];
  /**
   * Only the server can decide (e.g. a vulnerable package reported in a lockfile: fixable only if
   * the package manager can update it on its own). The UI must not count it as eligible yet.
   */
  decidedOnPreview?: boolean;
}

const LOCKFILE_RE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/;

/**
 * Typed single-source-of-truth helper for resolving a finding's fixed version.
 * Checks packageInfo.fixedVersion, metadata.fixedVersion, or any typed package representation.
 */
export function resolveFindingFixedVersion(finding: {
  packageInfo?: unknown;
  metadata?: unknown;
}): string | null {
  if (finding.packageInfo && typeof finding.packageInfo === "object") {
    const pkg = finding.packageInfo as { fixedVersion?: unknown };
    if (typeof pkg.fixedVersion === "string" && pkg.fixedVersion.trim().length > 0) {
      return pkg.fixedVersion.trim();
    }
  }
  if (finding.metadata && typeof finding.metadata === "object") {
    const meta = finding.metadata as { fixedVersion?: unknown };
    if (typeof meta.fixedVersion === "string" && meta.fixedVersion.trim().length > 0) {
      return meta.fixedVersion.trim();
    }
  }
  return null;
}

/**
 * Universal classification helper used both server-side and client-side.
 */
export function classifyRemediationEligibility(finding: {
  category?: string | null;
  ruleId?: string | null;
  title?: string | null;
  filePath?: string | null;
  packageInfo?: unknown;
  metadata?: unknown;
}): RemediationEligibility {
  const category = (finding.category || "").toLowerCase();
  const ruleId = (finding.ruleId || "").toLowerCase();
  const title = (finding.title || "").toLowerCase();

  // 1. Secrets are NEVER automatically patched with code edits
  if (category.includes("secret") || ruleId.includes("secret") || ruleId.includes("token") || ruleId.includes("key")) {
    return {
      eligibility: "unsuitable",
      canAutoFix: false,
      requiresRotation: true,
      reason: "Leaked credential detected. Removing secrets from code does not revoke them with providers or erase them from Git history.",
      warnings: [
        "IMMEDIATE ACTION REQUIRED: Revoke and rotate the compromised credential in the external provider's console.",
        "Erasing the secret string from this commit does NOT protect you: attackers can still extract it from Git history.",
        "Automated code patching is prohibited for secrets to prevent introducing dummy credentials into production.",
      ],
    };
  }

  // 2. Dependencies
  if (category.includes("dependenc") || finding.packageInfo != null) {
    const fixedVersion = resolveFindingFixedVersion(finding);
    const hasFixed = Boolean(fixedVersion);

    if (hasFixed && LOCKFILE_RE.test(finding.filePath || "")) {
      return {
        eligibility: "potentially_breaking",
        canAutoFix: true,
        requiresRotation: false,
        decidedOnPreview: true,
        reason: `A fixed release (${fixedVersion}) exists. VibeShield can apply it only if the package manager can update this package without changing others; that is checked against the lockfile when you generate the preview.`,
        warnings: [
          "Upgrading library versions may introduce breaking changes or transitive dependency conflicts.",
          "Run the project's automated test suite before merging this remediation.",
        ],
      };
    }

    if (hasFixed) {
      return {
        eligibility: "potentially_breaking",
        canAutoFix: true,
        requiresRotation: false,
        reason: `Automated version bump to patched release ${fixedVersion}.`,
        warnings: [
          "Upgrading library versions may introduce breaking changes or transitive dependency conflicts.",
          "Run the project's automated test suite before merging this remediation.",
        ],
      };
    }

    return {
      eligibility: "unsuitable",
      canAutoFix: false,
      requiresRotation: false,
      reason: "No upstream patched version is currently published for this vulnerability advisory.",
      warnings: [
        "Monitor the vulnerability advisory for an upstream security release.",
        "Consider replacing the vulnerable library with an active, maintained alternative.",
      ],
    };
  }

  // 3. Code Analysis
  const isAuthOrCrypto =
    ruleId.includes("auth") ||
    ruleId.includes("jwt") ||
    ruleId.includes("crypto") ||
    ruleId.includes("password") ||
    ruleId.includes("permission") ||
    ruleId.includes("rbac") ||
    ruleId.includes("session") ||
    title.includes("authorization") ||
    title.includes("authentication");

  if (isAuthOrCrypto) {
    return {
      eligibility: "unsuitable",
      canAutoFix: false,
      requiresRotation: false,
      reason: "Authentication, authorization and cryptographic logic require deep runtime context and manual security review.",
      warnings: [
        "Security-critical authentication mechanisms should not be modified automatically.",
        "Have a senior security engineer review and author this patch manually.",
      ],
    };
  }

  const isLocalizedSafe =
    ruleId.includes("header") ||
    ruleId.includes("cors") ||
    ruleId.includes("innerhtml") ||
    ruleId.includes("eval") ||
    ruleId.includes("nosniff") ||
    ruleId.includes("xss") ||
    ruleId.includes("regex") ||
    title.includes("security header") ||
    title.includes("dangerouslysetinnerhtml");

  if (isLocalizedSafe) {
    return {
      eligibility: "safe",
      canAutoFix: true,
      requiresRotation: false,
      reason: "Localized unsafe pattern with unambiguous secure replacement.",
      warnings: [],
    };
  }

  // Default code analysis: potentially breaking
  return {
    eligibility: "potentially_breaking",
    canAutoFix: true,
    requiresRotation: false,
    reason: "Code modification proposed. Requires review to ensure business logic remains unaffected.",
    warnings: ["Review the exact diff to confirm application behavior is preserved."],
  };
}

/** What the report shows for a finding: the server's stored decision when there is one. */
export type FindingFixStatus = {
  kind: "fix_ready" | "decided_on_preview" | "manual_review" | "not_eligible" | "rotate_credential" | "safe" | "potentially_breaking";
  label: string;
  /** Counted as "eligible for automated fix". */
  eligible: boolean;
  reason: string;
};

export function findingFixStatus(
  finding: Parameters<typeof classifyRemediationEligibility>[0],
  serverDecision?: {
    eligibility: RemediationEligibilityType;
    unifiedDiff: string;
    eligibilityReason: string;
    generation?: { state: string } | null;
  } | null,
): FindingFixStatus {
  // A preview still being generated is not a decision yet.
  if (serverDecision && serverDecision.generation?.state !== "running") {
    if (serverDecision.eligibility === "unsuitable" || !serverDecision.unifiedDiff) {
      return { kind: "manual_review", label: "Manual Review", eligible: false, reason: serverDecision.eligibilityReason };
    }
    return {
      kind: "fix_ready",
      label: serverDecision.eligibility === "safe" ? "Safe Fix Ready" : "Fix Ready",
      eligible: true,
      reason: serverDecision.eligibilityReason,
    };
  }
  const e = classifyRemediationEligibility(finding);
  if (e.requiresRotation) return { kind: "rotate_credential", label: "Rotate Credential", eligible: false, reason: e.reason };
  if (!e.canAutoFix) return { kind: "not_eligible", label: "Manual Review", eligible: false, reason: e.reason };
  if (e.decidedOnPreview) return { kind: "decided_on_preview", label: "Checked on Preview", eligible: false, reason: e.reason };
  return e.eligibility === "safe"
    ? { kind: "safe", label: "Safe Fix", eligible: true, reason: e.reason }
    : { kind: "potentially_breaking", label: "Potentially Breaking", eligible: true, reason: e.reason };
}

/**
 * Which engine a preview for this finding uses, mirroring the server's remediationEngineFor:
 * only "ai" calls the AI provider (and counts toward its quota).
 */
export function remediationEngine(finding: {
  scanner?: string | null;
  filePath?: string | null;
  ruleId?: string | null;
  category?: string | null;
  packageInfo?: unknown;
  redactedEvidence?: string | null;
  title?: string | null;
  metadata?: unknown;
}): "npm" | "manifest" | "deterministic" | "ai" | "none" {
  const e = classifyRemediationEligibility(finding);
  if (!e.canAutoFix) return "none";
  const pkg = (finding.packageInfo ?? null) as { ecosystem?: string } | null;
  if (finding.scanner === "osv-scanner" && /(^|\/)package-lock\.json$/.test(finding.filePath || "") && pkg?.ecosystem?.toLowerCase() === "npm") return "npm";
  if (finding.packageInfo != null || finding.scanner === "osv-scanner" || finding.category === "Dependencies") return "manifest";
  if ((finding.ruleId || "").toLowerCase().includes("eval") || /\beval\s*\(/.test(finding.redactedEvidence || "")) return "deterministic";
  return "ai";
}

export const ENGINE_NOTES: Record<ReturnType<typeof remediationEngine>, string> = {
  npm: "No AI request: VibeShield's deterministic npm engine builds the fix (the same result as npm install/npm update, checked against the scanned lockfile).",
  manifest: "No AI request: a deterministic manifest version bump against the file at the scanned commit.",
  deterministic: "No AI request: a deterministic, source-checked code transformation.",
  ai: "Uses the AI provider to propose the change (counts toward the AI quota); the result is still checked against the scanned file.",
  none: "No automated fix is offered for this finding.",
};
