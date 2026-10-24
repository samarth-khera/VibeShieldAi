export type RemediationEligibilityType = "safe" | "potentially_breaking" | "unsuitable";

export interface RemediationEligibility {
  eligibility: RemediationEligibilityType;
  canAutoFix: boolean;
  requiresRotation: boolean;
  reason: string;
  warnings: string[];
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
    const pkg = finding.packageInfo as { name?: string; fixedVersion?: string } | null;
    const hasFixed = Boolean(pkg?.fixedVersion);

    if (hasFixed) {
      return {
        eligibility: "potentially_breaking",
        canAutoFix: true,
        requiresRotation: false,
        reason: `Automated version bump to patched release ${pkg?.fixedVersion || ""}.`,
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
