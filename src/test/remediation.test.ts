import { describe, it, expect, beforeEach } from "vitest";
import { validateUnifiedDiff, generateRemediationPatch } from "@/server/remediation/patch";
import { classifyRemediationEligibility } from "@/lib/remediation-eligibility";
import { InMemoryJobStore } from "@/test/mock-store";
import {
  createPreview,
  approveRemediation,
  applyAndVerify,
  type RemediationDeps,
} from "@/server/remediation/service";
import { createRemediationPullRequest } from "@/server/remediation/github-pr";
import type { LlmProvider } from "@/server/ai/client";
import type { FindingRecord, JobRecord } from "@/server/job-store";
import type { NormalizedFinding } from "@/server/scanners/types";

function makeFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    scanner: "semgrep",
    ruleId: "semgrep:sample-rule",
    category: "Code Analysis",
    severity: "medium",
    originalSeverity: "medium",
    title: "Sample finding",
    description: "Sample description",
    filePath: "src/sample.ts",
    fingerprint: "fp-sample",
    startLine: 1,
    endLine: 1,
    redactedEvidence: "sample",
    vulnerabilityId: null,
    remediation: "Fix sample",
    packageInfo: null,
    metadata: null,
    ...overrides,
  };
}

describe("Phase 6.5: AI Remediation and User-Approved Auto-Fix", () => {
  describe("1. Patch Validation & Path Traversal Prevention", () => {
    it("accepts a clean, safe unified diff within repository workspace", () => {
      const cleanDiff = `--- a/src/server.ts
+++ b/src/server.ts
@@ -10,3 +10,4 @@
-const token = "hardcoded";
+const token = process.env.TOKEN;
`;
      const res = validateUnifiedDiff(cleanDiff);
      expect(res.valid).toBe(true);
      expect(res.affectedFiles).toContain("src/server.ts");
    });

    it("rejects path traversal attempts with ../", () => {
      const traversalDiff = `--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1,1 +1,1 @@
-root:x:0:0
+root:x:0:0:hacked
`;
      const res = validateUnifiedDiff(traversalDiff);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Path traversal/i);
    });

    it("rejects absolute file paths in diff", () => {
      const absDiff = `--- a//etc/shadow
+++ b//etc/shadow
@@ -1,1 +1,1 @@
-test
+test2
`;
      const res = validateUnifiedDiff(absDiff);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/Absolute path/i);
    });

    it("rejects modifications to protected paths like .git or .env", () => {
      const gitDiff = `--- a/.git/config
+++ b/.git/config
@@ -1,1 +1,1 @@
-bare = false
+bare = true
`;
      const res = validateUnifiedDiff(gitDiff);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/protected path forbidden/i);

      const envDiff = `--- a/.env.production
+++ b/.env.production
@@ -1,1 +1,1 @@
-SECRET=old
+SECRET=new
`;
      const envRes = validateUnifiedDiff(envDiff);
      expect(envRes.valid).toBe(false);
      expect(envRes.error).toMatch(/protected path forbidden/i);
    });

    it("rejects oversized diffs (> 50KB)", () => {
      const hugeDiff = `--- a/src/big.ts\n+++ b/src/big.ts\n` + "+ ".repeat(30000);
      const res = validateUnifiedDiff(hugeDiff);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/exceeds maximum allowed size/i);
    });

    it("rejects multi-file patches exceeding limit (> 5 files)", () => {
      const sixFilesDiff = [1, 2, 3, 4, 5, 6]
        .map((i) => `--- a/file${i}.ts\n+++ b/file${i}.ts\n@@ -1 +1 @@\n-old\n+new\n`)
        .join("\n");
      const res = validateUnifiedDiff(sixFilesDiff);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/affects too many files/i);
    });
  });

  describe("2. Remediation Eligibility Classification", () => {
    it("strictly marks secrets as unsuitable and mandates external credential rotation", () => {
      const secretFinding = {
        category: "Secrets",
        ruleId: "gitleaks:generic-api-key",
        title: "Discovered API Key",
        filePath: "config/keys.json",
        remediation: "Remove token",
      };
      const res = classifyRemediationEligibility(secretFinding);
      expect(res.eligibility).toBe("unsuitable");
      expect(res.canAutoFix).toBe(false);
      expect(res.requiresRotation).toBe(true);
      expect(res.warnings.length).toBeGreaterThan(0);
      expect(res.reason).toMatch(/Removing secrets from code does not revoke them/);
    });

    it("classifies dependencies with known fixed versions as potentially breaking", () => {
      const depFinding = {
        category: "Dependencies",
        ruleId: "osv:GHSA-1234",
        title: "Prototype pollution in lodash",
        filePath: "package.json",
        packageInfo: { name: "lodash", fixedVersion: "4.17.21" },
      };
      const res = classifyRemediationEligibility(depFinding);
      expect(res.eligibility).toBe("potentially_breaking");
      expect(res.canAutoFix).toBe(true);
      expect(res.requiresRotation).toBe(false);
    });

    it("classifies dependencies without a known fixed version as unsuitable", () => {
      const unpatchedDep = {
        category: "Dependencies",
        ruleId: "osv:GHSA-9999",
        title: "Zero-day in abandoned-lib",
        filePath: "package.json",
        packageInfo: { name: "abandoned-lib" },
      };
      const res = classifyRemediationEligibility(unpatchedDep);
      expect(res.eligibility).toBe("unsuitable");
      expect(res.canAutoFix).toBe(false);
    });

    it("classifies security-sensitive authentication and cryptography rules as unsuitable", () => {
      const authFinding = {
        category: "Code Analysis",
        ruleId: "semgrep:broken-jwt-auth",
        title: "Broken JWT authentication validation",
        filePath: "src/auth/jwt.ts",
      };
      const res = classifyRemediationEligibility(authFinding);
      expect(res.eligibility).toBe("unsuitable");
      expect(res.canAutoFix).toBe(false);
      expect(res.reason).toMatch(/Authentication, authorization and cryptographic logic require deep runtime context/);
    });

    it("classifies localized unsafe patterns (e.g. security headers, innerHTML) as safe", () => {
      const headerFinding = {
        category: "Code Analysis",
        ruleId: "semgrep:missing-x-content-type-options-header",
        title: "Missing nosniff security header",
        filePath: "src/middleware.ts",
      };
      const res = classifyRemediationEligibility(headerFinding);
      expect(res.eligibility).toBe("safe");
      expect(res.canAutoFix).toBe(true);
    });
  });

  describe("3. Remediation Workflow: Review-Only & Explicit Approval Requirement", () => {
    let store: InMemoryJobStore;
    let deps: RemediationDeps;
    let mockLlm: LlmProvider;
    let testJob: JobRecord;
    let testFinding: FindingRecord;

    beforeEach(async () => {
      store = new InMemoryJobStore();
      testJob = await store.create({
        owner: "test-org",
        repo: "test-repo",
        repositoryUrl: "https://github.com/test-org/test-repo",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(testJob.id, {
        status: "completed",
        commitSha: "sha-1234567890",
        defaultBranch: "main",
      });

      await store.saveFindings(testJob.id, [
        makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:security-header-missing",
          category: "Code Analysis",
          severity: "medium",
          title: "Missing nosniff header",
          description: "Missing security header",
          filePath: "src/middleware.ts",
          fingerprint: "fp-header-001",
          startLine: 12,
        }),
      ]);
      const { findings } = await store.getFindings(testJob.id);
      testFinding = findings[0];

      mockLlm = {
        isConfigured: () => true,
        getModelName: () => "qwen3.5:4b-q4_K_M",
        async generateText() {
          return `\`\`\`diff
--- a/src/middleware.ts
+++ b/src/middleware.ts
@@ -12,2 +12,3 @@
 export function middleware(req) {
+  res.headers.set('X-Content-Type-Options', 'nosniff');
\`\`\``;
        },
      };

      deps = {
        store,
        llmProvider: mockLlm,
      };
    });

    it("Mode A (Review Only) generates proposed patch preview without applying or modifying files", async () => {
      const preview = await createPreview(testJob.id, testFinding.id, deps);
      expect(preview.status).toBe("preview");
      expect(preview.unifiedDiff).toContain("nosniff");
      expect(preview.findingFingerprints).toContain("fp-header-001");
      expect(preview.approvedAt).toBeNull();
      expect(preview.rescanStatus).toBeNull();

      // Ensure job record is still intact
      const job = await store.get(testJob.id);
      expect(job?.commitSha).toBe("sha-1234567890");
    });

    it("Auto-fix execution rejects unapproved patches (requires explicit user authorization)", async () => {
      const preview = await createPreview(testJob.id, testFinding.id, deps);
      expect(preview.status).toBe("preview");

      // Attempting to apply without user approval must throw
      await expect(applyAndVerify(testJob.id, preview.id, deps)).rejects.toThrow(
        /Explicit user approval is required/
      );
    });

    it("Explicit user approval transitions remediation to approved state", async () => {
      const preview = await createPreview(testJob.id, testFinding.id, deps);
      const approved = await approveRemediation(testJob.id, preview.id, deps, "user-session-123");

      expect(approved.status).toBe("approved");
      expect((approved.approvedOperations as { approvedBy?: string })?.approvedBy).toBe("user-session-123");
      expect(approved.approvedAt).toBeInstanceOf(Date);
    });

    it("Refuses to create automated code patches for leaked secrets and flags rotation", async () => {
      await store.saveFindings(testJob.id, [
        makeFinding({
          scanner: "gitleaks",
          ruleId: "gitleaks:slack-bot-token",
          category: "Secrets",
          severity: "critical",
          title: "Leaked Token",
          description: "Secret leak",
          filePath: "secrets.env",
          fingerprint: "fp-secret-999",
        }),
      ]);
      const { findings } = await store.getFindings(testJob.id);
      const secretFinding = findings.find((f) => f.fingerprint === "fp-secret-999")!;

      const preview = await createPreview(testJob.id, secretFinding.id, deps);
      expect(preview.requiresRotation).toBe(true);
      expect(preview.eligibility).toBe("unsuitable");
      expect(preview.unifiedDiff).toBeFalsy();
      expect(preview.warnings?.length).toBeGreaterThan(0);

      // Attempting to approve an unsuitable finding must throw
      await expect(approveRemediation(testJob.id, preview.id, deps)).rejects.toThrow(
        /This finding requires manual intervention and cannot be auto-approved/
      );
    });
  });

  describe("4. Sandbox Security Rescan Verification Gate", () => {
    it("never marks remediation as verified when rescan reveals incomplete fix or regressions", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-owner",
        repo: "test-repo",
        repositoryUrl: "https://github.com/test-owner/test-repo",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-abc",
        defaultBranch: "main",
      });

      await store.saveFindings(job.id, [
        makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          category: "Code Analysis",
          severity: "high",
          title: "Use of eval()",
          description: "Unsafe eval",
          filePath: "src/calc.ts",
          fingerprint: "fp-eval-1",
        }),
      ]);
      const { findings } = await store.getFindings(job.id);
      expect(findings.length).toBe(1);

      const rem = await store.createRemediation({
        id: "rem-123",
        scanJobId: job.id,
        findingFingerprints: ["fp-eval-1"],
        affectedFiles: ["src/calc.ts"],
        commitSha: "sha-abc",
        eligibility: "safe",
        eligibilityReason: "Localized safe fix",
        requiresRotation: false,
        patchSummary: "Replace eval with JSON.parse",
        unifiedDiff: `--- a/src/calc.ts\n+++ b/src/calc.ts\n@@ -1 +1 @@\n-eval(x)\n+JSON.parse(x)\n`,
        status: "approved",
        approvedAt: new Date(),
        rescanStatus: null,
        branchName: null,
        pullRequestUrl: null,
      });

      // Update with incomplete rescan (target still detected)
      const updated = await store.updateRemediation(job.id, rem.id, {
        status: "needs_review",
        rescanStatus: "needs_review",
        rescanSummary: {
          targetResolved: false,
          originalFindingsCount: 1,
          postRescanFindingsCount: 1,
          newFindingsCount: 0,
          resolvedFingerprints: [],
          remainingFingerprints: ["fp-eval-1"],
          regressions: [],
        },
      });

      expect(updated.status).toBe("needs_review");
      expect(updated.rescanStatus).toBe("needs_review");
      expect(updated.rescanSummary?.targetResolved).toBe(false);
    });
  });

  describe("5. GitHub Least-Privilege Branch & PR Controls", () => {
    it("never targets the default branch and uses dedicated vibeshield/fixes/<scan-id> branch", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "acme",
        repo: "webapp",
        repositoryUrl: "https://github.com/acme/webapp",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-base-001",
        defaultBranch: "main",
      });

      const rem = await store.createRemediation({
        id: "rem-pr-test",
        scanJobId: job.id,
        findingFingerprints: ["fp-1"],
        affectedFiles: ["src/file.ts"],
        commitSha: "sha-base-001",
        eligibility: "safe",
        eligibilityReason: "Safe patch",
        requiresRotation: false,
        patchSummary: "Add nosniff header",
        unifiedDiff: "--- a/file\n+++ b/file\n+line\n",
        status: "verified",
        approvedAt: new Date(),
        rescanStatus: "verified",
        branchName: null,
        pullRequestUrl: null,
      });

      // Call without write token to test graceful fallback
      const result = await createRemediationPullRequest({
        owner: job.owner,
        repo: job.repo,
        defaultBranch: job.defaultBranch || "main",
        commitSha: job.commitSha || "HEAD",
        scanJobId: job.id,
        remediationId: rem.id,
        patchSummary: rem.patchSummary,
        unifiedDiff: rem.unifiedDiff,
      });

      expect(result.hasWriteAccess).toBe(false);
      expect(result.branchName).toBe(`vibeshield/fixes/${job.id.slice(0, 12)}`);
      expect(result.branchName).not.toBe("main");
      expect(result.branchName).not.toBe(job.defaultBranch);
      expect(result.message).toMatch(/GitHub write authorization is not configured/);
    });
  });

  describe("6. Phase 5: Permission-Gated Auto-Fix & E2E Rescan Verification", () => {
    it("Review Only mode: generates proposed patch preview without mutating target code or creating branches", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-eval-001",
        defaultBranch: "main",
      });

      const originalSource = 'export function parseLegacyJson(rawJson: string) {\n  return eval("(" + rawJson + ")");\n}\n';
      await store.saveFindings(job.id, [
        makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          category: "Code Analysis",
          severity: "high",
          title: "Legacy JSON deserialization",
          filePath: "src/parser.ts",
          fingerprint: "fp-eval-1234",
          startLine: 2,
          endLine: 2,
          redactedEvidence: '  return eval("(" + rawJson + ")");',
        }),
      ]);

      const { findings } = await store.getFindings(job.id);
      const evalFinding = findings[0];

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/parser.ts": originalSource },
      };

      // 1. Generate preview
      const preview = await createPreview(job.id, evalFinding.id, deps);
      expect(preview.status).toBe("preview");
      expect(preview.approvedAt).toBeNull();
      expect(preview.branchName).toBeNull();
      expect(preview.pullRequestUrl).toBeNull();

      // Verify diff transforms eval to JSON.parse
      expect(preview.unifiedDiff).toContain('-  return eval("(" + rawJson + ")");');
      expect(preview.unifiedDiff).toContain("+  return JSON.parse(rawJson);");

      // Verify target source is completely untouched
      expect(deps.sourceFiles!["src/parser.ts"]).toBe(originalSource);
    });

    it("explicit user approval is strictly mandatory before patch application", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-eval-001",
        defaultBranch: "main",
      });

      await store.saveFindings(job.id, [
        makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          category: "Code Analysis",
          severity: "high",
          title: "Legacy JSON deserialization",
          filePath: "src/parser.ts",
          fingerprint: "fp-eval-1234",
          startLine: 2,
          endLine: 2,
          redactedEvidence: '  return eval("(" + rawJson + ")");',
        }),
      ]);
      const { findings } = await store.getFindings(job.id);
      const evalFinding = findings[0];

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/parser.ts": 'return eval("(" + rawJson + ")");' },
      };

      const preview = await createPreview(job.id, evalFinding.id, deps);

      // Attempting apply without approval must fail with 403
      await expect(applyAndVerify(job.id, preview.id, deps)).rejects.toThrow(
        /Explicit user approval is required/
      );

      // Explicit user approval
      const approved = await approveRemediation(job.id, preview.id, deps, "session-user-999");
      expect(approved.status).toBe("approved");
      expect(approved.approvedAt).toBeInstanceOf(Date);
    });

    it("applies approved patch in isolated sandbox, verifies resolution, and proves 0 regressions", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-eval-001",
        defaultBranch: "main",
      });

      const vulnerableSource = 'export function parseLegacyJson(rawJson: string) {\n  return eval("(" + rawJson + ")");\n}\n';
      const evalFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        category: "Code Analysis",
        severity: "high",
        title: "Legacy JSON deserialization",
        filePath: "src/parser.ts",
        fingerprint: "fp-eval-verified-99",
        startLine: 2,
        endLine: 2,
        redactedEvidence: '  return eval("(" + rawJson + ")");',
      });

      await store.saveFindings(job.id, [evalFinding]);
      const { findings } = await store.getFindings(job.id);

      // Mock scan engine simulating Semgrep behavior:
      // Before fix (has eval): detects finding
      // After fix (eval replaced with JSON.parse): detects 0 findings
      const mockScanEngine = async (dir: string) => {
        const fs = await import("node:fs/promises");
        const path = await import("node:path");
        const content = await fs.readFile(path.join(dir, "src/parser.ts"), "utf8").catch(() => "");
        const hasEval = /\beval\s*\(/.test(content);
        return {
          status: "completed" as const,
          findings: hasEval ? [evalFinding] : [],
          counts: { critical: hasEval ? 1 : 0, high: 0, medium: 0, low: 0, info: 0, total: hasEval ? 1 : 0 },
          gitleaksStatus: "completed" as const,
          gitleaksDurationMs: 10,
          gitleaksError: null,
          semgrepStatus: "completed" as const,
          semgrepDurationMs: 50,
          semgrepError: null,
          osvStatus: "completed" as const,
          osvDurationMs: 10,
          osvError: null,
          scannerVersions: { gitleaks: "8.18", semgrep: "1.60", osvScanner: "2.7" },
          scanCoverage: {
            lockfilesFound: [],
            scannersRun: ["gitleaks", "semgrep", "osv-scanner"],
            limitations: [],
          },
        };
      };

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/parser.ts": vulnerableSource },
        scanEngine: mockScanEngine,
      };

      const preview = await createPreview(job.id, findings[0].id, deps);
      await approveRemediation(job.id, preview.id, deps, "user-verifier");

      const verified = await applyAndVerify(job.id, preview.id, deps);

      expect(verified.status).toBe("verified");
      expect(verified.rescanStatus).toBe("verified");
      expect(verified.rescanSummary?.targetResolved).toBe(true);
      expect(verified.rescanSummary?.newFindingsCount).toBe(0);
      expect(verified.rescanSummary?.regressions).toHaveLength(0);
      expect(verified.rescanSummary?.resolvedFingerprints).toContain("fp-eval-verified-99");
    });

    it("rejects generic placeholder comments like [SECURED] or [REMOVED VULNERABLE CODE]", async () => {
      // Finding with no source evidence and no matching rule template
      const unknownFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "unknown-exotic-rule",
        category: "Code Analysis",
        severity: "medium",
        title: "Exotic issue",
        filePath: "src/unknown.ts",
        redactedEvidence: "",
      });

      // generateRemediationPatch must throw rather than produce fake comment placeholders
      await expect(
        generateRemediationPatch({
          finding: unknownFinding,
          scanJobId: "job-1",
          commitSha: "sha-1",
        })
      ).rejects.toThrow(/Cannot generate automated patch.*Manual code review is required/);
    });

    it("rejects generic eval() replacement when arbitrary JavaScript execution semantics must be preserved", async () => {
      const arbitraryScriptFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "js-code-execution-eval",
        category: "Code Analysis",
        severity: "critical",
        title: "Dynamic code execution",
        filePath: "src/runner.ts",
        description: "Executes arbitrary script passed by user",
        redactedEvidence: "  return eval(script);",
        remediation: "Avoid dynamic execution of arbitrary script.",
      });

      await expect(
        generateRemediationPatch({
          finding: arbitraryScriptFinding,
          scanJobId: "job-1",
          commitSha: "sha-1",
        })
      ).rejects.toThrow(/Cannot safely replace eval\(\) with JSON\.parse\(\) where arbitrary JavaScript execution semantics must be preserved/);
    });

    it("marks remediation as needs_review if rescan still detects the targeted finding", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-eval-001",
        defaultBranch: "main",
      });

      const evalFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        category: "Code Analysis",
        severity: "high",
        title: "Legacy JSON deserialization",
        filePath: "src/parser.ts",
        fingerprint: "fp-eval-incomplete",
        startLine: 2,
        endLine: 2,
        redactedEvidence: '  return eval("(" + rawJson + ")");',
      });

      await store.saveFindings(job.id, [evalFinding]);
      const { findings } = await store.getFindings(job.id);

      // Mock scan engine that always returns the finding (simulating failed/incomplete fix)
      const mockFailingScanEngine = async () => ({
        status: "completed" as const,
        findings: [evalFinding],
        counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
        gitleaksStatus: "completed" as const,
        gitleaksDurationMs: 10,
        gitleaksError: null,
        semgrepStatus: "completed" as const,
        semgrepDurationMs: 50,
        semgrepError: null,
        osvStatus: "completed" as const,
        osvDurationMs: 10,
        osvError: null,
        scannerVersions: { gitleaks: "8.18", semgrep: "1.60", osvScanner: "2.7" },
        scanCoverage: {
          lockfilesFound: [],
          scannersRun: ["gitleaks", "semgrep", "osv-scanner"],
          limitations: [],
        },
      });

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/parser.ts": 'return eval("(" + rawJson + ")");' },
        scanEngine: mockFailingScanEngine,
      };

      const preview = await createPreview(job.id, findings[0].id, deps);
      await approveRemediation(job.id, preview.id, deps, "user-verifier");

      const result = await applyAndVerify(job.id, preview.id, deps);

      // Must be needs_review, NEVER verified
      expect(result.status).toBe("needs_review");
      expect(result.rescanStatus).toBe("needs_review");
      expect(result.rescanSummary?.targetResolved).toBe(false);
    });
  });

  describe("7. Security Hardening & Fail-Closed eval() Remediation Regression Suite", () => {
    it("case 1: eval(script) with a description indicating arbitrary script execution is rejected", async () => {
      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "js-code-execution-eval",
        title: "Dynamic code execution",
        description: "Executes arbitrary script passed by user",
        filePath: "src/runner.ts",
        redactedEvidence: "  return eval(script);",
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-reg-1",
          commitSha: "sha-1",
        })
      ).rejects.toThrow(
        /Cannot safely replace eval\(\) with JSON\.parse\(\) where arbitrary JavaScript execution semantics must be preserved/
      );
    });

    it("case 2: eval(script) with additional generic words such as data, input, or payload is still rejected", async () => {
      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "js-code-execution-eval",
        title: "Dynamic code execution with input data payload",
        description: "Executes arbitrary script passed by user to process input data payload",
        filePath: "src/runner.ts",
        redactedEvidence: "  return eval(script);",
        remediation: "Avoid dynamic execution of arbitrary script even for data payload parsing.",
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-reg-2",
          commitSha: "sha-1",
        })
      ).rejects.toThrow(
        /Cannot safely replace eval\(\) with JSON\.parse\(\) where arbitrary JavaScript execution semantics must be preserved/
      );
    });

    it("case 3: evidence containing a JSON-related keyword without sufficient source context is rejected for automatic remediation", async () => {
      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "js-code-execution-eval",
        title: "Unsafe JSON parsing via eval",
        description: "Uses eval to parse JSON data",
        filePath: "src/handler.ts",
        redactedEvidence: "  const result = eval(userInput);",
      });

      // Without sourceContent or with generic variable name without JSON proof
      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-reg-3",
          commitSha: "sha-1",
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("case 4: a genuinely verified JSON-parsing transformation is accepted only when its preconditions are established", async () => {
      // Precondition A: surrounding source context confirms JSON parsing + explicit JSON-named variable
      const verifiedFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Unsafe eval usage",
        description: "Evaluates JSON string dynamically",
        filePath: "src/config.ts",
        startLine: 3,
        endLine: 3,
        redactedEvidence: "  return eval(jsonData);",
      });

      const sourceContent = `export function parseConfig(jsonData: string) {
  // Parse incoming JSON configuration
  return eval(jsonData);
}`;

      const patchResult = await generateRemediationPatch({
        finding: verifiedFinding,
        scanJobId: "job-reg-4",
        commitSha: "sha-1",
        sourceContent,
      });

      expect(patchResult.unifiedDiff).toContain("-  return eval(jsonData);");
      expect(patchResult.unifiedDiff).toContain("+  return JSON.parse(jsonData);");
      expect(patchResult.patchSummary).toMatch(/Replace unsafe dynamic eval\(\) with safe JSON\.parse\(\)/);

      // Precondition B: classic pre-JSON.parse deserialization idiom
      const idiomFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Legacy JSON deserialization",
        description: "Legacy pre-JSON.parse deserialization idiom",
        filePath: "src/parser.ts",
        startLine: 2,
        endLine: 2,
        redactedEvidence: '  return eval("(" + rawData + ")");',
      });

      const idiomPatchResult = await generateRemediationPatch({
        finding: idiomFinding,
        scanJobId: "job-reg-4",
        commitSha: "sha-1",
      });

      expect(idiomPatchResult.unifiedDiff).toContain('-  return eval("(" + rawData + ")");');
      expect(idiomPatchResult.unifiedDiff).toContain("+  return JSON.parse(rawData);");
    });

    it("case 5: invalid, stale, or non-applicable patches do not become verified", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-stale-001",
        defaultBranch: "main",
      });

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Unsafe eval",
        filePath: "src/config.ts",
        fingerprint: "fp-eval-stale",
        startLine: 3,
        endLine: 3,
        redactedEvidence: "  return eval(jsonData);",
      });
      await store.saveFindings(job.id, [finding]);

      // Stale patch: targets code lines that do not exist or mismatch
      const staleRem = await store.createRemediation({
        id: "rem-stale-001",
        scanJobId: job.id,
        findingFingerprints: ["fp-eval-stale"],
        affectedFiles: ["src/config.ts"],
        commitSha: "sha-stale-001",
        eligibility: "safe",
        eligibilityReason: "Localized safe fix",
        requiresRotation: false,
        patchSummary: "Stale patch",
        unifiedDiff: `--- a/src/config.ts\n+++ b/src/config.ts\n@@ -10,1 +10,1 @@\n-nonExistentCodeOldLine();\n+replacementCode();\n`,
        status: "approved",
        approvedAt: new Date(),
        rescanStatus: null,
        branchName: null,
        pullRequestUrl: null,
      });

      // Scan engine still detects the vulnerability post-patch because stale patch didn't fix it
      const mockEngine = async () => ({
        status: "completed" as const,
        findings: [finding],
        counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
        gitleaksStatus: "completed" as const,
        gitleaksDurationMs: 10,
        gitleaksError: null,
        semgrepStatus: "completed" as const,
        semgrepDurationMs: 50,
        semgrepError: null,
        osvStatus: "completed" as const,
        osvDurationMs: 10,
        osvError: null,
        scannerVersions: { gitleaks: "8.18", semgrep: "1.60", osvScanner: "2.7" },
        scanCoverage: { lockfilesFound: [], scannersRun: ["semgrep"], limitations: [] },
      });

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/config.ts": "export function parseConfig(jsonData: string) {\n  return eval(jsonData);\n}\n" },
        scanEngine: mockEngine,
      };

      const result = await applyAndVerify(job.id, staleRem.id, deps);
      expect(result.status).toBe("needs_review");
      expect(result.rescanStatus).toBe("needs_review");
      expect(result.rescanSummary?.targetResolved).toBe(false);
    });

    it("case 6: an unapproved apply request is rejected", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-001",
        defaultBranch: "main",
      });

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        filePath: "src/config.ts",
        fingerprint: "fp-unapproved",
        redactedEvidence: '  return eval("(" + rawData + ")");',
      });
      await store.saveFindings(job.id, [finding]);
      const { findings: savedFindings6 } = await store.getFindings(job.id);

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/config.ts": 'return eval("(" + rawData + ")");' },
      };

      const preview = await createPreview(job.id, savedFindings6[0].id, deps);
      expect(preview.status).toBe("preview");
      expect(preview.approvedAt).toBeNull();

      // Attempting to apply without explicit user approval must throw 403
      await expect(applyAndVerify(job.id, preview.id, deps)).rejects.toThrow(
        /Explicit user approval is required/
      );
    });

    it("case 7: a failed post-fix rescan or regression check does not mark remediation successful", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-user",
        repo: "vulnerable-app",
        repositoryUrl: "https://github.com/test-user/vulnerable-app",
        expiresAt: new Date(Date.now() + 3600000),
      });
      await store.update(job.id, {
        status: "completed",
        commitSha: "sha-001",
        defaultBranch: "main",
      });

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        filePath: "src/config.ts",
        fingerprint: "fp-target",
        redactedEvidence: '  return eval("(" + rawData + ")");',
      });
      await store.saveFindings(job.id, [finding]);
      const { findings: savedFindings7 } = await store.getFindings(job.id);

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/config.ts": 'return eval("(" + rawData + ")");' },
      };

      const preview = await createPreview(job.id, savedFindings7[0].id, deps);
      await approveRemediation(job.id, preview.id, deps, "admin");

      // Subcase 7A: Rescan introduces a new regression finding
      const regressionFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:regression-detected",
        fingerprint: "fp-regression-999",
      });

      const engineWithRegression = async () => ({
        status: "completed" as const,
        findings: [regressionFinding], // target is resolved, but new regression was introduced!
        counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
        gitleaksStatus: "completed" as const,
        gitleaksDurationMs: 10,
        gitleaksError: null,
        semgrepStatus: "completed" as const,
        semgrepDurationMs: 50,
        semgrepError: null,
        osvStatus: "completed" as const,
        osvDurationMs: 10,
        osvError: null,
        scannerVersions: { gitleaks: "8.18", semgrep: "1.60", osvScanner: "2.7" },
        scanCoverage: { lockfilesFound: [], scannersRun: ["semgrep"], limitations: [] },
      });

      const regressionResult = await applyAndVerify(job.id, preview.id, {
        ...deps,
        scanEngine: engineWithRegression,
      });

      expect(regressionResult.status).toBe("needs_review");
      expect(regressionResult.rescanStatus).toBe("needs_review");
      expect(regressionResult.rescanSummary?.newFindingsCount).toBe(1);
      expect(regressionResult.rescanSummary?.regressions).toContain("fp-regression-999");

      // Subcase 7B: Rescan engine itself fails
      const failingEngine = async () => ({
        status: "failed" as const,
        findings: [],
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        gitleaksStatus: "failed" as const,
        gitleaksDurationMs: 10,
        gitleaksError: "Engine timeout",
        semgrepStatus: "failed" as const,
        semgrepDurationMs: 10,
        semgrepError: "Engine crashed",
        osvStatus: "failed" as const,
        osvDurationMs: 10,
        osvError: "Engine error",
        scannerVersions: { gitleaks: "8.18", semgrep: "1.60", osvScanner: "2.7" },
        scanCoverage: { lockfilesFound: [], scannersRun: [], limitations: ["Failed scan"] },
      });

      // Create fresh preview for Subcase 7B to test engine failure on approved patch
      const preview2 = await createPreview(job.id, savedFindings7[0].id, deps);
      await approveRemediation(job.id, preview2.id, deps, "admin");

      const failedRescanResult = await applyAndVerify(job.id, preview2.id, {
        ...deps,
        scanEngine: failingEngine,
      });

      expect(failedRescanResult.status).toBe("needs_review");
      expect(failedRescanResult.rescanStatus).toBe("failed");
    });
  });
});
