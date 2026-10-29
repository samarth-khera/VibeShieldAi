import { describe, it, expect, beforeEach, vi } from "vitest";
import { diffDigest } from "@/server/remediation/service";
/** The job owner's session subject; in production it comes from the signed owner grant. */
const TEST_OWNER = { ownerSubject: "test-owner-subject" };
import {
  validateUnifiedDiff,
  generateRemediationPatch,
  verifyJsonSourceProof,
  updatePythonRequirementsContent,
  updatePackageJsonContent,
  applyUnifiedDiffString,
} from "@/server/remediation/patch";
import { classifyRemediationEligibility, resolveFindingFixedVersion } from "@/lib/remediation-eligibility";
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
import type { NormalizedFinding, ScanEngineResult } from "@/server/scanners/types";
import { runOsvScan } from "@/server/scanners/osv";
import { runSubprocess } from "@/server/scanners/runner";
import { toPublicFinding } from "@/server/api";

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
        commitSha: "b6da814997f805087d933c7a36b32ac7e8559127",
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
@@ -12,1 +12,2 @@
 export function middleware(req) {
+  res.headers.set('X-Content-Type-Options', 'nosniff');
\`\`\``;
        },
      };

      deps = {
        store,
        llmProvider: mockLlm,
        // Previews are checked against the real file at the scanned commit.
        sourceFiles: {
          "src/middleware.ts": `${Array.from({ length: 11 }, (_, i) => `// line ${i + 1}`).join("\n")}\nexport function middleware(req) {\n  return next(req);\n}\n`,
        },
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
      expect(job?.commitSha).toBe("b6da814997f805087d933c7a36b32ac7e8559127");
    });

    it("Auto-fix execution rejects unapproved patches (requires explicit user authorization)", async () => {
      const preview = await createPreview(testJob.id, testFinding.id, deps);
      expect(preview.status).toBe("preview");

      // Attempting to apply without user approval must throw
      await expect(applyAndVerify(testJob.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(
        /Explicit user approval is required/
      );
    });

    it("Explicit user approval transitions remediation to approved state", async () => {
      const preview = await createPreview(testJob.id, testFinding.id, deps);
      const approved = await approveRemediation(testJob.id, preview.id, deps, TEST_OWNER);

      expect(approved.status).toBe("approved");
      expect(approved.approvedOperations).toMatchObject({
        approvedBy: "job_owner",
        ownerSubject: TEST_OWNER.ownerSubject,
        scanJobId: testJob.id,
        remediationId: preview.id,
        commitSha: preview.commitSha,
        findingFingerprints: preview.findingFingerprints,
        diffSha256: diffDigest(preview.unifiedDiff),
      });
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
      await expect(approveRemediation(testJob.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(
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
        commitSha: "978bf64bb60c272d98db160f08c6f1a35c428cb0",
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
        commitSha: "978bf64bb60c272d98db160f08c6f1a35c428cb0",
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
        commitSha: "1ce018972d914b2c2020b6760f2cf19d69bbc0d7",
        defaultBranch: "main",
      });

      const rem = await store.createRemediation({
        id: "rem-pr-test",
        scanJobId: job.id,
        findingFingerprints: ["fp-1"],
        affectedFiles: ["src/file.ts"],
        commitSha: "1ce018972d914b2c2020b6760f2cf19d69bbc0d7",
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

      // There is no ambient credential: without the user's own token nothing reaches GitHub.
      vi.stubEnv("GITHUB_TOKEN", "ambient-read-token");
      const fetchSpy = vi.fn();
      const result = await createRemediationPullRequest({
        owner: job.owner,
        repo: job.repo,
        commitSha: job.commitSha!,
        scanJobId: job.id,
        remediationId: rem.id,
        unifiedDiff: rem.unifiedDiff,
        title: "t",
        body: "b",
        token: "",
        fetchImpl: fetchSpy,
      });

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(result.status).toBe("failed");
      expect(result.code).toBe("credential_invalid");
      expect(result.branch).toMatch(/^vibeshield\/fix-/);
      expect(result.branch).not.toBe(job.defaultBranch);
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
        commitSha: "d826c48a412ac34642454fff1e6c06e96169e990",
        defaultBranch: "main",
      });

      const originalSource = 'export function getStaticConfig() {\n  const rawJson = \'{"version": 1}\';\n  return eval("(" + rawJson + ")");\n}\n';
      await store.saveFindings(job.id, [
        makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          category: "Code Analysis",
          severity: "high",
          title: "Verified JSON literal deserialization",
          filePath: "src/parser.ts",
          fingerprint: "fp-eval-1234",
          startLine: 3,
          endLine: 3,
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
        commitSha: "d826c48a412ac34642454fff1e6c06e96169e990",
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
          startLine: 3,
          endLine: 3,
          redactedEvidence: '  return eval("(" + rawJson + ")");',
        }),
      ]);
      const { findings } = await store.getFindings(job.id);
      const evalFinding = findings[0];

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/parser.ts": 'export function getStaticConfig() {\n  const rawJson = \'{"status": "ok"}\';\n  return eval("(" + rawJson + ")");\n}\n' },
      };

      const preview = await createPreview(job.id, evalFinding.id, deps);

      // Attempting apply without approval must fail with 403
      await expect(applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(
        /Explicit user approval is required/
      );

      // Explicit user approval
      const approved = await approveRemediation(job.id, preview.id, deps, TEST_OWNER);
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
        commitSha: "d826c48a412ac34642454fff1e6c06e96169e990",
        defaultBranch: "main",
      });

      const vulnerableSource = 'export function getStaticConfig() {\n  const rawJson = \'{"version": 1, "status": "active"}\';\n  return eval("(" + rawJson + ")");\n}\n';
      const evalFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        category: "Code Analysis",
        severity: "high",
        title: "Legacy JSON deserialization",
        filePath: "src/parser.ts",
        fingerprint: "fp-eval-verified-99",
        startLine: 3,
        endLine: 3,
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
      await approveRemediation(job.id, preview.id, deps, TEST_OWNER);

      const verified = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);

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
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
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
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
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
        commitSha: "d826c48a412ac34642454fff1e6c06e96169e990",
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
        startLine: 3,
        endLine: 3,
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
        sourceFiles: { "src/parser.ts": 'export function getStaticConfig() {\n  const rawJson = \'{"status": "ok"}\';\n  return eval("(" + rawJson + ")");\n}\n' },
        scanEngine: mockFailingScanEngine,
      };

      const preview = await createPreview(job.id, findings[0].id, deps);
      await approveRemediation(job.id, preview.id, deps, TEST_OWNER);

      const result = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);

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
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
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
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
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
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("case 4: a genuinely verified JSON-parsing transformation is accepted only when its preconditions are established", async () => {
      // Precondition A: surrounding source context proves local static JSON literal assignment
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

      const sourceContent = `export function loadDefaultConfig() {
  const jsonData = '{"theme": "dark", "version": 1}';
  return eval(jsonData);
}`;

      const patchResult = await generateRemediationPatch({
        finding: verifiedFinding,
        scanJobId: "job-reg-4",
        commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
        sourceContent,
      });

      expect(patchResult.unifiedDiff).toContain("-  return eval(jsonData);");
      expect(patchResult.unifiedDiff).toContain("+  return JSON.parse(jsonData);");
      expect(patchResult.patchSummary).toMatch(/Replace unsafe dynamic eval\(\) with safe JSON\.parse\(\)/);

      // Precondition B: classic pre-JSON.parse deserialization idiom with proven local static JSON literal
      const idiomSource = `export function getLegacyPayload() {
  const rawJson = '{"items": [1, 2, 3]}';
  return eval("(" + rawJson + ")");
}`;
      const idiomFinding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Legacy JSON deserialization",
        description: "Legacy pre-JSON.parse deserialization idiom",
        filePath: "src/parser.ts",
        startLine: 3,
        endLine: 3,
        redactedEvidence: '  return eval("(" + rawJson + ")");',
      });

      const idiomPatchResult = await generateRemediationPatch({
        finding: idiomFinding,
        scanJobId: "job-reg-4",
        commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
        sourceContent: idiomSource,
      });

      expect(idiomPatchResult.unifiedDiff).toContain('-  return eval("(" + rawJson + ")");');
      expect(idiomPatchResult.unifiedDiff).toContain("+  return JSON.parse(rawJson);");
    });

    it("uncovered path 1: eval(script) finding with a configured/mock LLM that returns a syntactically valid diff must not bypass the fail-closed policy", async () => {
      const mockLlm: LlmProvider = {
        getModelName: () => "mock-llm",
        isConfigured: () => true,
        generateText: async () => `--- a/src/runner.ts\n+++ b/src/runner.ts\n@@ -2,1 +2,1 @@\n-  return eval(script);\n+  return JSON.parse(script);\n`,
      };

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
          scanJobId: "job-bypass-1",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          llmProvider: mockLlm,
        })
      ).rejects.toThrow(
        /Cannot safely replace eval\(\) with JSON\.parse\(\) where arbitrary JavaScript execution semantics must be preserved/
      );
    });

    it("uncovered path 1: the LLM provider must not be called for an eval() finding whose safety preconditions are not established", async () => {
      let llmCalled = false;
      const mockLlm: LlmProvider = {
        getModelName: () => "mock-llm",
        isConfigured: () => true,
        generateText: async () => {
          llmCalled = true;
          return "diff";
        },
      };

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
          scanJobId: "job-llm-call-1",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          llmProvider: mockLlm,
        })
      ).rejects.toThrow();

      expect(llmCalled).toBe(false);
    });

    it('uncovered path 2: eval("(" + rawData + ")") with no source context must be rejected', async () => {
      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Legacy wrapper expression",
        filePath: "src/wrapper.ts",
        redactedEvidence: '  return eval("(" + rawData + ")");',
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-no-ctx",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("uncovered path 2: eval wrapper with unrelated JSON-related words elsewhere in the source must still be rejected", async () => {
      const unrelatedSource = `// Unrelated JSON utility elsewhere in file
import { parseJson } from "./utils";

const logger = { log: (x: any) => console.log(JSON.stringify(x)) };

export function executeUserPayload(rawData: string) {
  return eval("(" + rawData + ")");
}
`;

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Legacy wrapper expression",
        filePath: "src/payload.ts",
        startLine: 6,
        endLine: 6,
        redactedEvidence: '  return eval("(" + rawData + ")");',
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-unrelated-ctx",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: unrelatedSource,
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("an unrelated eligible finding can still use the LLM remediation path", async () => {
      let llmCalled = false;
      const mockLlm: LlmProvider = {
        getModelName: () => "mock-llm",
        isConfigured: () => true,
        generateText: async () => {
          llmCalled = true;
          return `--- a/src/server.ts\n+++ b/src/server.ts\n@@ -10,1 +10,2 @@\n res.send("ok");\n+  res.setHeader("X-Frame-Options", "DENY");\n`;
        },
      };

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "security:missing-frame-options",
        title: "Missing X-Frame-Options header",
        description: "Response does not include anti-clickjacking header",
        filePath: "src/server.ts",
        redactedEvidence: 'res.send("ok");',
      });

      const patch = await generateRemediationPatch({
        finding,
        scanJobId: "job-unrelated-llm",
        commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
        llmProvider: mockLlm,
      });

      expect(llmCalled).toBe(true);
      expect(patch.unifiedDiff).toContain('+  res.setHeader("X-Frame-Options", "DENY");');
      expect(patch.patchSummary).toContain("Surgical security patch for security:missing-frame-options");
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
        commitSha: "7f5068b388c2f799e4eed94853a4331f9c0defe2",
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
        commitSha: "7f5068b388c2f799e4eed94853a4331f9c0defe2",
        eligibility: "safe",
        eligibilityReason: "Localized safe fix",
        requiresRotation: false,
        patchSummary: "Stale patch",
        unifiedDiff: `--- a/src/config.ts\n+++ b/src/config.ts\n@@ -10,1 +10,1 @@\n-nonExistentCodeOldLine();\n+replacementCode();\n`,
        status: "preview",
        approvedAt: null,
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

      // A patch that does not match the scanned revision is refused before it can even be approved.
      await expect(approveRemediation(job.id, staleRem.id, deps, TEST_OWNER)).rejects.toMatchObject({ code: "patch_does_not_apply", status: 409 });
      await expect(applyAndVerify(job.id, staleRem.id, deps, TEST_OWNER)).rejects.toMatchObject({ code: "approval_required" });
      const after = await store.getRemediation(job.id, staleRem.id);
      expect(after?.status).toBe("preview");
      expect(after?.approvedAt).toBeNull();
      expect(after?.rescanStatus).toBeNull();
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
        commitSha: "a79cd73d35dea77eaead8954951688d38f4fc45d",
        defaultBranch: "main",
      });

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        filePath: "src/config.ts",
        fingerprint: "fp-unapproved",
        startLine: 3,
        endLine: 3,
        redactedEvidence: '  return eval("(" + rawJson + ")");',
      });
      await store.saveFindings(job.id, [finding]);
      const { findings: savedFindings6 } = await store.getFindings(job.id);

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/config.ts": 'export function getStaticConfig() {\n  const rawJson = \'{"status": "ok"}\';\n  return eval("(" + rawJson + ")");\n}\n' },
      };

      const preview = await createPreview(job.id, savedFindings6[0].id, deps);
      expect(preview.status).toBe("preview");
      expect(preview.approvedAt).toBeNull();

      // Attempting to apply without explicit user approval must throw 403
      await expect(applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(
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
        commitSha: "a79cd73d35dea77eaead8954951688d38f4fc45d",
        defaultBranch: "main",
      });

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        filePath: "src/config.ts",
        fingerprint: "fp-target",
        startLine: 3,
        endLine: 3,
        redactedEvidence: '  return eval("(" + rawJson + ")");',
      });
      await store.saveFindings(job.id, [finding]);
      const { findings: savedFindings7 } = await store.getFindings(job.id);

      const deps: RemediationDeps = {
        store,
        sourceFiles: { "src/config.ts": 'export function getStaticConfig() {\n  const rawJson = \'{"status": "ok"}\';\n  return eval("(" + rawJson + ")");\n}\n' },
      };

      const preview = await createPreview(job.id, savedFindings7[0].id, deps);
      await approveRemediation(job.id, preview.id, deps, TEST_OWNER);

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
      }, TEST_OWNER);

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
      await approveRemediation(job.id, preview2.id, deps, TEST_OWNER);

      const failedRescanResult = await applyAndVerify(job.id, preview2.id, {
        ...deps,
        scanEngine: failingEngine,
      }, TEST_OWNER);

      expect(failedRescanResult.status).toBe("failed");
      expect(failedRescanResult.rescanStatus).toBe("failed");
      expect(failedRescanResult.rescanSummary?.reason).toBe("scanner_failed");
      expect(failedRescanResult.rescanSummary?.targetResolved).toBe(false);
    });

    it("regression: rejects nearby function with JSON-related name that passes arbitrary user-controlled script to eval()", async () => {
      const misleadingFnSource = `export function parseJson(userInput: string) {
  // Misleading function name, but input is arbitrary untrusted script
  return eval(userInput);
}`;

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Unsafe eval in parseJson",
        filePath: "src/json-helper.ts",
        startLine: 3,
        endLine: 3,
        redactedEvidence: "  return eval(userInput);",
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-misleading-fn",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: misleadingFnSource,
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("regression: rejects misleading variable name when input originates from untrusted source", async () => {
      const misleadingVarSource = `export function handleRequest(req: any) {
  // Misleading variable name rawJson, but assigned from untrusted query
  const rawJson = req.query.command;
  return eval("(" + rawJson + ")");
}`;

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Legacy wrapper with untrusted query",
        filePath: "src/api-handler.ts",
        startLine: 4,
        endLine: 4,
        redactedEvidence: '  return eval("(" + rawJson + ")");',
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-misleading-var",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: misleadingVarSource,
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("regression: rejects conflicting data-flow evidence where cleanVar is reassigned", async () => {
      const conflictingFlowSource = `export function processPayload(input: string) {
  let data = '{"safe": true}';
  if (input) {
    data = input;
  }
  return eval("(" + data + ")");
}`;

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Conflicting data flow reassignment",
        filePath: "src/payload.ts",
        startLine: 6,
        endLine: 6,
        redactedEvidence: '  return eval("(" + data + ")");',
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-conflicting-flow",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: conflictingFlowSource,
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    it("regression: rejects ambiguous source context with no verifiable local assignment", async () => {
      const ambiguousSource = `export function computeDynamic(ref: unknown) {
  // Ambiguous: target variable has unknown external origin
  return eval("(" + target + ")");
}`;

      const finding = makeFinding({
        scanner: "semgrep",
        ruleId: "semgrep:eval-detected",
        title: "Ambiguous source context",
        filePath: "src/ambiguous.ts",
        startLine: 3,
        endLine: 3,
        redactedEvidence: '  return eval("(" + target + ")");',
      });

      await expect(
        generateRemediationPatch({
          finding,
          scanJobId: "job-ambiguous-ctx",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: ambiguousSource,
        })
      ).rejects.toThrow(
        /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
      );
    });

    describe("AST-Based Source-Proof Ordering, Scope, and Destructuring Regression Tests", () => {
      it("reproduces and refuses the false-acceptance bypass: function process({ data }) { eval(data); data = JSON.stringify({ safe: true }); }", async () => {
        const reproducedSource = `function process({ data }: any) {
  eval(data);
  data = JSON.stringify({ safe: true });
}`;

        const finding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Dangerous eval of destructured parameter",
          filePath: "src/process.ts",
          startLine: 2,
          endLine: 2,
          redactedEvidence: "  eval(data);",
        });

        // 1. Direct unit verification via AST verifyJsonSourceProof
        expect(verifyJsonSourceProof(reproducedSource, "data", 2)).toBe(false);

        // 2. Public generateRemediationPatch interface must refuse automatic remediation
        await expect(
          generateRemediationPatch({
            finding,
            scanJobId: "job-reproduced-bypass",
            commitSha: "dede029882a4ac6ef53646cf8df5b5bbe4f6366d",
            sourceContent: reproducedSource,
          })
        ).rejects.toThrow(
          /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
        );
      });

      it("variant 1: refuses destructured function parameters (object, array, nested, renamed, and rest)", async () => {
        // Variant 1A: Object destructuring
        const objDestructSource = `function handleObj({ data }: any) {
  return eval(data);
}`;
        expect(verifyJsonSourceProof(objDestructSource, "data", 2)).toBe(false);

        // Variant 1B: Renamed object destructuring
        const renamedObjSource = `function handleRenamed({ payload: data }: any) {
  return eval(data);
}`;
        expect(verifyJsonSourceProof(renamedObjSource, "data", 2)).toBe(false);

        // Variant 1C: Nested object destructuring
        const nestedObjSource = `function handleNested({ config: { data } }: any) {
  return eval(data);
}`;
        expect(verifyJsonSourceProof(nestedObjSource, "data", 2)).toBe(false);

        // Variant 1D: Array destructuring
        const arrayDestructSource = `const handleArray = ([ data ]: any) => {
  return eval(data);
};`;
        expect(verifyJsonSourceProof(arrayDestructSource, "data", 2)).toBe(false);

        // Variant 1E: Rest parameter
        const restParamSource = `function handleRest(...data: any[]) {
  return eval(data[0]);
}`;
        expect(verifyJsonSourceProof(restParamSource, "data", 2)).toBe(false);

        // All must throw in generateRemediationPatch
        const finding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Unsafe eval of destructured param",
          filePath: "src/params.ts",
          startLine: 2,
          endLine: 2,
          redactedEvidence: "  return eval(data);",
        });

        await expect(
          generateRemediationPatch({
            finding,
            scanJobId: "job-destruct-param",
            commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
            sourceContent: objDestructSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
      });

      it("variant 2: refuses assignments occurring after the eval() call", async () => {
        const postEvalAssignSource = `function handlePostAssign() {
  let data: any;
  eval(data);
  data = JSON.stringify({ safe: true });
}`;
        expect(verifyJsonSourceProof(postEvalAssignSource, "data", 3)).toBe(false);

        const postEvalConstSource = `function handlePostConst() {
  eval(data);
  const data = JSON.stringify({ safe: true });
}`;
        expect(verifyJsonSourceProof(postEvalConstSource, "data", 2)).toBe(false);

        const finding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Eval executed before safe assignment",
          filePath: "src/order.ts",
          startLine: 3,
          endLine: 3,
          redactedEvidence: "  eval(data);",
        });

        await expect(
          generateRemediationPatch({
            finding,
            scanJobId: "job-post-assign",
            commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
            sourceContent: postEvalAssignSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
      });

      it("variant 3: refuses variables shadowed in nested blocks or functions", async () => {
        // Outer safe const is shadowed in inner block by untrusted variable
        const shadowedBlockSource = `function handleShadow() {
  const data = JSON.stringify({ safe: true });
  {
    const data = req.body;
    eval(data);
  }
}`;
        expect(verifyJsonSourceProof(shadowedBlockSource, "data", 5)).toBe(false);

        // Outer safe const is shadowed by inner function parameter
        const shadowedFnSource = `function outer() {
  const data = JSON.stringify({ safe: true });
  function inner(data: any) {
    eval(data);
  }
}`;
        expect(verifyJsonSourceProof(shadowedFnSource, "data", 4)).toBe(false);

        const finding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Shadowed eval finding",
          filePath: "src/shadow.ts",
          startLine: 5,
          endLine: 5,
          redactedEvidence: "    eval(data);",
        });

        await expect(
          generateRemediationPatch({
            finding,
            scanJobId: "job-shadowed",
            commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
            sourceContent: shadowedBlockSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
      });

      it("variant 4: refuses multiple declarations, reassignments, and ambiguous scope", async () => {
        // Multiple declarations of the same variable
        const multiDeclSource = `function processMulti() {
  const data = JSON.stringify({ a: 1 });
  const data = JSON.stringify({ b: 2 });
  eval(data);
}`;
        expect(verifyJsonSourceProof(multiDeclSource, "data", 4)).toBe(false);

        // Intervening reassignment
        const reassignSource = `function processReassign(input: string) {
  let data = JSON.stringify({ safe: true });
  data = input;
  eval(data);
}`;
        expect(verifyJsonSourceProof(reassignSource, "data", 4)).toBe(false);

        // Compound assignment
        const compoundAssignSource = `function processCompound(input: string) {
  let data = JSON.stringify({ safe: true });
  data += input;
  eval(data);
}`;
        expect(verifyJsonSourceProof(compoundAssignSource, "data", 4)).toBe(false);

        const finding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Ambiguous / reassigned variable",
          filePath: "src/reassign.ts",
          startLine: 4,
          endLine: 4,
          redactedEvidence: "  eval(data);",
        });

        await expect(
          generateRemediationPatch({
            finding,
            scanJobId: "job-multi-decl",
            commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
            sourceContent: reassignSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
      });

      it("variant 5: refuses a safe-looking assignment outside the scope containing the eval() call", async () => {
        // Declared in helper function, but evaluated in unrelated function
        const externalScopeSource = `function helper() {
  const data = JSON.stringify({ safe: true });
  return data;
}

function process() {
  eval(data);
}`;
        expect(verifyJsonSourceProof(externalScopeSource, "data", 7)).toBe(false);

        // Declared in sibling closed block
        const siblingBlockSource = `function processSibling() {
  if (true) {
    const data = JSON.stringify({ safe: true });
  }
  eval(data);
}`;
        expect(verifyJsonSourceProof(siblingBlockSource, "data", 5)).toBe(false);

        const finding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Out-of-scope assignment",
          filePath: "src/scope.ts",
          startLine: 7,
          endLine: 7,
          redactedEvidence: "  eval(data);",
        });

        await expect(
          generateRemediationPatch({
            finding,
            scanJobId: "job-external-scope",
            commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
            sourceContent: externalScopeSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
      });

      it("variant 6: accepts valid JSON data initialized before the call without intervening reassignment", async () => {
        // Valid JSON.stringify
        const validStringifySource = `export function getValidConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(validStringifySource, "data", 3)).toBe(true);

        const stringifyFinding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Safe JSON stringify wrapper",
          filePath: "src/valid.ts",
          startLine: 3,
          endLine: 3,
          redactedEvidence: '  return eval("(" + data + ")");',
        });

        const patch1 = await generateRemediationPatch({
          finding: stringifyFinding,
          scanJobId: "job-valid-stringify",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: validStringifySource,
        });
        expect(patch1.unifiedDiff).toContain("+  return JSON.parse(data);");
        expect(patch1.unifiedDiff).toContain("-  return eval");

        // Valid static JSON string literal
        const validLiteralSource = `export function getStaticData() {
  const data = '{"safe": true, "version": 2}';
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(validLiteralSource, "data", 3)).toBe(true);

        const literalFinding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Safe static JSON literal wrapper",
          filePath: "src/literal.ts",
          startLine: 3,
          endLine: 3,
          redactedEvidence: '  return eval("(" + data + ")");',
        });

        const patch2 = await generateRemediationPatch({
          finding: literalFinding,
          scanJobId: "job-valid-literal",
          commitSha: "b710a299818728a4e4cb4851fca1607ae797a07b",
          sourceContent: validLiteralSource,
        });
        expect(patch2.unifiedDiff).toContain("+  return JSON.parse(data);");
        expect(patch2.unifiedDiff).toContain("-  return eval");
      });

      it("variant 7: rejects locally shadowed or overridden JSON binding whose stringify returns executable JavaScript text", async () => {
        // Shadowed JSON object with stringify returning executable JavaScript
        const shadowedJsonSource = `const JSON = {
  stringify: (_obj: unknown) => "alert('pwned:' + document.cookie)"
};

export function getShadowedConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(shadowedJsonSource, "data", 8)).toBe(false);

        const shadowedFinding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Shadowed JSON eval wrapper",
          filePath: "src/shadowed.ts",
          startLine: 8,
          endLine: 8,
          redactedEvidence: '  return eval("(" + data + ")");',
        });

        await expect(
          generateRemediationPatch({
            finding: shadowedFinding,
            scanJobId: "job-shadowed-json",
            commitSha: "4ccc63d101e0252858875be307c6e50c71e3fe68",
            sourceContent: shadowedJsonSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        // Mutated JSON.stringify property
        const mutatedJsonSource = `JSON.stringify = () => "evil()";
export function getMutatedConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(mutatedJsonSource, "data", 5)).toBe(false);

        // Imported custom JSON module
        const importedJsonSource = `import JSON from "custom-json-lib";
export function getImportedConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(importedJsonSource, "data", 5)).toBe(false);

        // Parameter binding named JSON
        const paramJsonSource = `export function getParamConfig(JSON: any) {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(paramJsonSource, "data", 4)).toBe(false);

        // Computed property overrides: globalThis["JSON"], window["JSON"], global["JSON"]
        const computedGlobalThisSource = `globalThis["JSON"] = {
  stringify: () => "alert('pwned-globalThis')"
};
export function getComputedGlobalThisConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(computedGlobalThisSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "globalThis computed override",
              filePath: "src/computed-globalthis.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-computed-globalthis",
            commitSha: "914e232a57a9f6175b7155dd128478a42f2944e2",
            sourceContent: computedGlobalThisSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        const computedWindowSource = `window["JSON"] = {
  stringify: () => "alert('pwned-window')"
};
export function getComputedWindowConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(computedWindowSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "window computed override",
              filePath: "src/computed-window.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-computed-window",
            commitSha: "597df2956fbb5aa5a07daa3222aa351c65cda9ce",
            sourceContent: computedWindowSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        const computedGlobalSource = `global["JSON"] = {
  stringify: () => "alert('pwned-global')"
};
export function getComputedGlobalConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(computedGlobalSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "global computed override",
              filePath: "src/computed-global.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-computed-global",
            commitSha: "8fbe68991b63bc048d15b8813f8431c83a71313b",
            sourceContent: computedGlobalSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        // Object.defineProperty(globalThis, "JSON", ...) & window/global variants
        const definePropGlobalThisSource = `Object.defineProperty(globalThis, "JSON", {
  value: { stringify: () => "alert('pwned-defineProperty')" }
});
export function getDefinePropConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(definePropGlobalThisSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Object.defineProperty globalThis override",
              filePath: "src/define-prop-globalthis.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-define-prop-globalthis",
            commitSha: "7667452d6fd28d88db387cd9e9f444f20c64a714",
            sourceContent: definePropGlobalThisSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        const definePropWindowSource = `Object.defineProperty(window, "JSON", {
  value: { stringify: () => "alert('pwned-window-defineProperty')" }
});
export function getDefinePropWindowConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(definePropWindowSource, "data", 7)).toBe(false);

        const definePropGlobalSource = `Object.defineProperty(global, "JSON", {
  value: { stringify: () => "alert('pwned-global-defineProperty')" }
});
export function getDefinePropGlobalConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(definePropGlobalSource, "data", 7)).toBe(false);

        // Object.defineProperties(globalThis, ...) when defining JSON & window variant
        const definePropertiesGlobalThisSource = `Object.defineProperties(globalThis, {
  JSON: { value: { stringify: () => "alert('pwned-defineProperties')" } }
});
export function getDefinePropertiesConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(definePropertiesGlobalThisSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Object.defineProperties globalThis override",
              filePath: "src/define-props-globalthis.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-define-props-globalthis",
            commitSha: "00616282095b9b7cf31a1171327a584f38f10a4c",
            sourceContent: definePropertiesGlobalThisSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        const definePropertiesWindowComputedSource = `Object.defineProperties(window, {
  ["JSON"]: { value: { stringify: () => "alert('pwned-defineProperties-window')" } }
});
export function getDefinePropertiesWindowConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(definePropertiesWindowComputedSource, "data", 7)).toBe(false);

        // Object.assign(globalThis, { JSON: ... }) & window/global variants
        const assignGlobalThisSource = `Object.assign(globalThis, {
  JSON: { stringify: () => "alert('pwned-assign-globalThis')" }
});
export function getAssignGlobalThisConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(assignGlobalThisSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Object.assign globalThis override",
              filePath: "src/assign-globalthis.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-assign-globalthis",
            commitSha: "f966442f9b129d272b933cb19ad855dd443c2da0",
            sourceContent: assignGlobalThisSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        const assignWindowSource = `Object.assign(window, {
  ["JSON"]: { stringify: () => "alert('pwned-assign-window')" }
});
export function getAssignWindowConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(assignWindowSource, "data", 7)).toBe(false);

        const assignGlobalSource = `Object.assign(global, {
  JSON: { stringify: () => "alert('pwned-assign-global')" }
});
export function getAssignGlobalConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(assignGlobalSource, "data", 7)).toBe(false);

        // Reflect.defineProperty(globalThis, "JSON", ...) & window/global variants
        const reflectDefinePropGlobalThisSource = `Reflect.defineProperty(globalThis, "JSON", {
  value: { stringify: () => "alert('pwned-reflect-globalThis')" }
});
export function getReflectDefinePropConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectDefinePropGlobalThisSource, "data", 7)).toBe(false);

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Reflect.defineProperty globalThis override",
              filePath: "src/reflect-globalthis.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-reflect-globalthis",
            commitSha: "11530fd6b3d9d6c68b2c88465536e472a320e530",
            sourceContent: reflectDefinePropGlobalThisSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        const reflectDefinePropWindowSource = `Reflect.defineProperty(window, "JSON", {
  value: { stringify: () => "alert('pwned-reflect-window')" }
});
export function getReflectDefinePropWindowConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectDefinePropWindowSource, "data", 7)).toBe(false);

        const reflectDefinePropGlobalSource = `Reflect.defineProperty(global, "JSON", {
  value: { stringify: () => "alert('pwned-reflect-global')" }
});
export function getReflectDefinePropGlobalConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectDefinePropGlobalSource, "data", 7)).toBe(false);

        // Reflect.set(globalThis, "JSON", ...) & window, global, self variants
        const reflectSetGlobalThisSource = `Reflect.set(globalThis, "JSON", {
  stringify: () => "alert('pwned-reflect-set-globalThis')"
});
export function getReflectSetConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetGlobalThisSource, "data", 7)).toBe(false);

        let llmCalledOnReflectSet = false;
        const mockLlmForReflectSet: LlmProvider = {
          getModelName: () => "mock-llm",
          isConfigured: () => true,
          generateText: async () => {
            llmCalledOnReflectSet = true;
            return "diff";
          },
        };

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Reflect.set globalThis override",
              filePath: "src/reflect-set-globalthis.ts",
              startLine: 7,
              endLine: 7,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-reflect-set-globalthis",
            commitSha: "b1239da346b012cc13f11467d50b950c791ed01e",
            sourceContent: reflectSetGlobalThisSource,
            llmProvider: mockLlmForReflectSet,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        // LLM must never be invoked for eval findings that fail verification
        expect(llmCalledOnReflectSet).toBe(false);

        // window variant
        const reflectSetWindowSource = `Reflect.set(window, "JSON", {
  stringify: () => "alert('pwned-reflect-set-window')"
});
export function getReflectSetWindowConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetWindowSource, "data", 7)).toBe(false);

        // global variant
        const reflectSetGlobalSource = `Reflect.set(global, "JSON", {
  stringify: () => "alert('pwned-reflect-set-global')"
});
export function getReflectSetGlobalConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetGlobalSource, "data", 7)).toBe(false);

        // self variant
        const reflectSetSelfSource = `Reflect.set(self, "JSON", {
  stringify: () => "alert('pwned-reflect-set-self')"
});
export function getReflectSetSelfConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetSelfSource, "data", 7)).toBe(false);

        // Computed "JSON" property names and wrapped expressions
        const reflectSetWrappedSource = `Reflect.set((window as any), ["JSON"], {
  stringify: () => "alert('pwned-reflect-set-wrapped')"
});
export function getReflectSetWrappedConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetWrappedSource, "data", 7)).toBe(false);

        const reflectSetTemplateSource = `Reflect.set(self, \`JSON\`, {
  stringify: () => "alert('pwned-reflect-set-template')"
});
export function getReflectSetTemplateConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetTemplateSource, "data", 7)).toBe(false);

        // Dynamic property key on global root fails closed
        const reflectSetDynamicSource = `const key = "JS" + "ON";
Reflect.set(globalThis, key, {
  stringify: () => "alert('pwned-dynamic')"
});
export function getReflectSetDynamicConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetDynamicSource, "data", 8)).toBe(false);

        // Positive control: Statically proven safe non-JSON property does not trigger false positive
        const reflectSetSafeSource = `Reflect.set(globalThis, "otherProp", 123);
export function getReflectSetSafeConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(reflectSetSafeSource, "data", 4)).toBe(true);

        // Indirect Object.assign via variable containing JSON
        const indirectAssignGlobalThisSource = `const overrides = {
  JSON: { stringify: () => "alert('pwned-indirect-assign')" }
};
Object.assign(globalThis, overrides);
export function getIndirectAssignConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectAssignGlobalThisSource, "data", 8)).toBe(false);

        let llmCalledOnIndirectAssign = false;
        const mockLlmForIndirectAssign: LlmProvider = {
          getModelName: () => "mock-llm",
          isConfigured: () => true,
          generateText: async () => {
            llmCalledOnIndirectAssign = true;
            return "diff";
          },
        };

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Indirect Object.assign globalThis override",
              filePath: "src/indirect-assign.ts",
              startLine: 8,
              endLine: 8,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-indirect-assign",
            commitSha: "6bedaf20e5d1dd79caed680ca1d634977ad4cd02",
            sourceContent: indirectAssignGlobalThisSource,
            llmProvider: mockLlmForIndirectAssign,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
        expect(llmCalledOnIndirectAssign).toBe(false);

        // window, global, self variants of indirect Object.assign
        const indirectAssignWindowSource = `const overrides = { JSON: { stringify: () => "alert('pwned-window')" } };
Object.assign(window, overrides);
export function getIndirectAssignWindow() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectAssignWindowSource, "data", 5)).toBe(false);

        const indirectAssignGlobalSource = `const overrides = { JSON: { stringify: () => "alert('pwned-global')" } };
Object.assign(global, overrides);
export function getIndirectAssignGlobal() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectAssignGlobalSource, "data", 5)).toBe(false);

        const indirectAssignSelfSource = `const overrides = { JSON: { stringify: () => "alert('pwned-self')" } };
Object.assign(self, overrides);
export function getIndirectAssignSelf() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectAssignSelfSource, "data", 5)).toBe(false);

        // Indirect Object.defineProperties via variable containing JSON
        const indirectDefinePropertiesSource = `const descriptors = {
  JSON: { value: { stringify: () => "alert('pwned-indirect-descriptors')" } }
};
Object.defineProperties(globalThis, descriptors);
export function getIndirectDefinePropsConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectDefinePropertiesSource, "data", 8)).toBe(false);

        let llmCalledOnIndirectDefineProps = false;
        const mockLlmForIndirectDefineProps: LlmProvider = {
          getModelName: () => "mock-llm",
          isConfigured: () => true,
          generateText: async () => {
            llmCalledOnIndirectDefineProps = true;
            return "diff";
          },
        };

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Indirect Object.defineProperties globalThis override",
              filePath: "src/indirect-define-properties.ts",
              startLine: 8,
              endLine: 8,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-indirect-define-props",
            commitSha: "36813142bf31cca3eea088f64d58f4683d32d5ab",
            sourceContent: indirectDefinePropertiesSource,
            llmProvider: mockLlmForIndirectDefineProps,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
        expect(llmCalledOnIndirectDefineProps).toBe(false);

        // window, global, self variants of indirect Object.defineProperties
        const indirectDefinePropsWindowSource = `const descriptors = { JSON: { value: { stringify: () => "alert('pwned-window')" } } };
Object.defineProperties(window, descriptors);
export function getIndirectDefinePropsWindow() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectDefinePropsWindowSource, "data", 5)).toBe(false);

        const indirectDefinePropsGlobalSource = `const descriptors = { JSON: { value: { stringify: () => "alert('pwned-global')" } } };
Object.defineProperties(global, descriptors);
export function getIndirectDefinePropsGlobal() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectDefinePropsGlobalSource, "data", 5)).toBe(false);

        const indirectDefinePropsSelfSource = `const descriptors = { JSON: { value: { stringify: () => "alert('pwned-self')" } } };
Object.defineProperties(self, descriptors);
export function getIndirectDefinePropsSelf() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(indirectDefinePropsSelfSource, "data", 5)).toBe(false);

        // Spread-based mutation sources: Object.assign(globalThis, { ...overrides })
        const spreadAssignSource = `const overrides = { JSON: { stringify: () => "alert('pwned-spread')" } };
Object.assign(globalThis, { ...overrides });
export function getSpreadAssignConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(spreadAssignSource, "data", 5)).toBe(false);

        let llmCalledOnSpreadAssign = false;
        const mockLlmForSpreadAssign: LlmProvider = {
          getModelName: () => "mock-llm",
          isConfigured: () => true,
          generateText: async () => {
            llmCalledOnSpreadAssign = true;
            return "diff";
          },
        };

        await expect(
          generateRemediationPatch({
            finding: makeFinding({
              scanner: "semgrep",
              ruleId: "semgrep:eval-detected",
              title: "Spread Object.assign globalThis override",
              filePath: "src/spread-assign.ts",
              startLine: 5,
              endLine: 5,
              redactedEvidence: '  return eval("(" + data + ")");',
            }),
            scanJobId: "job-spread-assign",
            commitSha: "f2a8df492b87efd051a482d45c1b1eab1e928165",
            sourceContent: spreadAssignSource,
            llmProvider: mockLlmForSpreadAssign,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);
        expect(llmCalledOnSpreadAssign).toBe(false);

        // Unknown/unresolved spread sources fail closed
        const unknownSpreadAssignSource = `Object.assign(globalThis, { ...unknownOverrides });
export function getUnknownSpreadConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(unknownSpreadAssignSource, "data", 4)).toBe(false);

        const unknownSpreadDefinePropsSource = `Object.defineProperties(globalThis, { ...unknownDescriptors });
export function getUnknownSpreadDefinePropsConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(unknownSpreadDefinePropsSource, "data", 4)).toBe(false);

        // Unresolved computed property in object literal fails closed
        const unresolvedComputedAssignSource = `const dynamicKey = "JSON";
Object.assign(globalThis, { [dynamicKey]: { stringify: () => "evil" } });
export function getUnresolvedComputedConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(unresolvedComputedAssignSource, "data", 5)).toBe(false);

        // Safe, statically inspectable non-JSON sources allow verified safe eval remediation
        const safeAssignVarSource = `const safeOverrides = { otherProp: 123 };
Object.assign(globalThis, safeOverrides);
export function getSafeAssignVarConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(safeAssignVarSource, "data", 5)).toBe(true);

        const safeAssignLiteralSource = `Object.assign(globalThis, { otherProp: 123, foo: "bar" });
export function getSafeAssignLiteralConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(safeAssignLiteralSource, "data", 4)).toBe(true);

        const safeSpreadAssignSource = `const safeBase = { otherProp: 123 };
Object.assign(globalThis, { ...safeBase, directProp: 456 });
export function getSafeSpreadAssignConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(safeSpreadAssignSource, "data", 5)).toBe(true);

        const safeDefinePropertiesSource = `const safeDescriptors = { otherProp: { value: 123 } };
Object.defineProperties(globalThis, safeDescriptors);
export function getSafeDefinePropsConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(safeDefinePropertiesSource, "data", 5)).toBe(true);

        const safeComputedNonJsonSource = `Object.assign(globalThis, { ["other"]: 123 });
export function getSafeComputedNonJsonConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(safeComputedNonJsonSource, "data", 4)).toBe(true);

        // Unrelated eligible remediation (e.g. security headers) remains functional
        const headerFinding = makeFinding({
          ruleId: "security-headers-missing",
          title: "Missing nosniff header",
          filePath: "src/server.ts",
          startLine: 1,
          redactedEvidence: "res.status(200);",
        });
        const headerPatch = await generateRemediationPatch({
          finding: headerFinding,
          scanJobId: "job-header",
          commitSha: "39c110af561d754551bebc5c20df780f94f43d09",
        });
        expect(headerPatch.eligibility.canAutoFix).toBe(true);
        expect(headerPatch.unifiedDiff).toContain("res.headers.set('X-Content-Type-Options', 'nosniff');");
      });

      it("variant 8: fails closed on TypeScript parse diagnostics for malformed source containing otherwise safe-looking declarations", async () => {
        // Syntax error: missing expression before semicolon
        const syntaxErrorSource = `export function getMalformedConfig() {
  const bad = ;
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(syntaxErrorSource, "data", 5)).toBe(false);

        const malformedFinding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Malformed source containing safe-looking declaration",
          filePath: "src/malformed.ts",
          startLine: 5,
          endLine: 5,
          redactedEvidence: '  return eval("(" + data + ")");',
        });

        await expect(
          generateRemediationPatch({
            finding: malformedFinding,
            scanJobId: "job-malformed-syntax",
            commitSha: "0d16892e4c33c8c3283e86af96a90bde3b887cbc",
            sourceContent: syntaxErrorSource,
          })
        ).rejects.toThrow(/Cannot automatically replace eval\(\) with JSON\.parse\(\)/);

        // Syntax error: unclosed block and missing paren
        const unclosedSource = `export function getUnclosedConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")"
`;
        expect(verifyJsonSourceProof(unclosedSource, "data", 3)).toBe(false);
      });

      it("variant 9: fails closed on ambiguous target calls and mismatched lines", async () => {
        // Multiple matching calls without line specified: ambiguous
        const multiCallSource = `export function getMultiCallConfig() {
  const data = JSON.stringify({ safe: true });
  eval("(" + data + ")");
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(multiCallSource, "data")).toBe(false);

        // Multiple calls on the exact same line: ambiguous
        const sameLineSource = `export function getSameLineConfig() {
  const data = JSON.stringify({ safe: true });
  eval(data); eval(data);
}`;
        expect(verifyJsonSourceProof(sameLineSource, "data", 3)).toBe(false);

        // Mismatched line number (single call on line 4, but line 99 requested)
        const singleCallSource = `export function getSingleConfig() {
  const data = JSON.stringify({ safe: true });
  return eval("(" + data + ")");
}`;
        expect(verifyJsonSourceProof(singleCallSource, "data", 99)).toBe(false);
      });

      it("end-to-end disposable fixture: reproduced bypass is refused across full preview lifecycle, while proven safe wrapper succeeds and verifies", async () => {
        const store = new InMemoryJobStore();
        const job = await store.create({
          owner: "test-user",
          repo: "vulnerable-app",
          repositoryUrl: "https://github.com/test-user/vulnerable-app",
          expiresAt: new Date(Date.now() + 3600000),
        });
        await store.update(job.id, {
          status: "completed",
          commitSha: "03d932328cb48710e459041d44c6e8ccac2e3d95",
          defaultBranch: "main",
        });

        const bypassSource = `function process({ data }: any) {
  eval(data);
  data = JSON.stringify({ safe: true });
}`;
        const bypassFinding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Reproduced bypass finding",
          filePath: "src/bypass.ts",
          fingerprint: "fp-bypass-e2e",
          startLine: 2,
          endLine: 2,
          redactedEvidence: "  eval(data);",
        });

        const safeSource = `export function getSafeConfig() {
  const safeData = JSON.stringify({ active: true, env: "prod" });
  return eval("(" + safeData + ")");
}`;
        const safeFinding = makeFinding({
          scanner: "semgrep",
          ruleId: "semgrep:eval-detected",
          title: "Legitimate safe config finding",
          filePath: "src/config.ts",
          fingerprint: "fp-safe-e2e",
          startLine: 3,
          endLine: 3,
          redactedEvidence: '  return eval("(" + safeData + ")");',
        });

        await store.saveFindings(job.id, [bypassFinding, safeFinding]);
        const { findings } = await store.getFindings(job.id);
        const persistedBypass = findings.find((f) => f.fingerprint === "fp-bypass-e2e")!;
        const persistedSafe = findings.find((f) => f.fingerprint === "fp-safe-e2e")!;

        const deps: RemediationDeps = {
          store,
          sourceFiles: {
            "src/bypass.ts": bypassSource,
            "src/config.ts": safeSource,
          },
          scanEngine: async (dir: string) => {
            const fs = await import("node:fs/promises");
            const path = await import("node:path");
            const configContent = await fs.readFile(path.join(dir, "src/config.ts"), "utf8").catch(() => "");
            const hasEval = /\beval\s*\(/.test(configContent);
            return {
              status: "completed" as const,
              findings: hasEval ? [safeFinding] : [],
              counts: { critical: hasEval ? 1 : 0, high: 0, medium: 0, low: 0, info: 0, total: hasEval ? 1 : 0 },
              gitleaksStatus: "completed" as const,
              gitleaksDurationMs: 5,
              gitleaksError: null,
              semgrepStatus: "completed" as const,
              semgrepDurationMs: 20,
              semgrepError: null,
              osvStatus: "completed" as const,
              osvDurationMs: 5,
              osvError: null,
              scannerVersions: { gitleaks: "8.18", semgrep: "1.60", osvScanner: "2.7" },
              scanCoverage: { lockfilesFound: [], scannersRun: ["gitleaks", "semgrep", "osv-scanner"], limitations: [] },
            };
          },
        };

        // 1. Direct generation on reproduced bypass throws
        await expect(
          generateRemediationPatch({
            finding: persistedBypass,
            scanJobId: job.id,
            commitSha: "03d932328cb48710e459041d44c6e8ccac2e3d95",
            sourceContent: bypassSource,
          })
        ).rejects.toThrow(
          /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
        );

        // 2. createPreview returns an empty diff with unsuitable eligibility requiring manual review
        const bypassPreview = await createPreview(job.id, persistedBypass.id, deps);
        expect(bypassPreview.unifiedDiff).toBe("");
        expect(bypassPreview.eligibility).toBe("unsuitable");
        expect(bypassPreview.eligibilityReason).toMatch(
          /Cannot automatically replace eval\(\) with JSON\.parse\(\) without verified JSON source context/
        );
        expect(bypassPreview.warnings).toContain(
          "No automated fix could be safely generated. Please review and apply changes manually."
        );

        // 3. Attempting to approve an unsuitable finding must fail
        await expect(approveRemediation(job.id, bypassPreview.id, deps, TEST_OWNER)).rejects.toThrow(
          /requires manual intervention and cannot be auto-approved/
        );

        // 4. Attempting to apply unapproved preview must fail
        await expect(applyAndVerify(job.id, bypassPreview.id, deps, TEST_OWNER)).rejects.toThrow(
          /Explicit user approval is required/
        );

        // 5. Contrasting legitimate safe finding: createPreview succeeds
        const safePreview = await createPreview(job.id, persistedSafe.id, deps);
        expect(safePreview.unifiedDiff).toContain("JSON.parse(safeData)");
        expect(safePreview.status).toBe("preview");

        // 3. User approval is mandatory
        const approved = await approveRemediation(job.id, safePreview.id, deps, TEST_OWNER);
        expect(approved.status).toBe("approved");

        // 4. Sandboxed verification applies patch and confirms 0 regressions
        const verified = await applyAndVerify(job.id, safePreview.id, deps, TEST_OWNER);
        expect(verified.status).toBe("verified");
        expect(verified.rescanStatus).toBe("verified");
      });
    });
  });

  describe("8. Manifest-Aware Dependency Auto-Fix & OSV Fixed Version Suite (Phase 3)", () => {
    it("consistently resolves OSV fixed version across metadata and packageInfo", () => {
      // 1. Fixed version in packageInfo
      const findingWithPkgInfo = makeFinding({
        category: "Dependencies",
        scanner: "osv-scanner",
        filePath: "backend/requirements.txt",
        packageInfo: { name: "pytest", version: "7.1.0", fixedVersion: "7.4.4" },
      });
      expect(resolveFindingFixedVersion(findingWithPkgInfo)).toBe("7.4.4");
      const elig1 = classifyRemediationEligibility(findingWithPkgInfo);
      expect(elig1.canAutoFix).toBe(true);
      expect(elig1.eligibility).toBe("potentially_breaking");

      // 2. Fixed version in metadata (legacy OSV output)
      const findingWithMetadata = makeFinding({
        category: "Dependencies",
        scanner: "osv-scanner",
        filePath: "backend/requirements.txt",
        packageInfo: { name: "pytest", version: "7.1.0" },
        metadata: { fixedVersion: "7.4.4" },
      });
      expect(resolveFindingFixedVersion(findingWithMetadata)).toBe("7.4.4");
      const elig2 = classifyRemediationEligibility(findingWithMetadata);
      expect(elig2.canAutoFix).toBe(true);
      expect(elig2.eligibility).toBe("potentially_breaking");

      // 3. No fixed version
      const unpatchedFinding = makeFinding({
        category: "Dependencies",
        scanner: "osv-scanner",
        filePath: "backend/requirements.txt",
        packageInfo: { name: "pytest", version: "7.1.0" },
      });
      expect(resolveFindingFixedVersion(unpatchedFinding)).toBeNull();
      const elig3 = classifyRemediationEligibility(unpatchedFinding);
      expect(elig3.canAutoFix).toBe(false);
      expect(elig3.eligibility).toBe("unsuitable");
      expect(elig3.reason).toMatch(/No upstream patched version/i);

      // 4. Parity test: verify pytest finding projected to client via toPublicFinding produces identical classification
      const storeRecord: FindingRecord = {
        id: "find-pytest-parity",
        scanJobId: "job-parity",
        fingerprint: "fp-pytest-parity",
        scanner: "osv-scanner",
        ruleId: "GHSA-4567",
        category: "Dependencies",
        severity: "high",
        originalSeverity: "HIGH",
        title: "Pytest vulnerable",
        description: "Vulnerable pytest package",
        filePath: "backend/requirements.txt",
        startLine: 2,
        endLine: 2,
        redactedEvidence: "pytest==7.1.0",
        vulnerabilityId: "GHSA-4567",
        remediation: "Upgrade pytest to 7.4.4",
        packageInfo: { name: "pytest", version: "7.1.0", fixedVersion: "7.4.4", ecosystem: "PyPI" },
        metadata: { fixedVersion: "7.4.4" },
        aiExplanation: null,
        createdAt: new Date(),
      };

      const serverClassification = classifyRemediationEligibility(storeRecord);
      const publicFinding = toPublicFinding(storeRecord);
      const clientClassification = classifyRemediationEligibility(publicFinding);

      expect(serverClassification.canAutoFix).toBe(true);
      expect(clientClassification.canAutoFix).toBe(true);
      expect(clientClassification.eligibility).toBe("potentially_breaking");
      expect(clientClassification).toEqual(serverClassification);
    });

    it("generates a valid Python requirements.txt patch for pytest without npm JSON syntax", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-owner",
        repo: "test-repo",
        repositoryUrl: "https://github.com/test-owner/test-repo",
        expiresAt: new Date(Date.now() + 86400000),
      });
      await store.update(job.id, { status: "completed", commitSha: "0ab17293d0cd91dd0de67f78a876a12f9066f0cc" });

      const initialRequirements = [
        "flask==2.2.5",
        "pytest==7.1.0",
        "requests==2.31.0",
        "",
      ].join("\n");

      const pytestFinding = makeFinding({
        scanner: "osv-scanner",
        ruleId: "osv:GHSA-4567",
        category: "Dependencies",
        severity: "high",
        title: "Pytest vulnerable to improper temporary directory handling",
        filePath: "backend/requirements.txt",
        packageInfo: {
          name: "pytest",
          version: "7.1.0",
          fixedVersion: "7.4.4",
          ecosystem: "PyPI",
        },
        metadata: {
          fixedVersion: "7.4.4",
        },
        fingerprint: "fp-pytest-001",
      });

      await store.saveFindings(job.id, [pytestFinding]);
      const [savedPytest] = (await store.getFindings(job.id)).findings;

      const sourceFiles: Record<string, string> = {
        "backend/requirements.txt": initialRequirements,
      };

      const scanEngine = async (): Promise<ScanEngineResult> => {
        // Mock scanner: once pytest is upgraded to 7.4.4, vulnerability is resolved
        return {
          status: "completed" as const,
          findings: [],
          gitleaksStatus: "completed",
          gitleaksDurationMs: 5,
          gitleaksError: null,
          semgrepStatus: "completed",
          semgrepDurationMs: 10,
          semgrepError: null,
          osvStatus: "completed",
          osvDurationMs: 10,
          osvError: null,
          scannerVersions: { gitleaks: "8.18", semgrep: "1.182", osvScanner: "2.7" },
          scanCoverage: { lockfilesFound: ["backend/requirements.txt"], scannersRun: ["osv-scanner"], limitations: [] },
          counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        };
      };

      const deps: RemediationDeps = {
        store,
        sourceFiles,
        scanEngine,
      };

      // 1. Preview generation
      const preview = await createPreview(job.id, savedPytest.id, deps);
      expect(preview.status).toBe("preview");
      expect(preview.eligibility).toBe("potentially_breaking");
      expect(preview.affectedFiles).toEqual(["backend/requirements.txt"]);

      // Diff must contain valid Python requirements syntax and NOT npm JSON syntax
      expect(preview.unifiedDiff).toContain("--- a/backend/requirements.txt");
      expect(preview.unifiedDiff).toContain("+++ b/backend/requirements.txt");
      expect(preview.unifiedDiff).toContain("-pytest==7.1.0");
      expect(preview.unifiedDiff).toContain("+pytest==7.4.4");
      expect(preview.unifiedDiff).not.toContain('"pytest":');
      expect(preview.unifiedDiff).not.toContain('"1.0.1"');

      // 2. Read-only preview: base source content is NOT mutated
      expect(sourceFiles["backend/requirements.txt"]).toBe(initialRequirements);

      // 3. Unapproved apply is rejected
      await expect(applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(
        /Explicit user approval is required/
      );

      // 4. User approves patch
      const approved = await approveRemediation(job.id, preview.id, deps, TEST_OWNER);
      expect(approved.status).toBe("approved");

      // 5. Sandboxed execution applies patch and rescan verifies resolution
      const verified = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);
      expect(verified.status).toBe("verified");
      expect(verified.rescanStatus).toBe("verified");
      expect(verified.rescanSummary?.targetResolved).toBe(true);
      expect(verified.rescanSummary?.resolvedFingerprints).toContain("fp-pytest-001");
      expect(verified.rescanSummary?.newFindingsCount).toBe(0);
    });

    it("proves pytest vulnerability resolution with real OSV-Scanner binary and sandbox rescan", async (ctx) => {
      // 1. Verify OSV-Scanner is available in this environment
      const osvAvailable = await runSubprocess("osv-scanner", ["--version"], { cwd: process.cwd(), timeoutMs: 5000 })
        .then((r) => r.exitCode === 0)
        .catch(() => false);

      if (!osvAvailable) {
        // Reported as skipped (never as passed); `npm run test:scanners` makes this a failure instead.
        if (process.env.REQUIRE_REAL_SCANNERS === "1") throw new Error("osv-scanner is required but not installed");
        ctx.skip();
      }

      // 2. Controlled fixture with vulnerable pytest declaration retaining markers and extras
      const initialRequirements = [
        "# Controlled fixture dependencies",
        "pytest[testing]==7.1.0; python_version >= '3.8' # test runner",
        "",
      ].join("\n");

      const fs = await import("node:fs/promises");
      const os = await import("node:os");
      const path = await import("node:path");

      // Verify real scanner detects vulnerable pytest on initial manifest
      const tmpFixtureDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibe-osv-pre-"));
      await fs.mkdir(path.join(tmpFixtureDir, "backend"), { recursive: true });
      await fs.writeFile(path.join(tmpFixtureDir, "backend/requirements.txt"), initialRequirements);

      const preScan = await runOsvScan(tmpFixtureDir);
      await fs.rm(tmpFixtureDir, { recursive: true, force: true });

      expect(preScan.status).toBe("completed");
      const pytestFinding = preScan.findings.find(
        (f) => f.packageInfo?.name?.toLowerCase() === "pytest" && f.packageInfo?.fixedVersion
      );

      expect(pytestFinding).toBeDefined();
      const realFixedVersion = pytestFinding!.packageInfo!.fixedVersion!;
      expect(realFixedVersion).toBe("9.0.3"); // Confirmed by official OSV PyPI advisory GHSA-6w46-j5rx-g56g

      // 3. Set up store and job
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-owner",
        repo: "test-repo",
        repositoryUrl: "https://github.com/test-owner/test-repo",
        expiresAt: new Date(Date.now() + 86400000),
      });
      await store.update(job.id, { status: "completed", commitSha: "776b42ead4e72e55ff90cb2bdc0ac63a6a55a2e0" });
      await store.saveFindings(job.id, preScan.findings);
      const { findings: savedFindings } = await store.getFindings(job.id);
      const savedFinding = savedFindings.find(
        (f) => f.fingerprint === pytestFinding!.fingerprint
      )!;

      const sourceFiles: Record<string, string> = {
        "backend/requirements.txt": initialRequirements,
      };

      // Real OSV-Scanner rescan engine executing the actual binary against the patched workspace
      const realScannerEngine = async (workspaceDir: string): Promise<ScanEngineResult> => {
        const osvRes = await runOsvScan(workspaceDir);
        return {
          status: osvRes.status === "failed" ? "failed" : "completed",
          findings: osvRes.findings,
          gitleaksStatus: "completed",
          gitleaksDurationMs: 0,
          gitleaksError: null,
          semgrepStatus: "completed",
          semgrepDurationMs: 0,
          semgrepError: null,
          osvStatus: osvRes.status,
          osvDurationMs: osvRes.durationMs,
          osvError: osvRes.error ?? null,
          scannerVersions: { gitleaks: "8.18", semgrep: "1.182", osvScanner: "2.7.0" },
          scanCoverage: {
            lockfilesFound: osvRes.coverage?.lockfilesFound ?? ["backend/requirements.txt"],
            scannersRun: ["osv-scanner"],
            limitations: [],
          },
          counts: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            total: osvRes.findings.length,
          },
        };
      };

      const deps: RemediationDeps = {
        store,
        sourceFiles,
        scanEngine: realScannerEngine,
      };

      // 4. Generate preview
      const preview = await createPreview(job.id, savedFinding.id, deps);
      expect(preview.status).toBe("preview");
      expect(preview.eligibility).toBe("potentially_breaking");
      expect(preview.affectedFiles).toEqual(["backend/requirements.txt"]);

      // Diff must contain valid requirements.txt syntax with real fixed version and preserved extras/markers
      expect(preview.unifiedDiff).toContain("-pytest[testing]==7.1.0; python_version >= '3.8' # test runner");
      expect(preview.unifiedDiff).toContain(`+pytest[testing]==${realFixedVersion}; python_version >= '3.8' # test runner`);

      // Read-only: base source not mutated
      expect(sourceFiles["backend/requirements.txt"]).toBe(initialRequirements);

      // 5. Unapproved apply is rejected
      await expect(applyAndVerify(job.id, preview.id, deps, TEST_OWNER)).rejects.toThrow(
        /Explicit user approval is required/
      );

      // 6. User approval
      const approved = await approveRemediation(job.id, preview.id, deps, TEST_OWNER);
      expect(approved.status).toBe("approved");

      // 7. Apply patch in sandbox and execute REAL OSV-Scanner rescan
      const verified = await applyAndVerify(job.id, preview.id, deps, TEST_OWNER);
      expect(verified.status).toBe("verified");
      expect(verified.rescanStatus).toBe("verified");
      expect(verified.rescanSummary?.targetResolved).toBe(true);
      expect(verified.rescanSummary?.resolvedFingerprints).toContain(pytestFinding!.fingerprint);
      expect(verified.rescanSummary?.newFindingsCount).toBe(0);
      expect(verified.rescanSummary?.remainingFingerprints).toHaveLength(0);
      expect(verified.rescanSummary?.postRescanFindingsCount).toBe(0);
    }, 60_000); // live OSV API

    it("preserves Python environment markers, extras, and comments during requirements patch", () => {
      const manifest = [
        "# Core dependencies",
        "flask==2.2.5 # web framework",
        "  pytest[testing] == 7.1.0 ; python_version >= '3.8' # test suite",
        "requests==2.31.0",
      ].join("\n");

      const result = updatePythonRequirementsContent(manifest, "pytest", "7.4.4");
      expect(result).not.toBeNull();
      expect(result?.newLine).toBe("  pytest[testing] == 7.4.4 ; python_version >= '3.8' # test suite");
      expect(result?.oldLine).toBe("  pytest[testing] == 7.1.0 ; python_version >= '3.8' # test suite");

      const diff = [
        "--- a/requirements.txt",
        "+++ b/requirements.txt",
        `@@ -${result!.lineIndex + 1},1 +${result!.lineIndex + 1},1 @@`,
        `-${result!.oldLine}`,
        `+${result!.newLine}`,
        "",
      ].join("\n");

      const applied = applyUnifiedDiffString(manifest, diff);
      expect(applied).toBe(result?.updatedContent);
      expect(applied).toContain("pytest[testing] == 7.4.4 ; python_version >= '3.8' # test suite");
    });

    it("updates Node.js package.json preserving prefix and formatting", () => {
      const pkgJson = JSON.stringify(
        {
          name: "test-app",
          dependencies: {
            express: "^4.18.2",
            lodash: "^4.17.20",
          },
        },
        null,
        2
      );

      const result = updatePackageJsonContent(pkgJson, "lodash", "4.17.21");
      expect(result).not.toBeNull();
      expect(result?.newLine).toContain('"lodash": "^4.17.21"');
      expect(result?.oldLine).toContain('"lodash": "^4.17.20"');
      expect(result?.updatedContent).toContain('"lodash": "^4.17.21"');
      expect(result?.updatedContent).toContain('"express": "^4.18.2"');
    });

    it("refuses auto-fixing with explicit manual-review reason when dependency is not declared in manifest", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-owner",
        repo: "test-repo",
        repositoryUrl: "https://github.com/test-owner/test-repo",
        expiresAt: new Date(Date.now() + 86400000),
      });
      await store.update(job.id, { commitSha: "48d02bf682e591b1f2b85dea908fe1f412501664" });

      const finding = makeFinding({
        scanner: "osv-scanner",
        ruleId: "osv:GHSA-9999",
        category: "Dependencies",
        filePath: "backend/requirements.txt",
        packageInfo: { name: "urllib3", version: "1.26.4", fixedVersion: "1.26.5" },
        metadata: { fixedVersion: "1.26.5" },
      });

      await store.saveFindings(job.id, [finding]);
      const [savedFinding] = (await store.getFindings(job.id)).findings;

      const deps: RemediationDeps = {
        store,
        sourceFiles: {
          "backend/requirements.txt": "requests==2.31.0\npytest==7.4.4\n",
        },
      };

      const preview = await createPreview(job.id, savedFinding.id, deps);
      expect(preview.unifiedDiff).toBe("");
      expect(preview.eligibility).toBe("unsuitable");
      expect(preview.eligibilityReason).toMatch(/not found in manifest/i);
    });

    it("refuses auto-fixing with explicit manual-review reason when manifest content is unavailable", async () => {
      const store = new InMemoryJobStore();
      const job = await store.create({
        owner: "test-owner",
        repo: "test-repo",
        repositoryUrl: "https://github.com/test-owner/test-repo",
        expiresAt: new Date(Date.now() + 86400000),
      });
      await store.update(job.id, { commitSha: "b63bd3d9320b6eb0908bf9561cdf5a35fd65e947" });

      const finding = makeFinding({
        scanner: "osv-scanner",
        ruleId: "osv:GHSA-pytest",
        category: "Dependencies",
        filePath: "backend/requirements.txt",
        packageInfo: { name: "pytest", version: "7.1.0", fixedVersion: "7.4.4" },
        metadata: { fixedVersion: "7.4.4" },
      });

      await store.saveFindings(job.id, [finding]);
      const [savedFinding2] = (await store.getFindings(job.id)).findings;

      const deps: RemediationDeps = {
        store,
        // No sourceFiles and no fetchImpl
      };

      const preview = await createPreview(job.id, savedFinding2.id, deps);
      expect(preview.unifiedDiff).toBe("");
      expect(preview.eligibility).toBe("unsuitable");
      expect(preview.eligibilityReason).toMatch(/source content is unavailable/i);
    });
  });
});

