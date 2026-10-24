import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runGitleaksScan } from "@/server/scanners/gitleaks";
import { runSemgrepScan } from "@/server/scanners/semgrep";
import { runOsvScan } from "@/server/scanners/osv";
import { runSecurityScanEngine, detectScannerVersions } from "@/server/scanners/engine";
import { redactText, redactEvidence, computeFingerprint } from "@/server/scanners/redact";
import { runSubprocess } from "@/server/scanners/runner";

describe("Security Scanners Integration & Acceptance", () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = await mkdtemp(path.join(tmpdir(), "vibeshield-test-"));
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true }).catch(() => undefined);
  });

  describe("Gitleaks — Secret Detection", () => {
    it("detects fake harmless token and redacts secret values", async () => {
      const fakeToken = ["ghp", "012345678901234567890123456789012345"].join("_");
      await writeFile(path.join(testDir, "config.ts"), `export const token = "${fakeToken}";\n`);

      const result = await runGitleaksScan(testDir);
      expect(result.status).toBe("completed");
      expect(result.findings.length).toBeGreaterThanOrEqual(1);

      const secretFinding = result.findings.find((f) => f.ruleId === "github-pat");
      expect(secretFinding).toBeDefined();
      expect(secretFinding?.category).toBe("Secrets");
      expect(secretFinding?.severity).toBe("critical");
      expect(secretFinding?.filePath).toBe("config.ts");
      expect(secretFinding?.startLine).toBe(1);

      // Redaction verification: raw token must NEVER appear anywhere in the finding object
      const findingJson = JSON.stringify(secretFinding);
      expect(findingJson).not.toContain(fakeToken);
      expect(secretFinding?.redactedEvidence).toContain("REDACTED");
    });

    it("returns clean completed result for repository with no secrets", async () => {
      await writeFile(path.join(testDir, "index.ts"), `export function add(a: number, b: number) { return a + b; }\n`);
      const result = await runGitleaksScan(testDir);
      expect(result.status).toBe("completed");
      expect(result.findings).toHaveLength(0);
    });

    it("handles missing executable gracefully without crashing", async () => {
      const result = await runGitleaksScan(testDir, { binaryPath: "nonexistent-gitleaks-binary" });
      expect(result.status).toBe("failed");
      expect(result.error).toBeDefined();
      expect(result.findings).toHaveLength(0);
    });
  });

  describe("Semgrep — Static Code Analysis", () => {
    it("detects insecure code constructs from controlled ruleset", async () => {
      const insecureCode = `
        function runCode(userInput: string) {
          eval("const x = " + userInput);
          const cp = require("child_process");
          cp.exec(userInput);
        }
      `;
      await writeFile(path.join(testDir, "vulnerable.ts"), insecureCode);

      const result = await runSemgrepScan(testDir);
      expect(result.status).toBe("completed");
      expect(result.findings.length).toBeGreaterThanOrEqual(2);

      const evalFinding = result.findings.find((f) => f.ruleId === "js-code-execution-eval");
      expect(evalFinding).toBeDefined();
      expect(evalFinding?.category).toBe("Code Analysis");
      expect(evalFinding?.severity).toBe("critical");
      expect(evalFinding?.filePath).toBe("vulnerable.ts");
      expect(evalFinding?.remediation).toBeDefined();

      const execFinding = result.findings.find((f) => f.ruleId === "js-command-injection-child-process");
      expect(execFinding).toBeDefined();
      expect(execFinding?.category).toBe("Code Analysis");
      expect(execFinding?.severity).toBe("critical");
    });

    it("returns clean result for safe code", async () => {
      await writeFile(
        path.join(testDir, "safe.ts"),
        `export function multiply(x: number, y: number) { return x * y; }\n`,
      );
      const result = await runSemgrepScan(testDir);
      expect(result.status).toBe("completed");
      expect(result.findings).toHaveLength(0);
    });

    it("handles missing executable gracefully", async () => {
      const result = await runSemgrepScan(testDir, { binaryPath: "nonexistent-semgrep-binary" });
      expect(result.status).toBe("failed");
      expect(result.error).toBeDefined();
    });
  });

  describe("OSV-Scanner — Dependency Vulnerabilities", () => {
    it("detects vulnerable dependencies from package-lock.json fixture", async () => {
      const lockfileContent = {
        name: "test-project",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "test-project",
            version: "1.0.0",
            dependencies: {
              lodash: "4.17.15",
            },
          },
          "node_modules/lodash": {
            version: "4.17.15",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
          },
        },
      };

      await writeFile(path.join(testDir, "package-lock.json"), JSON.stringify(lockfileContent, null, 2));

      const result = await runOsvScan(testDir);
      expect(result.status).toBe("completed");
      expect(result.coverage?.lockfilesFound).toContain("package-lock.json");
      expect(result.findings.length).toBeGreaterThan(0);

      const lodashVuln = result.findings.find((f) => f.packageInfo?.name === "lodash");
      expect(lodashVuln).toBeDefined();
      expect(lodashVuln?.category).toBe("Dependencies");
      expect(lodashVuln?.filePath).toBe("package-lock.json");
      expect(lodashVuln?.vulnerabilityId).toMatch(/^(GHSA-|CVE-)/);
      expect(lodashVuln?.remediation).toContain("Upgrade lodash to version");
    });

    it("accurately reports unsupported or missing lockfiles when none present", async () => {
      await writeFile(path.join(testDir, "readme.txt"), "No dependencies here");
      const result = await runOsvScan(testDir);
      expect(result.status).toBe("completed");
      expect(result.findings).toHaveLength(0);
      expect(result.coverage?.lockfilesFound).toHaveLength(0);
      expect(result.coverage?.limitations?.[0]).toContain("No supported dependency lockfiles");
    });

    it("handles missing executable gracefully", async () => {
      const result = await runOsvScan(testDir, { binaryPath: "nonexistent-osv-binary" });
      expect(result.status).toBe("failed");
      expect(result.error).toBeDefined();
    });
  });

  describe("Scan Engine Orchestration, Dedup & Coverage", () => {
    it("detects scanner versions", async () => {
      const versions = await detectScannerVersions();
      expect(versions.gitleaks).not.toBeNull();
      expect(versions.semgrep).not.toBeNull();
      expect(versions.osvScanner).not.toBeNull();
    });

    it("orchestrates all 3 scanners and deduplicates findings", async () => {
      // 1. Fake secret
      await writeFile(path.join(testDir, "secrets.ts"), `const key = "ghp_012345678901234567890123456789012345";\n`);
      // 2. Insecure eval
      await writeFile(path.join(testDir, "insecure.ts"), `eval("1+1");\n`);
      // 3. Vulnerable lodash lockfile
      const lockfile = {
        name: "test-app",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": { name: "test-app", version: "1.0.0", dependencies: { lodash: "4.17.15" } },
          "node_modules/lodash": {
            version: "4.17.15",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
          },
        },
      };
      await writeFile(path.join(testDir, "package-lock.json"), JSON.stringify(lockfile, null, 2));

      const engineResult = await runSecurityScanEngine(testDir);
      expect(engineResult.status).toBe("completed");
      expect(engineResult.gitleaksStatus).toBe("completed");
      expect(engineResult.semgrepStatus).toBe("completed");
      expect(engineResult.osvStatus).toBe("completed");

      // Verify findings across categories
      const categories = new Set(engineResult.findings.map((f) => f.category));
      expect(categories.has("Secrets")).toBe(true);
      expect(categories.has("Code Analysis")).toBe(true);
      expect(categories.has("Dependencies")).toBe(true);

      // Verify severity counts match findings
      expect(engineResult.counts.total).toBe(engineResult.findings.length);
      expect(engineResult.counts.critical).toBeGreaterThan(0);

      // Verify fingerprints are all unique
      const fingerprints = engineResult.findings.map((f) => f.fingerprint);
      const uniqueFingerprints = new Set(fingerprints);
      expect(uniqueFingerprints.size).toBe(fingerprints.length);
    });

    it("returns completed_with_warnings when one scanner fails", async () => {
      await writeFile(path.join(testDir, "test.ts"), `export const x = 1;\n`);
      const engineResult = await runSecurityScanEngine(testDir, {
        gitleaksBinary: "nonexistent-binary-fail",
      });
      expect(engineResult.status).toBe("completed_with_warnings");
      expect(engineResult.gitleaksStatus).toBe("failed");
      expect(engineResult.semgrepStatus).toBe("completed");
      expect(engineResult.osvStatus).toBe("completed");
    });
  });

  describe("Security Isolation & Non-Execution Proof", () => {
    it("never executes repository code, scripts or hooks", async () => {
      // Insecure repo with executable script and malicious package.json postinstall hook
      const markerPath = path.join(testDir, "HACKED_MARKER.txt");
      const packageJson = {
        name: "malicious-repo",
        scripts: {
          postinstall: `touch ${markerPath}`,
          preinstall: `touch ${markerPath}`,
          build: `touch ${markerPath}`,
        },
      };
      await writeFile(path.join(testDir, "package.json"), JSON.stringify(packageJson, null, 2));

      // Run engine on the workspace
      await runSecurityScanEngine(testDir);

      // Verify the postinstall marker file was NEVER created
      const exists = await (async () => {
        try {
          const { stat } = await import("node:fs/promises");
          await stat(markerPath);
          return true;
        } catch {
          return false;
        }
      })();
      expect(exists).toBe(false);
    });

    it("enforces timeout on slow commands", async () => {
      await expect(
        runSubprocess("sleep", ["2"], {
          cwd: testDir,
          timeoutMs: 100,
        }),
      ).rejects.toThrow(/timed out/i);
    });
  });

  describe("Redaction Helpers", () => {
    it("redacts AWS, Stripe, GitHub and private keys accurately", () => {
      const ghpToken = ["ghp", "0123456789abcdef0123456789abcdef012345"].join("_");
      const stripeToken = ["sk", "live", "51MzXYZ1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
      const stripeShort = ["sk", "live", "123456789012345678901234"].join("_");

      expect(redactText(ghpToken)).toBe("[REDACTED]");
      expect(redactText("AKIAIOSFODNN7EXAMPLE")).toBe("[REDACTED]");
      expect(redactText(stripeToken)).toBe("[REDACTED]");
      expect(redactEvidence(`const key = '${stripeShort}';`)).toContain("[REDACTED]");
      expect(redactEvidence("password = 'super_secret_value_12345'")).toContain("••••••••");
    });

    it("generates stable fingerprints for same input", () => {
      const fp1 = computeFingerprint(["gitleaks", "pat", "file.ts", 10]);
      const fp2 = computeFingerprint(["gitleaks", "pat", "file.ts", 10]);
      const fp3 = computeFingerprint(["gitleaks", "pat", "file.ts", 11]);
      expect(fp1).toBe(fp2);
      expect(fp1).not.toBe(fp3);
    });
  });
});
