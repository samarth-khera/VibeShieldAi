import { describe, expect, it } from "vitest";
import { createPreview } from "@/server/remediation/service";
import { fitColumn, REMEDIATION_TEXT_LIMITS } from "@/server/remediation/types";
import { InMemoryJobStore } from "@/test/mock-store";

/**
 * Production regression (2026-10-29): an eligible npm fix produced a 594-character explanation for
 * the VARCHAR(500) Remediation.eligibilityReason column. prisma.remediation.create threw P2000, the
 * preview request returned HTTP 500 and nothing was saved, so the fix could never be reviewed.
 */
describe("remediation text columns", () => {
  it("the test store rejects over-length values exactly like PostgreSQL (P2000)", async () => {
    const store = new InMemoryJobStore();
    await expect(store.createRemediation({ id: "x", scanJobId: "j", eligibilityReason: "x".repeat(501) } as never)).rejects.toMatchObject({
      code: "P2000",
    });
  });

  it("fitColumn keeps text that fits and shortens text that does not, marking the cut", () => {
    expect(fitColumn("short", 500)).toBe("short");
    const fitted = fitColumn("y".repeat(600), REMEDIATION_TEXT_LIMITS.eligibilityReason);
    expect(fitted).toHaveLength(500);
    expect(fitted.endsWith("…")).toBe(true);
  });

  it("never fails a preview because its explanation is longer than the column", async () => {
    const store = new InMemoryJobStore();
    const job = await store.create({ owner: "o", repo: "r", repositoryUrl: "https://github.com/o/r", expiresAt: new Date(Date.now() + 3_600_000) });
    await store.update(job.id, { status: "completed", commitSha: "7f90143a47c6280f6bcf9d55bb7c4767a48c1542" });
    await store.saveFindings(job.id, [
      {
        fingerprint: "fp-long",
        scanner: "semgrep",
        ruleId: `custom-rule-${"x".repeat(600)}`,
        category: "Code Analysis",
        severity: "medium",
        title: "Long rule",
        description: "",
        filePath: "src/app.ts",
        startLine: 3,
        endLine: 3,
        redactedEvidence: null,
        vulnerabilityId: null,
        remediation: null,
        packageInfo: null,
        metadata: null,
      },
    ] as never);
    const f = (await store.getFindings(job.id)).findings[0];
    const rem = await createPreview(job.id, f.id, { store, sourceFiles: { "src/app.ts": "a\nb\nc\n" } });
    expect(rem.eligibility).toBe("unsuitable");
    expect(rem.eligibilityReason).toHaveLength(500);
    expect(rem.eligibilityReason.endsWith("…")).toBe(true);
    expect(rem.patchSummary.length).toBeLessThanOrEqual(500);
  });
});
