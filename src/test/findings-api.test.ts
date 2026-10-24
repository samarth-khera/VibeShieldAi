import { describe, it, expect, beforeEach } from "vitest";
import {
  type JobRecord,
  type JobStore,
  type NewJob,
  type JobPatch,
  type FindingRecord,
  type FindingsFilter,
  newJobId,
} from "../server/job-store";
import {
  startScan,
  listScanFindings,
  getScanFinding,
  type ScanDeps,
} from "../server/scans-service";
import type { NormalizedFinding } from "../server/scanners/types";

class TestJobStore implements JobStore {
  private jobs = new Map<string, JobRecord>();
  private findings = new Map<string, FindingRecord[]>();

  async create(data: NewJob): Promise<JobRecord> {
    const id = newJobId();
    const record: JobRecord = {
      id,
      status: "queued",
      owner: data.owner,
      repo: data.repo,
      repositoryUrl: data.repositoryUrl,
      defaultBranch: null,
      commitSha: null,
      description: null,
      repoSizeKb: null,
      stars: null,
      primaryLanguage: null,
      archiveBytes: null,
      fileCount: null,
      unpackedBytes: null,
      failureCategory: null,
      errorMessage: null,
      gitleaksStatus: null,
      gitleaksDurationMs: null,
      gitleaksError: null,
      semgrepStatus: null,
      semgrepDurationMs: null,
      semgrepError: null,
      osvStatus: null,
      osvDurationMs: null,
      osvError: null,
      scannerVersions: null,
      scanCoverage: null,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      attempts: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      startedAt: null,
      completedAt: null,
      expiresAt: data.expiresAt,
    };
    this.jobs.set(id, record);
    return record;
  }

  async get(id: string): Promise<JobRecord | null> {
    return this.jobs.get(id) ?? null;
  }

  async claim(id: string): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job || job.status !== "queued") return false;
    job.status = "retrieving";
    return true;
  }

  async claimForScan(id: string): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job || (job.status !== "ready_for_scan" && job.status !== "completed_with_warnings")) {
      return false;
    }
    job.status = "scanning";
    return true;
  }

  async update(id: string, patch: JobPatch): Promise<void> {
    const current = this.jobs.get(id);
    if (!current) throw new Error("not found");
    const updated = { ...current, ...patch, updatedAt: new Date() };
    this.jobs.set(id, updated);
  }

  async requeue(id: string): Promise<boolean> {
    const job = this.jobs.get(id);
    if (!job) return false;
    job.status = "queued";
    return true;
  }

  async deleteExpired(): Promise<number> {
    return 0;
  }

  async saveFindings(scanJobId: string, findingsList: NormalizedFinding[]): Promise<void> {
    const existing = this.findings.get(scanJobId) || [];
    const newRecords: FindingRecord[] = findingsList.map((f, i) => ({
      id: f.id || `find-${i + 1}`,
      scanJobId,
      fingerprint: f.fingerprint,
      scanner: f.scanner,
      ruleId: f.ruleId,
      category: f.category,
      severity: f.severity,
      originalSeverity: f.originalSeverity ?? null,
      title: f.title,
      description: f.description,
      filePath: f.filePath,
      startLine: f.startLine ?? null,
      endLine: f.endLine ?? null,
      redactedEvidence: f.redactedEvidence ?? null,
      vulnerabilityId: f.vulnerabilityId ?? null,
      remediation: f.remediation ?? null,
      packageInfo: f.packageInfo ?? null,
      metadata: null,
      createdAt: new Date(),
    }));
    this.findings.set(scanJobId, [...existing, ...newRecords]);
  }

  async getFindings(scanJobId: string, filter?: FindingsFilter): Promise<{ findings: FindingRecord[]; total: number }> {
    const all = this.findings.get(scanJobId) || [];
    let filtered = [...all];
    if (filter?.severity) filtered = filtered.filter((f) => f.severity === filter.severity);
    if (filter?.category) filtered = filtered.filter((f) => f.category === filter.category);
    if (filter?.query) {
      const q = filter.query.toLowerCase();
      filtered = filtered.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.ruleId.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q)
      );
    }
    const total = filtered.length;
    const offset = filter?.offset ?? 0;
    const limit = filter?.limit ?? 100;
    const paged = filtered.slice(offset, offset + limit);
    return {
      findings: paged,
      total,
    };
  }

  async getFinding(scanJobId: string, findingId: string): Promise<FindingRecord | null> {
    const all = this.findings.get(scanJobId) || [];
    return all.find((f) => f.id === findingId || f.fingerprint === findingId) ?? null;
  }

  async saveFindingAiExplanation(scanJobId: string, findingId: string, aiExplanation: unknown): Promise<void> {
    const all = this.findings.get(scanJobId) || [];
    const item = all.find((f) => f.id === findingId || f.fingerprint === findingId);
    if (item) {
      item.aiExplanation = aiExplanation;
    }
  }

  async createRemediation(): Promise<never> { throw new Error("not implemented"); }
  async getRemediation(): Promise<null> { return null; }
  async listRemediations(): Promise<[]> { return []; }
  async updateRemediation(): Promise<never> { throw new Error("not implemented"); }
}

describe("Scan Findings API & Service Integration", () => {
  let store: TestJobStore;
  let deps: ScanDeps;
  let testJobId: string;

  const sampleFindings: NormalizedFinding[] = [
    {
      id: "f-1",
      fingerprint: "fp-1",
      scanner: "gitleaks",
      ruleId: "generic-api-key",
      category: "Secrets",
      severity: "high",
      title: "Hardcoded API Token",
      description: "Generic API Key detected",
      filePath: "src/config.ts",
      startLine: 12,
      endLine: 12,
      redactedEvidence: "api_key = \"REDACTED_SECRET_xxx\"",
      vulnerabilityId: null,
      remediation: "Revoke token and use environment variables.",
    },
    {
      id: "f-2",
      fingerprint: "fp-2",
      scanner: "semgrep",
      ruleId: "js-code-execution-eval",
      category: "Code Analysis",
      severity: "critical",
      title: "Arbitrary Code Execution via eval",
      description: "User input directly passed to eval()",
      filePath: "src/calc.js",
      startLine: 45,
      endLine: 45,
      redactedEvidence: "eval(req.body.expr)",
      vulnerabilityId: null,
      remediation: "Use safe expression parser instead of eval",
    },
    {
      id: "f-3",
      fingerprint: "fp-3",
      scanner: "osv-scanner",
      ruleId: "GHSA-c36v-f6fq-55px",
      category: "Dependencies",
      severity: "medium",
      title: "Vulnerable Dependency: minimist",
      description: "Prototype Pollution in minimist",
      filePath: "package-lock.json",
      startLine: null,
      endLine: null,
      redactedEvidence: null,
      vulnerabilityId: "GHSA-c36v-f6fq-55px",
      remediation: "Upgrade minimist to version >= 1.2.6",
    },
  ];

  beforeEach(async () => {
    store = new TestJobStore();
    deps = {
      store,
      enqueue: async () => {},
      rateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      workerOnline: async () => true,
      config: {} as unknown as ScanDeps["config"],
    };

    const job = await store.create({
      repositoryUrl: "https://github.com/test-org/test-repo",
      owner: "test-org",
      repo: "test-repo",
      expiresAt: new Date(Date.now() + 86400000),
    });
    testJobId = job.id;
    await store.update(testJobId, { status: "completed" });
    await store.saveFindings(testJobId, sampleFindings);
  });

  it("lists all findings for a scan with total count", async () => {
    const req = new Request(`http://localhost:3100/api/scans/${testJobId}/findings`);
    const res = await listScanFindings(testJobId, req, deps);
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(data.total).toBe(3);
    expect(data.findings).toHaveLength(3);
    expect(data.findings.map((f: { ruleId: string }) => f.ruleId)).toContain("generic-api-key");
  });

  it("filters findings by severity", async () => {
    const req = new Request(`http://localhost:3100/api/scans/${testJobId}/findings?severity=critical`);
    const res = await listScanFindings(testJobId, req, deps);
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(data.total).toBe(1);
    expect(data.findings[0].title).toContain("eval");
  });

  it("filters findings by category", async () => {
    const req = new Request(`http://localhost:3100/api/scans/${testJobId}/findings?category=Secrets`);
    const res = await listScanFindings(testJobId, req, deps);
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(data.total).toBe(1);
    expect(data.findings[0].category).toBe("Secrets");
  });

  it("searches findings by query keyword in title, ruleId or filePath", async () => {
    const req = new Request(`http://localhost:3100/api/scans/${testJobId}/findings?query=calc.js`);
    const res = await listScanFindings(testJobId, req, deps);
    expect(res.status).toBe(200);
    const { data } = await res.json();
    expect(data.total).toBe(1);
    expect(data.findings[0].filePath).toBe("src/calc.js");
  });

  it("paginates findings with limit and offset", async () => {
    const req1 = new Request(`http://localhost:3100/api/scans/${testJobId}/findings?limit=2&offset=0`);
    const res1 = await listScanFindings(testJobId, req1, deps);
    const json1 = await res1.json();
    expect(json1.data.findings).toHaveLength(2);

    const req2 = new Request(`http://localhost:3100/api/scans/${testJobId}/findings?limit=2&offset=2`);
    const res2 = await listScanFindings(testJobId, req2, deps);
    const json2 = await res2.json();
    expect(json2.data.findings).toHaveLength(1);
  });

  it("retrieves a single finding by finding ID", async () => {
    const res = await getScanFinding(testJobId, "f-2", deps);
    expect(res.status).toBe(200);
    const { data: finding } = await res.json();
    expect(finding.id).toBe("f-2");
    expect(finding.severity).toBe("critical");
    expect(finding.redactedEvidence).toBe("eval(req.body.expr)");
  });

  it("returns 404 for non-existent finding", async () => {
    const res = await getScanFinding(testJobId, "non-existent-id", deps);
    expect(res.status).toBe(404);
  });

  it("starts a scan when job is ready_for_scan", async () => {
    const readyJob = await store.create({
      repositoryUrl: "https://github.com/test-org/ready-repo",
      owner: "test-org",
      repo: "ready-repo",
      expiresAt: new Date(Date.now() + 86400000),
    });
    await store.update(readyJob.id, { status: "ready_for_scan" });

    let enqueuedJobId = "";
    deps.enqueue = async (id: string) => {
      enqueuedJobId = id;
    };

    const res = await startScan(readyJob.id, deps);
    expect(res.status).toBe(202);
    expect(enqueuedJobId).toBe(readyJob.id);

    const updated = await store.get(readyJob.id);
    expect(updated?.status).toBe("queued");
  });
});
