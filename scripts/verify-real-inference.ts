import { explainFinding } from "../src/server/ai/service";
import { OllamaProvider } from "../src/server/ai/client";
import { AiExplanationSchema } from "../src/server/ai/types";
import { generateRemediationPatch, validateUnifiedDiff } from "../src/server/remediation/patch";
import { InMemoryJobStore } from "../src/test/mock-store";
import type { FindingRecord } from "../src/server/job-store";

async function runRealInferenceVerification() {
  const baseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  const modelName = process.env.OLLAMA_MODEL || "qwen3.5:4b-q4_K_M";

  console.log("==================================================================");
  console.log("VibeShield AI — Real Local Ollama Inference Verification (Phase 10)");
  console.log("==================================================================");
  console.log(`Endpoint:     ${baseUrl}`);
  console.log(`Model:        ${modelName}`);
  console.log(`Architecture: ${process.arch} (${process.platform})`);
  console.log("------------------------------------------------------------------");

  // 1. Verify Ollama Service Availability
  console.log("[1/5] Checking Ollama Service Health & Model Registry...");
  let tagsRes: Response;
  try {
    tagsRes = await fetch(`${baseUrl}/api/tags`);
  } catch (err) {
    console.error(`FATAL: Cannot reach Ollama at ${baseUrl}. Ensure the Ollama container is running.`);
    console.error(`Error details: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  if (!tagsRes.ok) {
    console.error(`FATAL: Ollama returned status ${tagsRes.status}`);
    process.exit(1);
  }

  const tagsData = (await tagsRes.json()) as { models?: Array<{ name: string; size: number }> };
  const loadedModels = tagsData.models || [];
  console.log(`✓ Ollama service is ONLINE.`);
  console.log(`Loaded models: ${loadedModels.map((m) => `${m.name} (${(m.size / 1e9).toFixed(2)} GB)`).join(", ") || "none"}`);

  const activeModel = loadedModels.find((m) => m.name === modelName || m.name.startsWith(modelName));
  if (!activeModel) {
    console.warn(`WARNING: Configured model '${modelName}' is not loaded yet in Ollama.`);
    console.warn(`Available models: ${loadedModels.map((m) => m.name).join(", ")}`);
  } else {
    console.log(`✓ Confirmed model '${modelName}' is downloaded (${(activeModel.size / 1e9).toFixed(2)} GB).`);
  }

  const provider = new OllamaProvider({ baseUrl, modelName });
  const store = new InMemoryJobStore();
  const testJobId = "job-synthetic-test";

  // Synthetic, non-secret finding
  const syntheticFinding: FindingRecord = {
    id: "find-md5-weak",
    scanJobId: testJobId,
    scanner: "semgrep",
    severity: "critical",
    originalSeverity: "ERROR",
    ruleId: "javascript.crypto.insecure-hash.insecure-hash-algorithm-md5",
    category: "crypto",
    title: "Use of Insecure Cryptographic Hash (MD5)",
    description: "MD5 is cryptographically broken and prone to collision attacks. Use SHA-256 or bcrypt/Argon2id for passwords.",
    filePath: "src/server/auth.ts",
    startLine: 18,
    endLine: 20,
    redactedEvidence: "const hash = crypto.createHash('md5').update(password).digest('hex');",
    fingerprint: "fp-md5-synthetic-001",
    vulnerabilityId: null,
    remediation: "Replace crypto.createHash('md5') with modern cryptographic hashing (e.g. crypto.createHash('sha256') or argon2).",
    packageInfo: null,
    metadata: null,
    aiExplanation: null,
    createdAt: new Date(),
  };

  // Seed store with finding
  await store.saveFindings(testJobId, [
    {
      scanner: syntheticFinding.scanner as "semgrep",
      ruleId: syntheticFinding.ruleId,
      category: "Code Analysis",
      severity: syntheticFinding.severity as "critical",
      originalSeverity: syntheticFinding.originalSeverity,
      title: syntheticFinding.title,
      description: syntheticFinding.description,
      filePath: syntheticFinding.filePath,
      startLine: syntheticFinding.startLine,
      endLine: syntheticFinding.endLine,
      redactedEvidence: syntheticFinding.redactedEvidence,
      fingerprint: syntheticFinding.fingerprint,
      remediation: syntheticFinding.remediation,
      vulnerabilityId: null,
      packageInfo: null,
      metadata: {},
    },
  ]);

  // Retrieve stored finding
  const storedFinding = await store.getFinding(testJobId, "find-md5-weak").catch(() => null);
  const targetFindingId = storedFinding ? storedFinding.id : (await store.getFindings(testJobId)).findings[0]?.id;

  // 2. Real Inference: AI Explanation with Zod Schema Validation
  console.log("\n[2/5] Running Real Inference: Structured AI Security Explanation...");
  const memBefore = process.memoryUsage().heapUsed;
  const startTime = Date.now();

  const explainResult = await explainFinding(testJobId, targetFindingId, { store, provider, timeoutMs: 180000 });
  const latencyMs = Date.now() - startTime;
  const memAfter = process.memoryUsage().heapUsed;

  if (!explainResult.available) {
    console.error(`✗ Inference Failed with code '${explainResult.code}': ${explainResult.message}`);
    process.exit(1);
  }

  console.log(`✓ Real Inference SUCCEEDED in ${latencyMs}ms (${(latencyMs / 1000).toFixed(2)}s).`);
  console.log(`  Model reported: ${explainResult.model}`);
  console.log(`  Heap delta:     ${((memAfter - memBefore) / 1024 / 1024).toFixed(2)} MB`);

  // Validate output against Zod schema
  const validation = AiExplanationSchema.safeParse(explainResult.explanation);
  if (!validation.success) {
    console.error("✗ Schema validation failed for real inference output:", validation.error.format());
    process.exit(1);
  }
  console.log("✓ Zod schema validation: 100% PASSED.");
  console.log(`  Summary:        "${explainResult.explanation.summary.slice(0, 100)}..."`);
  console.log(`  Why It Matters: "${explainResult.explanation.whyItMatters.slice(0, 100)}..."`);
  console.log(`  Impact:         "${explainResult.explanation.impact.slice(0, 100)}..."`);
  console.log(`  Remediation:    ${explainResult.explanation.remediationSteps.length} steps generated`);
  console.log(`  Verification:   ${explainResult.explanation.verificationSteps.length} steps generated`);

  // 3. Cache Reuse Verification
  console.log("\n[3/5] Verifying Cache Reuse on Repeated Request...");
  const cacheStart = Date.now();
  const cachedResult = await explainFinding(testJobId, targetFindingId, { store, provider });
  const cacheLatencyMs = Date.now() - cacheStart;

  if (!cachedResult.available || !cachedResult.cached) {
    console.error("✗ Cache reuse failed: expected cached: true");
    process.exit(1);
  }
  console.log(`✓ Cache HIT confirmed: served in ${cacheLatencyMs}ms (0ms LLM inference).`);

  // 4. Remediation Patch Generation & Refusal Controls
  console.log("\n[4/5] Running Real Inference: Remediation Diff & Safety Refusal Controls...");
  
  // 4a. Verify safety refusal for ineligible finding (crypto/auth/secrets)
  try {
    await generateRemediationPatch({
      finding: syntheticFinding,
      scanJobId: testJobId,
      commitSha: "sha-test-1234",
      llmProvider: provider,
    });
    console.error("✗ Expected refusal for crypto/auth finding, but patch was generated.");
    process.exit(1);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`✓ Safety Refusal Verified: Ineligible crypto finding correctly refused.`);
    console.log(`  Refusal reason: "${msg}"`);
  }

  // 4b. Verify valid unified diff generation on an eligible code finding
  const eligibleFinding = {
    id: "find-xss-danger",
    fingerprint: "fp-xss-danger-123",
    scanner: "semgrep" as const,
    ruleId: "javascript.browser.security.dangerouslysetinnerhtml",
    category: "Code Analysis" as const,
    severity: "high" as const,
    originalSeverity: "HIGH",
    title: "Use of dangerouslySetInnerHTML can lead to XSS",
    description: "Setting innerHTML directly without sanitization enables Cross-Site Scripting (XSS).",
    filePath: "src/components/Banner.tsx",
    startLine: 12,
    endLine: 14,
    redactedEvidence: "<div dangerouslySetInnerHTML={{ __html: userHtml }} />",
    remediation: "Replace with safe text children or sanitize via DOMPurify.",
    vulnerabilityId: null,
    packageInfo: null,
    metadata: {},
  };

  const patchStart = Date.now();
  const patchResult = await generateRemediationPatch({
    finding: eligibleFinding,
    scanJobId: testJobId,
    commitSha: "sha-test-1234",
    llmProvider: provider,
  });
  const patchLatencyMs = Date.now() - patchStart;

  console.log(`✓ Remediation Patch generated in ${patchLatencyMs}ms.`);
  console.log(`  Summary: ${patchResult.patchSummary}`);
  console.log(`  Affected Files: ${patchResult.affectedFiles.join(", ")}`);

  const diffValidation = validateUnifiedDiff(patchResult.unifiedDiff);
  if (!diffValidation.valid) {
    console.error(`✗ Diff validation failed: ${diffValidation.error}`);
    process.exit(1);
  }
  console.log("✓ Unified diff validation: 100% VALID.");
  console.log("  Diff snippet:");
  console.log(patchResult.unifiedDiff.split("\n").slice(0, 8).map((l) => `    ${l}`).join("\n"));

  // 5. Error State Verification
  console.log("\n[5/5] Testing Error State & Unavailable-Model Handling...");
  const missingModelProvider = new OllamaProvider({ baseUrl, modelName: "qwen3.5:non-existent-tag-999" });
  const freshStore = new InMemoryJobStore();
  await freshStore.saveFindings(testJobId, [
    {
      id: "find-uncached-err",
      scanner: "semgrep",
      ruleId: syntheticFinding.ruleId,
      category: "Code Analysis",
      severity: "critical",
      originalSeverity: "CRITICAL",
      title: syntheticFinding.title,
      description: syntheticFinding.description,
      filePath: syntheticFinding.filePath,
      startLine: syntheticFinding.startLine,
      endLine: syntheticFinding.endLine,
      redactedEvidence: syntheticFinding.redactedEvidence,
      fingerprint: "fp-uncached-err-unique",
      remediation: syntheticFinding.remediation,
      vulnerabilityId: null,
      packageInfo: null,
      metadata: {},
    },
  ]);

  const missingModelResult = await explainFinding(testJobId, "find-uncached-err", {
    store: freshStore,
    provider: missingModelProvider,
  });

  if (missingModelResult.available || missingModelResult.code !== "model_missing") {
    console.error(`✗ Expected code 'model_missing', got '${missingModelResult.available ? "available" : missingModelResult.code}'`);
    process.exit(1);
  }
  console.log(`✓ Missing-model handled gracefully (code: '${missingModelResult.code}').`);
  console.log(`  Message: "${missingModelResult.message}"`);

  console.log("\n==================================================================");
  console.log("ALL REAL INFERENCE VERIFICATION CHECKS PASSED SUCCESSFULLY!");
  console.log("==================================================================");
}

runRealInferenceVerification().catch((err) => {
  console.error("Fatal verification error:", err);
  process.exit(1);
});
