import { z } from "zod";

export const CodeExampleSchema = z.object({
  language: z.string().default("typescript"),
  code: z.string(),
  title: z.string().optional(),
  isDiff: z.boolean().default(false),
});

export const AiExplanationSchema = z.object({
  summary: z.string().min(10, "Summary must be at least 10 characters"),
  whyItMatters: z.string().min(10, "Why it matters must be at least 10 characters"),
  impact: z.string().min(10, "Impact must be at least 10 characters"),
  exploitabilityConditions: z.string().min(10, "Exploitability conditions must be at least 10 characters"),
  remediationSteps: z.array(z.string().min(3)).min(1, "At least one remediation step is required"),
  codeExample: CodeExampleSchema.nullable().optional(),
  verificationSteps: z.array(z.string().min(3)).min(1, "At least one verification step is required"),
  uncertainties: z.array(z.string()).default([]),
  disclaimer: z.string().default(
    "This guidance is AI-generated based on static scanner findings. Review and test thoroughly before deploying to production."
  ),
});

export const AiExplanationJsonSchema: Record<string, unknown> = {
  type: "object",
  properties: {
    summary: {
      type: "string",
      description: "Clear, concise 1-2 sentence plain-English explanation of the security issue (min 10 characters).",
    },
    whyItMatters: {
      type: "string",
      description: "Why this vulnerability or weakness matters to the security posture of the application (min 10 characters).",
    },
    impact: {
      type: "string",
      description: "Concrete potential impact if exploited, grounded in the evidence (min 10 characters).",
    },
    exploitabilityConditions: {
      type: "string",
      description: "Prerequisites or environmental conditions required for this finding to be exploitable (min 10 characters).",
    },
    remediationSteps: {
      type: "array",
      items: { type: "string" },
      description: "Concrete remediation steps to resolve the finding.",
    },
    codeExample: {
      type: ["object", "null"],
      description: "Optional safe illustrative replacement code or unified diff.",
      properties: {
        language: { type: "string", description: "Programming language (e.g. typescript, python, javascript)." },
        code: { type: "string", description: "Remediated code replacement or illustrative snippet." },
        title: { type: "string", description: "Title of the code example." },
        isDiff: { type: "boolean", description: "Whether the code represents a unified git diff." },
      },
      required: ["code"],
    },
    verificationSteps: {
      type: "array",
      items: { type: "string" },
      description: "Step-by-step verification commands or checks to confirm resolution.",
    },
    uncertainties: {
      type: "array",
      items: { type: "string" },
      description: "Known ambiguities or context limitations not visible in the static evidence.",
    },
    disclaimer: {
      type: "string",
      description: "Safety disclaimer regarding static automated analysis.",
    },
  },
  required: [
    "summary",
    "whyItMatters",
    "impact",
    "exploitabilityConditions",
    "remediationSteps",
    "verificationSteps",
  ],
};

export type CodeExample = z.infer<typeof CodeExampleSchema>;
export type AiFindingExplanation = z.infer<typeof AiExplanationSchema>;

export type CachedAiExplanation = {
  cacheKey: string;
  fingerprint: string;
  contextHash: string;
  promptVersion: string;
  model: string;
  generatedAt: string;
  explanation: AiFindingExplanation;
};

export type AiDiagnosticInfo = {
  correlationId: string;
  model: string;
  category: string;
};

export type AiExplainResult =
  | {
      available: true;
      cached: boolean;
      model: string;
      explanation: AiFindingExplanation;
      generatedAt: string;
    }
  | {
      available: false;
      code:
        | "ai_not_configured"
        | "quota_exhausted"
        | "provider_error"
        | "rate_limited"
        | "invalid_response"
        | "schema_validation_failed"
        | "output_truncated"
        | "timeout"
        | "model_missing"
        | "service_unavailable";
      message: string;
      diagnostic?: AiDiagnosticInfo;
    };

