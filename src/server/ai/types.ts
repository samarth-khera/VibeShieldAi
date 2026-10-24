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
      code: "ai_not_configured" | "provider_error" | "rate_limited" | "invalid_response" | "timeout";
      message: string;
    };
