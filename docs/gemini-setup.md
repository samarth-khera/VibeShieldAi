# VibeShield AI — Gemini Free-Tier & Zero-Billing Setup Guide

## Architecture Overview
VibeShield AI uses a zero-cost architecture with on-demand AI explanations and remediation assistance.
1. **Security Scanning is Independent of AI**: Gitleaks, Semgrep, and OSV-Scanner run in parallel on an ephemeral GitHub Actions runner and persist real findings immediately without waiting for AI.
2. **On-Demand Server-Side AI**: When a user clicks **Explain with AI** or requests an automated remediation patch, VibeShield's serverless backend securely calls the official `@google/genai` SDK using `GEMINI_API_KEY`.
3. **Strict Zero-Billing Guardrails**:
   - The primary guarantee against billing is keeping your Google AI Studio / Google Cloud project strictly on the **Free Tier with no Cloud Billing account attached**.
   - Application-side quotas enforce atomic database-backed limits (per IP hourly, per IP daily, global daily cap).
   - An automatic PostgreSQL circuit breaker detects `429 RESOURCE_EXHAUSTED` responses and halts further calls immediately without retry storms.

---

## 1. Google AI Studio Setup (Free Tier — ₹0 Billing)

### Step 1: Create a Dedicated Free-Tier Project
1. Navigate to [Google AI Studio](https://aistudio.google.com/).
2. Sign in with your Google account.
3. Open the Project selector and choose **Create a new project** (e.g. `vibeshield-ai-free`).
4. **DO NOT** attach a Google Cloud Billing account or credit card to this project. If no billing account is linked, Google hard-caps usage at the Free Tier limits (e.g. 15 RPM / 1500 RPD for Gemini 2.5 Flash / Flash Lite) and will return HTTP 429 rather than charging your account.

### Step 2: Generate an API Key
1. In Google AI Studio, click **Get API key**.
2. Select your newly created `vibeshield-ai-free` project.
3. Click **Create API key**.
4. *(Recommended)* Apply API restrictions to restrict the key strictly to the **Generative Language API** in Google Cloud Console.
5. **NEVER** commit this key to Git, share it in chat, or use browser-side referrers. Treat this key as a secret.

---

## 2. Vercel Production Environment Configuration

Configure the following environment variables in the **Vercel Project Dashboard** under **Settings → Environment Variables** (select **Production** only):

| Variable | Recommended Value | Description |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | *(Your rotated Google AI Studio key)* | Secret server-only API key |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Free-tier supported model |
| `AI_PROVIDER` | `gemini` | Active AI provider (`gemini` or `ollama`) |
| `AI_GEMINI_ENABLED` | `true` | Enables AI feature flags |
| `AI_MAX_REQUESTS_PER_IP_HOURLY`| `5` | Anti-abuse limit per client IP per hour |
| `AI_MAX_REQUESTS_PER_IP_DAILY` | `15` | Anti-abuse limit per client IP per day |
| `AI_GLOBAL_DAILY_CAP` | `50` | Total AI calls per day before circuit breaker |
| `AI_CIRCUIT_BREAKER_COOLDOWN_HOURS` | `24` | Cooldown period on quota exhaustion |
| `ADMIN_SECRET` | *(Random 32-char secret)* | Secret for inspecting/resetting circuit breaker |

> [!IMPORTANT]
> **Never** set `NEXT_PUBLIC_GEMINI_API_KEY`. The frontend never communicates directly with Google. All requests flow through authenticated VibeShield serverless endpoints.

---

## 3. Circuit Breaker & Administrative Operations

### Inspect Circuit Breaker Status
```bash
curl -H "x-vibeshield-admin-secret: <ADMIN_SECRET>" \
  https://vibeshield-ai-phi.vercel.app/api/admin/circuit-breaker
```

### Manual Reset (After Google Quota Resets)
```bash
curl -X POST \
  -H "x-vibeshield-admin-secret: <ADMIN_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{"action": "reset"}' \
  https://vibeshield-ai-phi.vercel.app/api/admin/circuit-breaker
```

---

## 4. Billing Disclaimer
Application request limits and database-backed circuit breakers provide defence-in-depth against runaway traffic. However, Google's policies and free-tier quotas are determined exclusively by Google. The definitive external billing safeguard is ensuring that **no Cloud Billing account is attached to your Google Cloud project**.
