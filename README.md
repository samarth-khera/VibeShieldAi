# VibeShield AI

> **Zero-Cost, Multi-Scanner Public GitHub Repository Security Auditor & AI Remediation Engine**
> Live at [https://vibeshield-ai-phi.vercel.app](https://vibeshield-ai-phi.vercel.app/)

## Key Capabilities

1. **Real Security Scanners Running in Parallel**:
   - **Gitleaks**: Secrets and credential scanning across files and git history.
   - **Semgrep**: AST-based static application security testing (SAST) for insecure patterns and injection vulnerabilities.
   - **OSV-Scanner**: Open Source Vulnerability scanner checking dependencies against Google's OSV database.
2. **Scan Execution Independent of AI**:
   - Scans run in an isolated ephemeral environment via GitHub Actions.
   - Reports and findings are delivered and displayed as soon as the scanners finish (~10-20 seconds), without waiting for AI.
3. **On-Demand AI Security Analyst (Google Gemini 2.5 Flash)**:
   - Server-side explanations powered by the official `@google/genai` SDK.
   - Strictly bounded finding context, zero repo archive uploads, robust prompt-injection defenses.
   - Explanations are cached in PostgreSQL to eliminate duplicate AI calls.
4. **Zero-Billing Guardrails & Circuit Breaker**:
   - Designed for Google AI Studio Free Tier (₹0 billing).
   - Atomic PostgreSQL quotas (per-IP hourly, per-IP daily, global daily cap).
   - Automatic global circuit breaker trips on `429 RESOURCE_EXHAUSTED` to halt upstream requests and prevent retry storms.
   - Administrative inspection and reset via `/api/admin/circuit-breaker`.
5. **Approved AI Remediation & Sandbox Verification**:
   - Surgical unified git diff generation with anti-traversal safety validation.
   - Explicit human review and approval required before applying fixes.
   - Isolated sandbox rescan verification to confirm vulnerability resolution without regressions.

## Documentation
- [Gemini Free-Tier Setup & Zero-Billing Guide](docs/gemini-setup.md)

## Development

```bash
# Install dependencies
npm install

# Run database migrations
npm run db:migrate:dev

# Run tests
npm test

# Run typecheck & linter
npm run typecheck
npm run lint

# Start local Next.js dev server
npm run dev
```

## License
MIT
