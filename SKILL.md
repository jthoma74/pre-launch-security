---
name: pre-launch-security
description: Run a 34-point pre-launch security audit on an app (secrets, RLS/authz incl. IDOR, sessions & account flows, CSRF/CORS, input handling, SSRF, API surface, headers/HTTPS, admin/webhook surface, debug & env hygiene, logging, AI-layer checks, dependency scan, backups) and report PASS/FAIL/N-A with file:line evidence. Use when the user is about to launch/publish/ship/deploy an app (especially agent- or vibe-coded), asks "is this safe to launch", wants a pre-publish security checklist, or invokes /pre-launch-security.
---

# Pre-Launch Security Audit

Audit an app against 34 checks and report PASS / FAIL / WARN / N-A with `file:line` evidence.
**The audit is read-only — never modify the target repo unless the user explicitly asks for fixes.**
This audits the user's OWN app before launch. The separate `scan-repo` skill vets third-party repos before install — do not confuse the two.

## Source & attribution

Checks 1–20 are extracted from the Instagram reel "20 things to have Claude do before launching your app" by millee.md (Quoc Ly) — https://www.instagram.com/reel/Db9aX8rhfhU/, posted 2026-08-13. Checks 21–34, marked `[+]`, are expert-audit additions (2026-09-27) covering the reel's gaps.

## Workflow

### Phase 0 — Detect the stack (2–4 min)

Read package manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Gemfile`), config files, and env examples (`.env.example`, `.env.sample`). Establish:

- **Framework + language** (Next.js / Remix / Express / Django / Rails / FastAPI / Laravel / SvelteKit …).
- **Delivery shape** — browser-facing app vs headless / machine-to-machine API vs CLI or worker. Decides whether the browser-only controls (CSP, frame options, CSRF, CAPTCHA) have any surface at all.
- **User model** — multi-user, single-tenant, or no user accounts. Decides whether per-user scoping, session lifecycle, and per-tenant authorization exist as concepts in this app.
- **DB layer** — Supabase, Firebase, Prisma/Drizzle, raw SQL, ORM-less fetches.
- **Auth** — roll-your-own vs Supabase Auth / Clerk / Auth0 / NextAuth / Firebase Auth.
- **LLM / AI usage** — any model SDK (text, voice, or realtime: OpenAI, Anthropic, ElevenLabs/ConvAI, Deepgram, LiteLLM, OpenRouter, local `transformers`), prompt templates, tool-calling, RAG, agent loops, `wss://` realtime sessions.
- **File-upload surface** — storage buckets, multipart handlers, signed URLs.
- **Payments / webhooks** — Stripe, Lemon Squeezy, any inbound webhook route.
- **Deploy target** — Vercel, Netlify, Fly, Render, Docker, bare VPS.

Then read the repo's own security-relevant docs: `SECURITY.md`, `docs/known-issues*`, incident/postmortem notes, runbooks, README security sections. In agent-coded repos this is where past leaks, rotated keys, and known gotchas are actually recorded. **Treat every claim there as a lead, never as a fact** — verify it against the code and git history (check 2 carries the procedure) and report the verified state, not the document's.

**Phase 0's output is a written stack inventory** — framework, delivery shape, user model, DB, auth, AI/model layer, upload surface, webhooks, deploy target, plus the provider/dependency list (checks 1, 2, and 20 build their pattern and auditor lists from it). Carry it into the report. Phase 1's conditional checks — **12, 16, 21, 27, 28, 31, 33** — **MUST consult this inventory before declaring N-A**: a check's own grep never overrides the inventory. If the inventory found the surface, an empty grep means the grep is stack-blind, not that the surface is absent — widen it or read the code.

If the user provides a deployed URL, note it; live probes are optional and only with the user's explicit OK.

### Phase 1 — Run the 34 checks

Read `CHECKS.md` (same directory) **in full** at the start of this phase, then execute each check's detection procedure read-only.

- Conditional checks (AI layer, uploads, SSRF, webhooks, CSRF-for-cookie-auth, …) with no surface in this app → verdict **N-A with the reason** — and only when the Phase 0 inventory agrees that the surface is absent.
- **Never guess a verdict.** Every PASS / FAIL / WARN cites evidence: a `file:line` reference or the command run plus its output line.
- If a check cannot be determined from the repo (platform dashboard settings, DNS, provider config) → **WARN** with `verify manually: <what/where>`.

### Phase 2 — Report

Emit the report in the format below, in chat. Write it to a file only if the user asks.

### Phase 3 — Fixes (opt-in)

Offer to fix FAILs. Apply only on explicit go-ahead, or when the skill is invoked with a `fix` argument. Fix in severity order, smallest safe diff per fix, and re-run the affected check after each one. **NEVER auto-fix during the audit.**

## The 34 checks

**Group 1 — Secrets & environment**

| # | Check | Gist |
|---|---|---|
| 1 | Hide API keys | No secrets in client-shipped code |
| 2 | Purge Git secrets (and ROTATE) | History scrubbed, exposed keys rotated |
| 3 | Use public DB key | Anon/publishable key client-side only |
| 26 | `[+]` Separate prod from test | Distinct projects, keys, and databases |

**Group 2 — Database & authorization**

| # | Check | Gist |
|---|---|---|
| 4 | Enable row-level security | RLS on for every exposed table |
| 5 | Encrypt sensitive data | At-rest encryption for sensitive columns |
| 7 | Lock record access | Queries scoped to the owning user |
| 8 | Block field tampering | Server ignores client-set privileged fields |
| 22 | `[+]` Test object-level authorization (IDOR) | Swapped IDs must be denied |

**Group 3 — Auth, sessions & account flows**

| # | Check | Gist |
|---|---|---|
| 6 | Enforce server-side auth | Server re-checks, never trusts client |
| 9 | Secure session cookies | HttpOnly, Secure, SameSite set |
| 10 | Hash passwords | Slow modern hash, never plaintext |
| 29 | `[+]` Manage session lifecycle | Expiry, rotation, logout, revocation |
| 30 | `[+]` Harden account flows | No enumeration; safe reset + verify |

**Group 4 — Abuse & request forgery**

| # | Check | Gist |
|---|---|---|
| 11 | Rate limit login | Throttle and lock brute-force attempts |
| 12 | Add bot protection | CAPTCHA or bot defense on signup |
| 21 | `[+]` Protect against CSRF | Origin checks/tokens; SameSite insufficient |
| 27 | `[+]` Configure CORS deliberately | Explicit origins, no reflected wildcard |
| 28 | `[+]` Rate-limit globally + cap costs | All routes throttled, spend capped |

**Group 5 — Input handling**

| # | Check | Gist |
|---|---|---|
| 13 | Parameterize queries | No string-built SQL anywhere |
| 14 | Validate all input | Server-side schema validation everywhere |
| 15 | Escape user content | No unescaped HTML injection sinks |
| 16 | Restrict file uploads | Type, size, and storage-path limits |
| 31 | `[+]` Guard against SSRF | Block internal targets on fetched URLs |

**Group 6 — API surface & transport**

| # | Check | Gist |
|---|---|---|
| 17 | Trim API responses | Return only fields the client needs |
| 18 | Add security headers | CSP, HSTS, frame and MIME options |
| 19 | Force HTTPS | Redirect all plaintext to TLS |
| 23 | `[+]` Lock admin & internal surface | Admin, cron, webhook routes authenticated |
| 24 | `[+]` Deny web-root & bucket exposure | No public dotfiles, backups, buckets |
| 25 | `[+]` Kill debug leakage in prod | No stack traces, debug flags, source maps |

**Group 7 — AI layer (conditional)**

| # | Check | Gist |
|---|---|---|
| 33 | `[+]` Secure the AI layer | Prompt injection, tool scope, output trust |

**Group 8 — Supply chain & ops**

| # | Check | Gist |
|---|---|---|
| 20 | Scan dependencies | Audit for known vulnerable packages |
| 32 | `[+]` Log & alert on security events | Auth and abuse events logged, alerting |
| 34 | `[+]` Verify backups & rollback | Backups exist, restore path tested |

Per-check detection commands, verdict criteria, and fixes: see [CHECKS.md](CHECKS.md). Read it in full at the start of Phase 1.

## Report format

1. **Summary line:** `X PASS · Y FAIL · Z WARN · W N-A`
2. **One table per group**, columns `# | Check | Verdict | Evidence`. Within the report, list FAILs most-critical-first following the severity ordering: secrets/authz (Groups 1–2) > auth/abuse (Groups 3–4) > input/API (Groups 5–6) > AI/ops (Groups 7–8).
3. **Evidence** is a `file:line` reference or the command plus the output line that proves the verdict. N-A rows carry the reason. WARN rows carry `verify manually: <what/where>`.
4. **Ship / Don't ship verdict** to close:
   - **Don't ship** — any FAIL remains in Groups 1–4, or any secret is exposed (exposed secrets also require rotation before launch).
   - **Ship with follow-ups** — only WARNs and/or Group 5–8 FAILs remain; list them as post-launch tasks.

Example (format is exactly this):

```
**Group 2 — Database & authorization**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 4 | Enable row-level security | FAIL | supabase/migrations/0002_init.sql:41 — `messages` created, no `enable row level security` |
| 22 | [+] Object-level authorization (IDOR) | FAIL | app/api/orders/[id]/route.ts:18 — lookup by id only, no `user_id` predicate |
| 5 | Encrypt sensitive data | N-A | No sensitive columns (no PII, tokens, or payment data in schema) |
```

## Rules

- **Read-only by default.** No edits, no installs, no migrations, no writes to the target repo during Phases 0–2.
- **Never print discovered secret VALUES** — not even truncated. Name the file/line and the pattern class (e.g. "Stripe live secret key"), and instruct rotation.
- **Never run the target app, seed data, or touch production/staging** without explicit user OK. Live probing of a deployed URL is opt-in.
- **N-A always carries a reason.** "Not applicable" with no reason is an invalid verdict.
- **Don't skip a check because the stack is unfamiliar.** Say what you looked for, what you could not confirm, and the exact manual verification needed.
- **The audit covers the repo, not the platform dashboard.** Dashboard-, DNS-, and provider-only settings (RLS toggles applied out-of-band, WAF rules, backup schedules, spend caps) are WARN + "verify manually", never PASS by assumption.
