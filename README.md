# pre-launch-security

A Claude Code skill that runs a **34-point security audit on your app before you launch it**, and
reports `PASS` / `FAIL` / `WARN` / `N-A` for every check with `file:line` evidence.

Built for apps that were written fast — agent-coded, vibe-coded, shipped over a weekend — where the
code works but nobody has yet asked *"what happens when a stranger points a script at this?"*

**The audit is read-only.** It reads your repo and reports. It does not edit files, install packages,
run your app, run migrations, or touch your database. Fixes are a separate, opt-in phase you have to
ask for.

## What it actually does

1. **Detects your stack** — framework, delivery shape (browser app vs headless API vs CLI), user
   model, database layer, auth provider, AI/model SDKs, upload surface, webhooks, deploy target.
   This inventory is what makes the conditional checks honest: a check can only be marked "not
   applicable" when the stack inventory agrees the surface genuinely doesn't exist.
2. **Runs 34 checks**, each with its own detection commands, verdict criteria, and fix.
3. **Reports** one table per group, FAILs ordered most-critical-first, closing with a
   **ship / don't-ship verdict**.
4. **Offers fixes** — only if you say yes.

Two rules do most of the work:

- **Never guess a verdict.** Every PASS/FAIL/WARN cites a `file:line` or the command plus its output.
- **N-A always carries a reason.** A bare "not applicable" is an invalid verdict, because it's
  indistinguishable from a check that was quietly skipped.

## The 34 checks

Checks 1–20 come from the source reel (see [Credits](#credits)). Checks marked `[+]` are additions
that cover gaps the original list didn't reach — IDOR, CSRF, CORS, SSRF, session lifecycle, account
enumeration, debug leakage, the AI layer, logging, and backups.

| Group | Checks | What it covers |
|---|---|---|
| 1 — Secrets & environment | 4 | Keys out of client code, git history purged **and rotated**, public vs privileged DB keys, prod separated from test `[+]` |
| 2 — Database & authorization | 5 | Row-level security, encryption at rest, per-user record scoping, field-tampering/mass-assignment, object-level authz (IDOR/BOLA) `[+]` |
| 3 — Auth, sessions & account flows | 5 | Server-side auth enforcement, cookie flags, password hashing, session lifecycle & revocation `[+]`, account-enumeration and reset-token hardening `[+]` |
| 4 — Abuse & request forgery | 5 | Login rate limiting, bot protection, CSRF `[+]`, CORS `[+]`, global rate limits + spend caps ("denial of wallet") `[+]` |
| 5 — Input handling | 5 | Parameterized queries, server-side schema validation, output escaping/XSS, upload restrictions, SSRF `[+]` |
| 6 — API surface & transport | 6 | Response field allowlists, security headers, HTTPS/HSTS, admin & cron & webhook surface `[+]`, web-root and bucket exposure `[+]`, debug leakage in prod `[+]` |
| 7 — AI layer (conditional) | 1 | Prompt injection, tool scope and argument validation, treating model output as untrusted, secrets in system prompts `[+]` |
| 8 — Supply chain & ops | 3 | Dependency advisories, security-event logging & alerting `[+]`, backups and rollback path `[+]` |

**34 total — 20 from the source reel, 14 `[+]` additions.**

Full detection commands, verdict criteria, and fixes for each check live in
[`CHECKS.md`](CHECKS.md).

## Install

```bash
git clone https://github.com/jthoma74/pre-launch-security ~/.claude/skills/pre-launch-security
```

That's it — no dependencies, no build step. The skill is two markdown files; Claude Code picks it up
from `~/.claude/skills/` on the next session. It also works as a project skill (`.claude/skills/`) or
inside a plugin.

## Use

From a Claude Code session in the repo you want audited:

```
/pre-launch-security
```

Or just say what you want — the skill is written to trigger on natural phrasing:

- "is this safe to launch?"
- "audit this before I ship it"
- "run a pre-launch security check"

To go straight into fixes after the audit:

```
/pre-launch-security fix
```

Fixes are applied in severity order, smallest safe diff each, re-running the affected check after
each one. Nothing is auto-fixed during the audit itself.

## What the report looks like

It opens with a count — `X PASS · Y FAIL · Z WARN · W N-A` — then one table per group:

```
**Group 2 — Database & authorization**

| # | Check | Verdict | Evidence |
|---|---|---|---|
| 4 | Enable row-level security | FAIL | supabase/migrations/0002_init.sql:41 — `messages` created, no `enable row level security` |
| 22 | [+] Object-level authorization (IDOR) | FAIL | app/api/orders/[id]/route.ts:18 — lookup by id only, no `user_id` predicate |
| 5 | Encrypt sensitive data | N-A | No sensitive columns (no PII, tokens, or payment data in schema) |
```

and closes with one of two verdicts:

- **Don't ship** — any FAIL remains in Groups 1–4, or any secret is exposed. Exposed secrets also
  require rotation before launch: rewriting git history does not un-leak a key.
- **Ship with follow-ups** — only WARNs and/or Group 5–8 FAILs remain, listed as post-launch tasks.

## Requirements

- **Claude Code.** That's the only hard requirement.
- **Optional, for deeper coverage** — if any of these are already on your `PATH`, the relevant checks
  use them: `gitleaks` or `trufflehog` (git-history secret scanning), `osv-scanner`, `npm`/`pnpm`/`yarn
  audit`, `pip-audit` (via `uvx`), `cargo-audit`, `bundler-audit`, `govulncheck`.

  **The skill never installs any of them.** Every auditor invocation is gated on `command -v`, and an
  auditor that isn't present produces a `WARN` with the reason — never a silent `PASS`. An audit that
  mutates the project it is auditing has broken its own first rule.

  One nuance worth knowing: trufflehog's `--only-verified` mode verifies a secret by *sending it to
  the provider's API*. The skill uses `--no-verification` by default and will tell you if you ask for
  anything else.

## Honest limits

- **It audits the repo, not your dashboard.** Settings that live in a provider's UI — RLS toggles
  applied out of band, WAF rules, backup retention tiers, spend caps, DNS — cannot be read from
  source. Those come back as `WARN` + `verify manually: <what/where>`, never an assumed `PASS`.
- **Node/TypeScript is the primary target** (Next.js, Express, Prisma, Supabase, Firebase). Python
  equivalents (Django, Flask, FastAPI) are covered where they differ, and other stacks are handled by
  the same method — but pattern coverage is thinnest outside those.
- **Grep locates candidates; it cannot prove authorization.** The highest-value checks (7, 22, 33) are
  explicitly judgment calls that require reading handlers end to end. The skill says so and instructs
  the reading rather than pretending a clean grep is a clean bill of health. An empty grep never
  overrides the stack inventory.
- **No live probing by default.** If you supply a deployed URL, a few optional checks can confirm an
  HTTP→HTTPS redirect or that `/.env` 404s — but only with your explicit OK.
- **It is not a penetration test.** No exploitation, no fuzzing, no traffic sent at your app. It finds
  missing and defeated controls in code, which is a different (and cheaper) thing than proving
  exploitability.

## Related

If you want to vet *someone else's* repo before you install or run it, that's the opposite problem and
wants a different tool. This skill audits your own app before launch.

## Credits

Checks 1–20 are extracted from the Instagram reel
**"20 things to have Claude do before launching your app"** by
[millee.md](https://www.instagram.com/millee.md/) (Quoc Ly) —
https://www.instagram.com/reel/Db9aX8rhfhU/ — posted 2026-08-13. Credit for the original list is his.

Checks 21–34, marked `[+]` throughout, are additions covering the gaps in that list.

## License

MIT — see [LICENSE](LICENSE).
