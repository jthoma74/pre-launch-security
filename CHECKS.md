# Pre-launch security checks (34)

Reference for the `pre-launch-security` skill; loaded during Phase 1.

**Conventions.** Every command here is READ-ONLY — grep/glob/read/`git log`/ecosystem auditors. Never modify the target repo, never run the app's own code, never touch production. Live-endpoint probes are optional and only if the operator supplies a deployed URL.

`git grep -nIE` is the default matcher (tracked files only, skips binaries). In a non-git tree substitute `rg -nE '…' -g '!node_modules' -g '!*.lock'`. `git grep -L` lists files that do **not** match — the primary tool for "which routes are missing a guard".

**Default exclusions.** Vendored agent/skill/tooling trees are not app code. Append to every `git grep` below:
`-- ':!node_modules/*' ':!*lock*' ':!.claude/*' ':!.claude-flow/*' ':!.swarm/*' ':!_bmad*' ':!.cursor/*' ':!vendor/*' ':!third_party/*'`
and for the `rg` fallback: `-g '!node_modules' -g '!*.lock' -g '!.claude' -g '!.claude-flow' -g '!.swarm' -g '!_bmad*' -g '!.cursor' -g '!vendor' -g '!third_party'`.
**A security control only counts as present if it is found in app code.** Hits inside vendored agent/skill/tooling directories are noise **both ways** — they neither grant a PASS nor constitute a finding. Sole exception: checks 1 and 2, where a secret counts anywhere in the repo, vendored trees included.

**zsh glob safety.** Under zsh an unmatched glob aborts the whole command line (`no matches found`) *before* redirections apply, so `grep … next.config.* 2>/dev/null` does not fail quietly — nothing runs at all and you silently lose the check. Wrap config-file globs as `for f in <list>; do [ -e "$f" ] && grep … "$f"; done`, or run `setopt nullglob` first.

**Verdicts.** `PASS` control present and adequate · `FAIL` control absent or defeated · `WARN` present but weak, partial, or unverifiable from source · `N-A` the attack surface does not exist — **always state the reason** ("N-A: no file uploads", "N-A: no cookie auth, bearer-header API only"). Never emit a bare N-A.

Node/TS is the primary target (Next.js, Express, Prisma, Supabase, Firebase); Python equivalents (Django/Flask/FastAPI) are noted where they differ.

---

## Group 1 — Secrets & environment

### 1. Hide API keys

**Means:** No credential literal exists in source, config, committed build output, or anything shipped to the browser. Client-reachable env vars carry only public values.

**Detect:**
```bash
git grep -nIE "sk-[A-Za-z0-9]{16,}|sk_[A-Za-z0-9]{20,}|sk_live_|rk_live_|whsec_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-|glpat-|-----BEGIN [A-Z ]*PRIVATE KEY" -- ':!*.env*' ':!*lock*' ':!*.md'
# bare-hex API keys (ElevenLabs legacy, Recall, Deepgram, many voice/media vendors) — flag EVERY hit for review
git grep -nIE "\b[0-9a-f]{40}\b" -- ':!*.env*' ':!*lock*' ':!*.md' ':!*.snap'
git grep -nIE "(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY)[A-Za-z_]*\s*[:=]\s*[\"'\`][A-Za-z0-9+/_=-]{20,}" -- ':!*.env.example' ':!*lock*' ':!*test*'
# client-reachable prefixes must never name a privileged value
git grep -nIE "(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|GATSBY_)[A-Z0-9_]*(SECRET|PRIVATE|SERVICE|ADMIN|PASSWORD)" 
git grep -nIE "(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)[A-Z0-9_]*(KEY|TOKEN)"   # review each hit by hand
# committed build output is a client bundle
git ls-files | grep -E "^(dist|build|out|\.next|public/(js|assets))/" | head
```
**Derive the provider-specific patterns from the Phase 0 dependency list before running this check.** Every SDK in the manifest has a key shape: ElevenLabs `sk_…` (underscore, not the OpenAI hyphen), Recall/Deepgram and much of the voice-media tier bare 40-hex, Stripe `sk_live_`/`whsec_`, Supabase JWT-shaped `eyJ…`. A pattern set frozen at authoring time finds only the providers it was written for, not the stack you are auditing.

**Verdicts:** PASS — zero literal hits; every public-prefixed var is demonstrably a publishable value. FAIL — any live-looking credential in tracked source, or a privileged value behind a client prefix. WARN — high-entropy string that may be a test/placeholder key, or a public-prefixed var whose privilege you cannot confirm. N-A — never (every app has some config surface).

**Fix:** Move the value to a server-only env var (no client prefix), read it only in server code, and **rotate the exposed credential at the provider** — assume it is public.

**Judgment:** Placeholders (`sk-xxxx`, `your-key-here`, `example`) are not findings. A key-shaped string in a test fixture is WARN, not FAIL, unless it matches a live prefix (`sk_live_`, `AKIA`, `whsec_`). The bare-40-hex pattern is deliberately noisy — commit SHAs, `integrity` digests, and snapshot hashes match it. Triage each hit by what the surrounding identifier says it is (`*_API_KEY`, `*_TOKEN`, a provider client constructor) rather than discarding the pattern; a bare-hex key is invisible to every prefix-based scanner, which is exactly why it survives to launch.

### 2. Purge Git secrets

**Means:** Secret files were never committed, `.gitignore` covers them going forward, and anything that *was* committed has been rotated.

**Detect:**
```bash
grep -nE "^\.?env|^\*\.pem|secrets?" .gitignore 2>/dev/null; git check-ignore -v .env .env.local 2>/dev/null
# -AM, not -A: a key pasted into an ALREADY-TRACKED file is a modification, and -A never sees it
git log --all --diff-filter=AM --name-only --pretty=format: -- '*.env' '.env.*' '*secret*' '*credential*' '*.pem' '*.p12' '*.pfx' '*.keystore' 'serviceAccount*.json' | sort -u
# only if the tool is already installed — never install it
command -v gitleaks && gitleaks detect --no-banner --redact --report-format json --report-path "${TMPDIR:-/tmp}/gitleaks.json"
command -v trufflehog && trufflehog git file://. --no-verification --no-update
# CONTENT-based history pass — filenames prove nothing; -S counts occurrences, -G matches the diff text
for p in sk_live_ AKIA "BEGIN RSA PRIVATE KEY" service_role whsec_ xoxb-; do git log --all -n 300 --oneline -S"$p"; done
for p in '(sk_|sk-)[A-Za-z0-9]{20,}' '\b[0-9a-f]{40}\b'; do git log --all -n 300 --oneline -G"$p" -- ':!*lock*'; done
```
**Build the term list from Phase 0's provider inventory**, not from the fixed strings above: one term per provider (its env-var name *and* its key prefix — `ELEVENLABS_API_KEY`/`sk_`, `DEEPGRAM_API_KEY`, `OPENAI_API_KEY`/`sk-`, `RECALL_API_KEY`). Four hardcoded terms find four providers.

**`--only-verified` has an outbound side effect:** trufflehog verifies a candidate by *sending it to the provider's API*, which transmits secrets off the machine during a nominally read-only audit (and lights up the provider's auth logs). Prefer `--no-verification`; use `--only-verified` only with the operator's explicit consent, and say so in the report.

**Read the repo's recorded leaks** — `SECURITY.md`, `docs/known-issues*`, incident notes, runbooks (Phase 0 collected them). Agent-coded repos routinely carry entries like "key X was committed in `<sha>`, rotated on `<date>`". These are leads to verify, never evidence.

**Verifying a claimed remediation:**
```bash
git cat-file -t <documented SHA>                          # unresolvable ⇒ history was rewritten; resolvable ⇒ the blob is still reachable
git log --all --oneline -S'<pattern class>' | wc -l       # count only
git rev-list --all -n 300 | xargs -n1 -I{} git grep -cIE '<pattern class>' {} 2>/dev/null | head   # surviving blobs, counts only
```
Report SHAs and pattern-class counts — **never print a value, not even truncated.** Provider-side revocation cannot be established from the repo at all: it stays WARN + `verify manually: revoke <key class> at <provider> and audit its usage log`, however confidently a doc claims it was done.

**Verdicts:** PASS — no secret-bearing blob in history, `.gitignore` covers `.env*`. FAIL — a real credential appears in any historical commit and there is no evidence of rotation. WARN — history hit exists and rotation is claimed but undocumented, or `.env` is untracked but not gitignored. N-A — repo has no git history available (state so).

**Fix:** **Rotate first** — revoke and reissue every credential that ever touched a commit, and audit provider logs for use. History rewrite (`git filter-repo`, BFG) is secondary cleanup, not remediation.

**Judgment:** CRITICAL framing for the report: rewriting history does **not** un-leak. Forks, clones, CI caches, and GitHub's unreachable-commit API retain the blob. A repo that only rewrote history and did not rotate is still FAIL.

### 3. Use public DB key

**Means:** Only the anon/publishable key reaches the browser. Service-role, admin-SDK, and password-bearing connection strings stay server-side.

**Detect:**
```bash
git grep -nIE "service_role|SERVICE_ROLE|SUPABASE_SERVICE|supabaseAdmin|createAdminClient|SERVICE_ACCOUNT"
git grep -nIE "firebase-admin|admin\.initializeApp|cert\(|GOOGLE_APPLICATION_CREDENTIALS"
git grep -nIE "(postgres(ql)?|mysql|mongodb(\+srv)?)://[^:@/\"'\`]+:[^@\"'\`]+@"
# which of those files are client-reachable?
git grep -ln "^['\"]use client" -- 'app/**' 'src/**' 'components/**'
git grep -nIE "service_role|supabaseAdmin" -- 'components/**' 'app/**/page.tsx' 'app/**/layout.tsx' 'src/lib/client*'
```

**Verdicts:** PASS — privileged keys referenced only in server modules (`app/api/**`, `server/**`, server actions, `*.server.ts`) and never behind a client env prefix. FAIL — service-role key or admin creds imported into a `"use client"` module, a client env var, or a committed connection string with a password. WARN — privileged client constructed in a shared module that *could* be imported client-side.

**Fix:** Keep the service-role client in a server-only module (add `import 'server-only'` in Next.js); delete privileged values from any `NEXT_PUBLIC_`/`VITE_` name and rotate.

**Judgment:** An anon key in the browser is only safe if RLS actually constrains it — cross-ref check 4. An exposed anon key on a table with RLS off is equivalent to a full database dump.

### 26. [+] Separate prod from test

**Means:** Live and test credentials are distinct per environment and env-supplied; demo/seed/default accounts don't exist in prod; test and debug endpoints are absent or gated.

**Detect:**
```bash
git grep -nIE "sk_live_|pk_live_|sk_test_|pk_test_|_TEST_|_LIVE_"          # any literal = fail regardless of mode
git grep -nIE "process\.env\.(NODE_ENV|VERCEL_ENV|APP_ENV).*(test|live)|STRIPE_SECRET_KEY"
# seeded credentials / default admins
git grep -nIE "password['\"]?\s*[:=]\s*['\"](admin|password|test|test123|changeme|letmein|123456)" 
git grep -niE "(seed|demo|default)(_|-)?(user|admin|account)|is_admin.*true" -- prisma/ supabase/ migrations/ db/ scripts/ fixtures/ seeds/ 'src/**/seed*' 'app/**/seed*' 2>/dev/null
# test/debug/seed route surface — directory layout (Next/Remix/SvelteKit) is only half of it
find app pages src/routes api -type d \( -iname 'test*' -o -iname 'debug*' -o -iname 'seed*' -o -iname 'dev*' -o -iname '_internal*' \) 2>/dev/null
# decorator/table-mounted routes (FastAPI, Flask, Django, Express) — enumerate what is ACTUALLY mounted, then read the path names for test/debug/seed/reset/stub
git grep -nE "@(app|router)\.(get|post|put|patch|delete|websocket)\(|@app\.route\(|urlpatterns|Route\("
# gating evidence
git grep -nIE "NODE_ENV\s*[!=]==?\s*['\"]production" -- 'app/api/**' 'pages/api/**'
git grep -nE "os\.environ\.get\(.*(DEBUG|TEST|STUB|DEMO|MOCK)|os\.getenv\(.*(DEBUG|TEST|STUB|DEMO|MOCK)|settings\.(DEBUG|TESTING)" -- '*.py'
```

**Verdicts:** PASS — keys resolved from env per environment, no seeded credentials reachable in prod, test/debug routes absent or gated on a non-prod env check. FAIL — a live key hardcoded, a default-password account in a prod migration/seed, or an ungated `/debug|/seed|/test` route. WARN — gate exists but relies on a client-visible flag, or seeds are shared between dev and prod databases. A stub/demo/mock flag whose **default is on** (`os.environ.get("X_STUB", "1")`, `?? true`) is a finding *even though it is env-gated* — prod must opt **in** to the stub, never out of it, and one unset variable is all that stands between launch and serving fake data: FAIL if the flag bypasses auth, billing, or a safety gate, WARN otherwise.

**Fix:** Resolve every provider key from environment variables set per environment; move seeds into a dev-only script excluded from prod migrations; delete debug routes or guard them on a server-side env check plus auth.

---

## Group 2 — Database & authorization

### 4. Enable row-level security

**Means:** Every table holding user data enforces per-row authorization at the database layer (Postgres RLS, Firestore rules) — or all access is proxied through an authorization-checked server layer.

**Detect:**
```bash
# Postgres/Supabase: tables declared vs tables with RLS vs tables with policies
T="${TMPDIR:-/tmp}"
git grep -hoiE "create table (if not exists )?[\"a-z0-9_.]+" -- '*.sql' | awk '{print tolower($NF)}' | tr -d '"' | sort -u > "$T/tables"
git grep -hoiE "alter table [\"a-z0-9_.]+ enable row level security" -- '*.sql' | awk '{print tolower($3)}' | tr -d '"' | sort -u > "$T/rls"
git grep -hoiE "create policy .* on [\"a-z0-9_.]+" -- '*.sql' | awk '{print tolower($NF)}' | tr -d '"' | sort -u > "$T/pol"
comm -23 "$T/tables" "$T/rls"; comm -23 "$T/rls" "$T/pol"
# Firebase
cat firestore.rules storage.rules 2>/dev/null | grep -nE "if true|allow read, write|request\.auth == null"
# Prisma-only / server-mediated stacks
git grep -nE "policy|RLS|row level" -- 'prisma/**'; ls prisma/migrations | tail -5
```

**Verdicts:** PASS — every user-data table has RLS enabled *and* at least one non-permissive policy scoped to `auth.uid()`/`current_setting`; Firebase rules require `request.auth` and ownership. FAIL — a table with user data and RLS off, RLS on with zero policies (silently denies or, with a permissive grant, allows all), or `allow read, write: if true`. WARN — policies exist but use `USING (true)` or check only `auth.role() = 'authenticated'` (any logged-in user reads everyone's rows). N-A — no client-facing database key exists and all access flows through an authz-checked server layer: **state that explicitly** and lean on checks 7 and 22 instead.

**Fix:** `ALTER TABLE t ENABLE ROW LEVEL SECURITY;` plus explicit per-operation policies scoped to the owner column; for Firestore require `request.auth.uid == resource.data.ownerId`.

**Judgment:** RLS being "switched on" proves nothing. Read the policy predicates: a policy must bind a row to the *calling* identity, not merely to authentication. Also check `GRANT`s to `anon` — RLS does not save a table the anon role was granted `ALL` on with a permissive policy.

### 5. Encrypt sensitive data

**Means:** Application-level secrets and regulated fields — stored third-party API keys, OAuth refresh tokens, health/financial data, government IDs — are encrypted or tokenized at rest, not stored plaintext.

**Detect:**
```bash
git grep -niE "refresh_?token|access_?token|api_?key|client_?secret|ssn|social_security|date_of_birth|dob|card_?number|iban|routing|mrn|diagnosis" -- '*.prisma' '*.sql' 'supabase/migrations/**' 'models*' 'schema*'
git grep -nIE "createCipheriv|createDecipheriv|crypto\.subtle|libsodium|tweetnacl|sealedBox|pgp_sym_encrypt|pgcrypto|vault\.(create_)?secret|KMS|kms\.|Fernet|cryptography\.fernet|django-fernet|EncryptedField"
```

**Verdicts:** PASS — sensitive columns pass through an app-level cipher/KMS/Supabase Vault, or are never stored (exchanged per request). FAIL — provider tokens, stored user API keys, or regulated PII in plaintext columns. WARN — only provider disk encryption / "encryption at rest" is relied on while the app itself stores user secrets (a leaked DB credential or a broken RLS policy yields plaintext). N-A — no sensitive column exists; state which fields you reviewed.

**Fix:** Encrypt the column with an envelope key from a KMS (or `pgcrypto`/Supabase Vault), keep the key out of the database, and hash rather than encrypt anything you only need to compare.

**Judgment:** Disk encryption defends against a stolen disk, not against SQL injection, a leaked service-role key, or an over-broad RLS policy — that is why provider-only is WARN.

### 7. Lock record access

**Means:** Every read and write is behind an authenticated endpoint and scoped to the caller's own records.

**Detect:**
```bash
git grep -nIE "findMany\(|findFirst\(|findUnique\(|\.from\(['\"]|\.select\(|updateMany\(|deleteMany\(|objects\.(all|filter)\(" -- 'app/api/**' 'pages/api/**' 'src/routes/**' 'server/**' 'routers/**' 'views*'
# which handlers never mention the session subject at all
git grep -LIE "session\.user\.id|user\.id|auth\.uid\(\)|req\.user|request\.user|getUser\(|currentUser" -- 'app/api/**/route.ts' 'pages/api/**/*.ts' 'src/routes/**/*.ts'
git grep -nIE "where:\s*\{\s*id:|where:\s*\{\s*userId|eq\('user_id'|filter\(user="
```

**Verdicts:** PASS — every data access either filters on the session subject or is a deliberately public dataset. FAIL — a handler returns or mutates rows selected only by a client-supplied id with no owner predicate. WARN — owner scoping present on most endpoints but at least one relies solely on RLS while using a privileged client (escalate to check 22). N-A — **no user or tenant model exists** (single-tenant machine service, no accounts): state that, then assess the thing that replaces it — whether the scope of the one shared credential is deliberate. A single key that reads and writes everything is a design decision to report as such, not the absence of a finding. Unauthenticated surfaces are check 23's, not this one's.

**Fix:** Derive the subject from the server session, never from the request, and add the owner predicate to the query itself (`where: { id, userId: session.user.id }`) rather than filtering after fetch.

**Judgment:** Judgment-heavy — grep locates candidates, it cannot prove scoping. Read 3–5 representative handlers end to end (one list, one detail-by-id, one update, one delete, one nested/child resource) and report the actual trace. `updateMany`/`deleteMany` without an owner clause are the highest-yield finds.

### 8. Block field tampering

**Means:** Mutations write an explicit allowlist of fields. Raw request bodies are never spread into create/update, so privileged columns cannot be set by the client.

**Detect:**
```bash
git grep -nIE "\.\.\.(req\.body|request\.body|body|data|payload|input|values|json)\b"
git grep -nIE "data:\s*(body|req\.body|payload|await req\.json\(\)|input)\s*[,}]"
git grep -nIE "Object\.assign\((user|record|entity|doc|instance),"
git grep -nIE "\.update\((req\.body|body|payload)\)|insert\((body|payload)\)"
# privileged fields that must not be client-settable
git grep -nIE "\b(role|roles|is_?admin|isAdmin|is_?staff|permissions|credits|balance|price|amount|plan|tier|subscription_status|verified|email_verified|user_?id|owner_?id)\b" -- 'app/api/**' 'src/routes/**' 'server/**' 'schemas/**' 'validators/**'
```
Python/Django: `git grep -nE "fields\s*=\s*['\"]__all__['\"]|exclude\s*=" -- '*serializers*' '*forms*'`.
Python/Pydantic: `git grep -nE "model_config|ConfigDict\(extra=|class Config|extra\s*=\s*['\"](allow|ignore)" -- '*.py'` — no `extra="forbid"` anywhere means unknown keys are silently accepted; and `git grep -nE "\*\*(payload|body|data|req|item|kwargs)\b" -- '*.py'` — a request body splatted into a model or ORM constructor is the Python shape of the JS spread.

**Verdicts:** PASS — every mutation builds its payload field-by-field, or validates through a schema whose shape excludes privileged fields (zod `.strict()`, Pydantic `extra="forbid"`, DRF explicit `fields`). FAIL — raw body spread into a create/update, or a validation schema that accepts `role`/`credits`/`user_id`/`price` from the client. WARN — allowlist exists but the schema is non-strict, so unknown keys pass through to an ORM that accepts them. N-A — **no client-driven mutation exists** (read-only service, or every write is assembled entirely from server-side values): state what you enumerated — the write paths you found and where each field's value comes from — not merely that you found none.

**Fix:** Pick fields explicitly (`{ title: input.title, body: input.body }`), mark schemas strict so unknown keys are rejected, and set ownership and privilege fields server-side from the session.

### 22. [+] Test object-level authorization (IDOR/BOLA)

**Means:** Every route that accepts a resource identifier verifies that the authenticated caller may act on *that* object, between fetching it and returning or mutating it.

**Detect:**
```bash
# 1. enumerate id-taking routes
find app pages src/routes -type d -name '[[]*[]]' 2>/dev/null
git grep -nIE "params\.(id|[a-zA-Z]+Id)|req\.params\.|searchParams\.get\(['\"](id|user|account|org)|body\.(id|[a-zA-Z]+Id)" -- 'app/api/**' 'pages/api/**' 'src/routes/**'
# 2. routes using a privileged client — RLS does NOT protect these
git grep -lnIE "supabaseAdmin|SERVICE_ROLE|createAdminClient|admin\.(firestore|auth)\(\)|prisma\." -- 'app/api/**' 'pages/api/**' 'server/**'
# 3. of those, which never check ownership
git grep -LIE "session\.user\.id|user\.id ===|userId ===|=== *ownerId|requireOwner|assertCan|can\(|ability\." -- 'app/api/**/route.ts'
```

**Verdicts:** PASS — every id-taking handler compares the object's owner/tenant to the session subject (or the query itself carries the owner predicate). FAIL — any handler fetches by client-supplied id with a service-role/admin client and returns or mutates it with no ownership comparison. WARN — ownership enforced only by RLS on routes that use the anon key, with no defense in depth; or checks exist but use a sequential integer id with a guessable space and no rate limit. N-A — no route accepts a resource identifier (rare; state it).

**Fix:** After fetching, assert `resource.userId === session.user.id` (or a policy/CASL-style `can()` call) and return 404 on mismatch; prefer running user requests through the RLS-constrained client rather than the service-role client.

**Judgment:** This is the highest-frequency real vulnerability in agent-generated apps and it cannot be grepped to a verdict. Enumerate the id-taking routes into a list, then **read each handler's body** and record the authz line (or its absence) per route. Nested resources (`/projects/:pid/tasks/:tid`) need both levels checked — a valid task id under someone else's project is the classic miss. Also check that 403 vs 404 responses don't leak existence.

---

## Group 3 — Auth, sessions & account flows

### 6. Enforce server-side auth

**Means:** Authorization decisions happen on the server for every protected route. Hidden UI, client redirects, and client-sent user ids are not authorization.

**Detect:**
```bash
ls middleware.ts middleware.js src/middleware.ts 2>/dev/null && grep -nE "matcher|config|export const config" middleware.ts src/middleware.ts 2>/dev/null
# API routes with no server session check at all
git grep -LIE "getServerSession|auth\(\)|getUser\(|getSession|currentUser|verifyIdToken|requireAuth|withAuth|clerkClient|jwt\.verify|@login_required|IsAuthenticated|Depends\(get_current_user\)" -- 'app/api/**/route.ts' 'pages/api/**/*.ts' 'src/routes/**/*.ts' 'server/**/*.ts'
# trusting a client-supplied identity
git grep -nIE "userId\s*[:=]\s*(body|req\.body|payload|searchParams|req\.query|params)\.|const\s+\{\s*userId\s*\}\s*=\s*(await )?req"
# client-only gating masquerading as authz
git grep -nIE "useEffect\(.*router\.(push|replace)\(['\"]/(login|signin)|if \(!user\) return null" -- 'app/**' 'src/**' 'components/**'
# how is a shared bearer/API-key secret compared? plain ==/!= is timing-attackable
git grep -nIE "(token|secret|api_?key|apiKey|authorization|signature)\s*[!=]==?\s" -- 'app/api/**' 'src/routes/**' 'server/**' 'routers/**' 'middleware*' '*.py'
git grep -nIE "compare_digest|timingSafeEqual|hmac\.compare"   # presence = the control exists somewhere; check it is on the right comparison
```
Express: `git grep -nE "app\.use\(.*auth|router\.(get|post)\([^,]+,\s*(requireAuth|authenticate)"`.

**Verdicts:** PASS — middleware covers the protected path space *and* each protected handler re-checks the session server-side. FAIL — a protected route whose only gate is client-side, or a handler that takes the acting user id from the request. WARN — middleware-only protection with no per-handler check (a matcher typo silently unprotects everything), or a matcher whose regex misses `/api` subtrees; also WARN when a first-party shared secret (bearer token, service API key, cron or webhook secret) is compared with `==`/`!=` instead of a constant-time compare — the comparison short-circuits on the first differing byte and leaks the secret position by position to a patient caller. The fix is `secrets.compare_digest` (Python) or `crypto.timingSafeEqual` (Node) on equal-length buffers.

**Fix:** Re-derive the session inside every protected handler and return 401 before touching data; treat middleware as coarse routing defense, not the authorization boundary.

**Judgment:** Read the middleware `matcher` and compare it against the actual route tree — matcher gaps are invisible to grep. Note that Next.js middleware does not run for all invocation paths (route handlers called internally, some static/ISR paths), so per-handler checks are mandatory, not optional.

### 9. Secure session cookies

**Means:** Session cookies are `HttpOnly`, `Secure`, and `SameSite=Lax|Strict` with a sane path/domain; session tokens are not kept in `localStorage`.

**Detect:**
```bash
git grep -nIE "cookies\(\)\.set|res\.cookie\(|setCookie\(|Set-Cookie|cookieOptions|session:\s*\{"
git grep -nIE "httpOnly|secure\s*:|sameSite|SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|SESSION_COOKIE_SAMESITE|CSRF_COOKIE_SECURE"
git grep -nIE "localStorage\.setItem\(['\"][^'\"]*(token|jwt|session|auth|access)|sessionStorage\.setItem\(['\"][^'\"]*(token|jwt)"
git grep -nIE "sameSite:\s*['\"]none|secure:\s*false|httpOnly:\s*false"
```

**Verdicts:** PASS — all three attributes set (or the auth library's documented secure defaults are in use and unmodified). FAIL — `httpOnly: false` on a session cookie, `sameSite: 'none'` without a stated cross-site requirement, or a session JWT written to `localStorage`. WARN — attributes not set explicitly but the framework default is secure (Supabase SSR, NextAuth, Django) — note the reliance on the default. N-A — no cookie-based sessions (bearer-token API or fully third-party auth widget): state which.

**Fix:** Set `httpOnly: true, secure: true, sameSite: 'lax', path: '/'` on session cookies and move any localStorage-held session token into a cookie.

**Judgment:** `localStorage` tokens turn any XSS into full account takeover — pair this finding with check 15. Supabase's browser client storing the session in `localStorage` by default is a real WARN: note it and recommend the SSR/cookie adapter.

### 10. Hash passwords

**Means:** Stored passwords use a modern memory-hard or adaptive KDF with per-user salt: argon2id, bcrypt (cost ≥ 10), or scrypt with sound parameters.

**Detect:**
```bash
git grep -nIE "bcrypt|argon2|scrypt|pbkdf2|PASSWORD_HASHERS|passlib|CryptContext|werkzeug\.security"
git grep -nIE "bcrypt\.(hash|hashSync)\([^,]+,\s*[0-9]+|saltRounds|BCRYPT_ROUNDS|rounds:"
git grep -nIE "createHash\(['\"](md5|sha1|sha256)|hashlib\.(md5|sha1|sha256)\(|crypto\.createHash.*password"
git grep -nIE "password_?hash|hashed_?password|encrypted_password|password\s*:\s*String" -- '*.prisma' '*.sql' 'models*'
```

**Verdicts:** PASS — argon2id, or bcrypt with cost ≥ 10, or scrypt/PBKDF2 with current parameters, salt per user. FAIL — MD5/SHA-1/SHA-256 used directly on a password, unsalted, a shared global salt, encryption (reversible) instead of hashing, or a plaintext `password` column. WARN — bcrypt cost < 10, or PBKDF2 with a low iteration count. N-A — authentication is fully delegated to an IdP (Supabase Auth, Auth0, Clerk, Cognito, NextAuth OAuth-only) and the app stores no password material: **verify there is no local password column** before declaring this.

**Fix:** Switch to argon2id (or bcrypt cost 12), rehash transparently on next successful login, and drop any plaintext or reversibly-stored password column.

### 29. [+] Manage session lifecycle

**Means:** Sessions expire, the session identifier rotates at login and at privilege change (fixation defense), and the server can invalidate a session on logout and on password change.

**Detect:**
```bash
git grep -nIE "maxAge|expiresIn|expires_in|exp:|SESSION_COOKIE_AGE|JWT_EXPIR|ACCESS_TOKEN_EXPIRE|ttl:|idleTimeout"
git grep -nIE "signOut|logout|revoke(Session|Token|Refresh)|destroySession|session\.destroy|deleteSession|invalidateSessions|tokenVersion|sessionVersion|jti|denylist|blacklist"
git grep -nIE "regenerate|rotateSession|cycleKey|session\.regenerate|refreshSession"
git grep -nIE "jwt\.sign\(|SignJWT|encode_jwt" -- 'app/**' 'src/**' 'server/**'   # is there any revocation path?
```

**Verdicts:** PASS — finite session/access-token lifetime, identifier rotated on login and on role change, and logout plus password change invalidate server-side (session row deleted, or a `tokenVersion`/`jti` denylist checked on each request). FAIL — non-expiring sessions, or logout that only clears the client cookie while the token stays valid. WARN — stateless JWT with short expiry but **no revocation strategy**: a stolen or post-password-change token remains usable until expiry — state the window. N-A — no sessions at all (stateless public app): state it.

**Fix:** Set an absolute and idle timeout, regenerate the session id on login and privilege change, and on logout/password change delete the server session row or bump a per-user `tokenVersion` that every request validates.

### 30. [+] Harden account flows

**Means:** Login, signup, and password reset reveal nothing about whether an account exists; reset tokens are single-use, short-lived, and hashed at rest; email is verified before privileged actions.

**Detect:**
```bash
git grep -niE "user not found|no (such )?user|no account|email (not found|already (exists|registered|in use))|account (already )?exists|invalid password|incorrect password|wrong password"
git grep -nIE "reset(_|-)?(token|code)|passwordResetToken|verificationToken|otp|one_?time" -- '*.prisma' '*.sql' 'app/**' 'src/**' 'server/**'
git grep -nIE "used_?at|consumed_?at|usedAt|expires_?at|expiresAt|randomBytes\(|randomUUID\(|generateToken"
git grep -nIE "emailVerified|email_verified|email_confirmed_at|is_verified|confirmed_at"
```

**Verdicts:** PASS — identical generic response and status for existing vs unknown accounts across login/signup/reset; reset tokens are ≥128-bit random, stored hashed, single-use (`usedAt` set), expiring in ≤1h; privileged actions gated on verified email. FAIL — a distinct "no such user"/"email already registered" response, a reset token stored in plaintext or reusable, or a non-expiring reset link. WARN — messages are uniform but signup still errors distinctly on duplicate email, or reset tokens expire but are not marked single-use, or verification exists but is not enforced on privileged actions.

**Fix:** Return one generic message ("If an account exists, we've sent a link") with the same status code on every path; store `sha256(token)` with `expiresAt` and `usedAt`; require `emailVerified` before billing, sharing, or role changes.

**Judgment:** Also consider response-time enumeration: a path that skips the password-hash comparison for unknown users answers measurably faster. Confirm the code performs a dummy hash (or that timing is otherwise equalized) — this cannot be grepped, only read. Signup duplicate-email handling is the flow most often left enumerable by design; flag it with the UX tradeoff noted.

---

## Group 4 — Abuse & request forgery

### 11. Rate limit login

**Means:** Credential-facing endpoints — login, signup, password reset, OTP/magic-link, token refresh — are rate-limited per IP and per account.

**Detect:**
```bash
git grep -niE "rate.?limit|Ratelimit|@upstash/ratelimit|express-rate-limit|rate-limiter-flexible|@fastify/rate-limit|slowapi|django-ratelimit|axios-retry|throttle|Throttled|arcjet|unkey"
grep -nE "firewall|rateLimit|rules" vercel.json 2>/dev/null; ls .github/workflows wrangler.toml netlify.toml 2>/dev/null
git grep -nIE "attempt(s)?|lockout|locked_until|failed_login" -- '*.prisma' '*.sql' 'app/**' 'server/**'
```

**Verdicts:** PASS — a limiter wraps the auth endpoints with a concrete store (Redis/Upstash/memory-with-single-instance-caveat) or platform WAF rules exist in committed config. FAIL — no limiter and no platform rule anywhere on credential endpoints. WARN — limiter configured but only in-memory on a serverless/multi-instance deploy (per-instance, trivially bypassed), or the auth provider's built-in limits are relied on without verification. N-A — only third-party IdP redirect flows, no first-party credential endpoint: state it.

**Fix:** Add a shared-store limiter (Upstash Ratelimit, `rate-limiter-flexible` on Redis) keyed on both IP and identifier, plus progressive lockout on repeated failures per account.

**Judgment:** "Vercel/Cloudflare handles it" is not a PASS unless the rule exists in committed config or the operator confirms it in the dashboard. Note it as unverified otherwise.

### 12. Add bot protection

**Means:** Public, unauthenticated forms that cost money or create records (signup, contact, comment, waitlist, invite) have a bot challenge or equivalent heuristic gate.

**Detect:**
```bash
git grep -niE "turnstile|hcaptcha|recaptcha|grecaptcha|altcha|friendly-?captcha|mtcaptcha|botid|arcjet|honeypot|_gotcha|pow-?challenge"
git grep -nIE "TURNSTILE_SECRET|RECAPTCHA_SECRET|siteverify|challenges\.cloudflare\.com"
# inventory the public forms to compare against
git grep -lnIE "<form|onSubmit|action=\"/api" -- 'app/**' 'src/**' 'components/**'
```

**Verdicts:** PASS — a challenge is rendered *and* its token is verified server-side (`siteverify` call present) on each public form. FAIL — no bot protection on any public form. WARN — widget rendered but no server-side verification (trivially bypassed), or protection on signup only while a public contact/comment form triggers email sends or LLM calls. N-A — no unauthenticated write surface: state it. **N-A also for a machine-to-machine service with no browser forms** — an unauthenticated non-form write surface (a bare `POST`/WebSocket endpoint a script calls) is *not* a CAPTCHA finding: a bot challenge cannot be rendered to a caller that has no browser, and demanding one here produces a fix nobody can implement. Report the missing authentication under check 23 and the missing per-caller quota under check 28, then mark this N-A **with that pointer** so the surface is visibly assessed rather than dropped.

**Fix:** Add Cloudflare Turnstile (or hCaptcha) to each public form and verify the token server-side before processing; a honeypot field plus timing heuristic is an acceptable lighter gate on low-value forms.

### 21. [+] Protect against CSRF

**Means:** State-changing requests cannot be triggered by another origin — via a synchronizer token, or by verifying `Origin`/`Sec-Fetch-Site` server-side.

**Detect:**
```bash
git grep -niE "csrf|xsrf|csurf|CsrfViewMiddleware|csrf_token|@fastify/csrf|next-safe-action|Sec-Fetch-Site"
git grep -nIE "headers\(\)\.get\(['\"](origin|referer|sec-fetch-site)|req\.headers\.(origin|referer)|request\.headers\.get\(['\"]origin"
git grep -nIE "sameSite:\s*['\"](lax|strict)"
# do cookies authenticate mutating routes at all?
git grep -lnIE "cookies\(\)|req\.cookies|request\.cookies" -- 'app/api/**' 'pages/api/**' 'server/**'
```

**Verdicts:** PASS — mutating routes verify a CSRF token, or check `Origin`/`Sec-Fetch-Site` against an allowlist, or the framework's CSRF middleware is enabled globally (Django `CsrfViewMiddleware`, NextAuth's built-in token on its own routes). FAIL — cookie-authenticated mutating routes with no token and no origin check. WARN — `SameSite=Lax` is the only defense: it blocks cross-site POSTs in current browsers but not same-site subdomain attacks, `GET`-triggered mutations, or older clients — note the residual risk. N-A — no cookie auth; every mutating request carries a bearer token in a custom header that a cross-origin form cannot set: **state that reason explicitly**.

**Fix:** Verify `Sec-Fetch-Site: same-origin` (with an `Origin` allowlist fallback) at the start of every mutating handler, or adopt the framework's CSRF token; never expose a mutation over `GET`.

**Judgment:** Next.js Server Actions include origin checking by default, but plain route handlers do not — check them separately. Confirm no mutation is reachable via `GET`.

### 27. [+] Configure CORS deliberately

**Means:** Cross-origin access is granted to an explicit, finite list of origins — never reflected from the request, never `*` alongside credentials.

**Detect:**
```bash
git grep -nIE "Access-Control-Allow-Origin|Access-Control-Allow-Credentials|Access-Control-Allow-Headers"
git grep -nIE "cors\(|CORSMiddleware|CORS_ALLOW|CORS_ORIGIN|allowedOrigins|allow_origins|origin:\s*(true|\*|['\"]\*)"
for f in next.config.js next.config.mjs next.config.ts vercel.json netlify.toml _headers nginx.conf; do [ -e "$f" ] && grep -nE "headers|Access-Control" "$f"; done
# reflection: echoing the request Origin back
git grep -nIE "Allow-Origin[\"']?\s*[,:]\s*(req|request)\.headers|origin:\s*\(origin, *(cb|callback)\) *=> *(cb|callback)\(null, *true\)"
```

**Verdicts:** PASS — a hardcoded/env-driven origin allowlist; `*` appears only on genuinely public, credential-free endpoints. FAIL — `Access-Control-Allow-Origin: *` together with `Allow-Credentials: true`, or the request `Origin` reflected back unconditionally, or `cors({ origin: true, credentials: true })`. WARN — allowlist present but includes broad wildcards (`*.vercel.app`, `localhost` in prod config) or the preflight config and manual headers disagree. N-A — no cross-origin API consumers and no CORS headers set: state it.

**Fix:** Replace wildcards and reflection with an explicit allowlist read from env, echo the origin only after an exact allowlist match, and keep `Allow-Credentials` off unless cookies are genuinely needed cross-origin.

**Judgment:** Check both layers — framework middleware and hand-written headers in `next.config.js`/`vercel.json`/nginx. A permissive manual header silently overrides a careful middleware config.

### 28. [+] Rate-limit globally + cap costs

**Means:** Beyond login, expensive endpoints have per-user quotas — search, exports, report generation, email/SMS senders, and above all LLM/AI calls, which need both request-count and token/spend caps ("denial of wallet").

**Detect:**
```bash
git grep -lnIE "openai|@anthropic-ai|@ai-sdk|generateText|streamText|generateObject|replicate|bedrock|gemini|groq|elevenlabs|resend|sendgrid|twilio|puppeteer|playwright"
git grep -nIE "maxTokens|max_tokens|maxOutputTokens|max_completion_tokens|budget|quota|credits?(Remaining|Used)|usage_?limit|spend|monthly_?limit|tokensUsed"
git grep -nIE "limit\(|take:|pageSize|PAGE_SIZE|LIMIT [0-9]" -- 'app/api/**' 'server/**'
git grep -nIE "ratelimit|Ratelimit" -- 'app/api/**' 'src/routes/**' 'middleware.ts'
```

**Verdicts:** PASS — per-user (not just per-IP) request quota on each expensive endpoint, `maxTokens` bounded on every model call, and a tracked per-user token/credit budget enforced before the call. FAIL — an unauthenticated or unmetered endpoint that triggers LLM inference, email sending, headless-browser work, or an unbounded export. WARN — provider-side spending limits or a global rate limit exist but there is no per-user cap, so one abusive account can consume the whole budget; or `maxTokens` unset on streaming calls. N-A — no expensive endpoints and no AI calls: state it.

**Fix:** Require auth on every paid-work endpoint, meter usage per user in the database and refuse over-budget requests before calling the provider, bound `maxTokens` and result-set sizes, and set a provider-side hard spend cap as a backstop.

**Judgment:** Provider spend limits count toward PASS only as a backstop — they cap the blast radius, they do not stop the abuse. Per-user caps are the real control. Cross-ref check 33.

---

## Group 5 — Input handling

### 13. Parameterize queries

**Means:** No SQL is built by string concatenation or interpolation with data that can come from a request.

**Detect:**
```bash
git grep -nIE '\$queryRawUnsafe|\$executeRawUnsafe|queryRawUnsafe|\.query\(`|\.execute\(`|knex\.raw\(`|sequelize\.query\(`|db\.raw\(`|sql\.unsafe'
git grep -nIE '(SELECT|INSERT INTO|UPDATE|DELETE FROM|WHERE|ORDER BY)[^;]*\$\{'
git grep -nIE "Sequelize\.literal\(|literal\(|QueryTypes\.SELECT"
```
Python:
```bash
git grep -nIE 'execute\(f["\x27]|execute\(["\x27][^"\x27]*%s?["\x27]\s*%|cursor\.execute\([^,)]*\+|text\(f["\x27]|\.raw\(f["\x27]|extra\(where='
```

**Verdicts:** PASS — all access via ORM/query builder or parameterized statements (`$1`, `?`, `:name`); tagged-template `sql` helpers count (they parameterize interpolations). FAIL — request-derived data interpolated into a SQL string, or `$queryRawUnsafe`/`execute(f"…")` with non-constant input. WARN — raw SQL with interpolation of values that are currently internal constants or enum-validated (fragile, one refactor from injection), or a dynamic `ORDER BY`/table name not checked against an allowlist. N-A — no SQL database (document store / API-only): state it and check NoSQL operator injection instead (`$where`, `$ne` from user objects).

**Fix:** Use parameter placeholders for every value; for identifiers that must be dynamic (sort column, table), map the input through a hardcoded allowlist rather than interpolating.

**Judgment:** Prisma's `sql` tagged template and `$queryRaw` parameterize; `$queryRawUnsafe` does not — distinguish them. Note that `LIMIT`/`OFFSET` and `ORDER BY` cannot be parameterized in most drivers, so those are the spots to read closely.

### 14. Validate all input

**Means:** Every server entry point validates and coerces its input against a schema before use — body, query string, route params, and any header the code reads.

**Detect:**
```bash
git grep -lnIE "from ['\"](zod|joi|yup|valibot|superstruct|@sinclair/typebox)|pydantic|BaseModel|marshmallow|serializers\.|class-validator"
# handlers with no validation call
git grep -LIE "\.parse\(|safeParse\(|\.validate(Async)?\(|schema\.|BaseModel|Depends\(" -- 'app/api/**/route.ts' 'pages/api/**/*.ts' 'src/routes/**/*.ts' 'server/**/*.ts'
# unvalidated reads
git grep -nIE "await req\.json\(\)|req\.body\.[a-z]|searchParams\.get\(|req\.query\.[a-z]|params\.[a-z]" -- 'app/api/**' 'pages/api/**'
git grep -nIE "Number\(searchParams|parseInt\(req\.query|as unknown as|as any" -- 'app/api/**'
```
Python/FastAPI: `git grep -nE "request\.query_params|query_params\.get\(|Header\(|request\.headers\.get\(" -- '*.py'` — a `request.query_params.get(...)` value used directly in logic is the unvalidated boundary, and a raw `Header(...)`/`headers.get()` read is the same for headers; a `Depends(` that resolves a Pydantic model, or a typed Pydantic body / `Query(...)` annotation, is validation present.

**Verdicts:** PASS — a schema parse at the top of every handler covering body, query, and params, with strict/unknown-key rejection. FAIL — any handler consuming request data with no server-side schema, or validation implemented only in the client form. WARN — body validated but query/params/pagination values passed through raw (`Number(searchParams.get('limit'))` with no bound), or schemas present but non-strict. N-A — no request-handling code (static site): state it.

**Fix:** Parse at the boundary — `const input = Schema.strict().parse(await req.json())` — validate query and params with their own schemas, bound every numeric (pagination limits, ids), and treat client-side validation purely as UX.

**Judgment:** Client-side-only validation is FAIL for that boundary, full stop. Also check that type assertions (`as Foo`, `as any`) are not being used *in place of* runtime validation — TypeScript types vanish at runtime and agent-written code leans on them heavily.

### 15. Escape user content

**Means:** User-influenced strings are never injected as HTML. Where rich text is required, it is sanitized with a configured allowlist.

**Detect:**
```bash
git grep -nIE "dangerouslySetInnerHTML|v-html|\{@html|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write|\$\(.*\)\.html\(|mark_safe|\|\s*safe|Markup\(|autoescape off"
git grep -nIE "DOMPurify|sanitize-html|xss|rehype-sanitize|bleach|nh3"
git grep -nIE "html:\s*true|allowDangerousHtml|rehype-raw|skipHtml:\s*false|marked\(|markdown-it\("
# sinks that execute strings
git grep -nIE "new Function\(|eval\(|setTimeout\(['\"\`]|href=\{|window\.location\s*=" -- 'app/**' 'src/**' 'components/**'
```

**Verdicts:** PASS — no raw-HTML sink receives user data, or every one is preceded by DOMPurify/`sanitize-html`/`nh3` with an explicit allowlist config. FAIL — user-influenced value reaching `dangerouslySetInnerHTML`/`v-html`/`innerHTML` unsanitized, a markdown renderer with `html: true` on user content, or `mark_safe` on user input. WARN — sanitizer called with default config on a surface that also allows `style`/`href` (residual `javascript:` and CSS-exfil risk), or sanitization done client-side only on content also served elsewhere. N-A — no raw-HTML sink anywhere (framework auto-escaping only): state it.

**Fix:** Render user text as text and let JSX/template escaping work; where HTML is required, sanitize server-side with an explicit tag/attribute allowlist and forbid `javascript:`/`data:` URLs.

**Judgment:** Trace each sink's argument back to its source — a sink fed by a hardcoded constant or an editorial CMS field is not the same finding as one fed by a comment body. Also check user-controlled `href`/`src` for `javascript:` and user-controlled SVG uploads rendered inline.

### 16. Restrict file uploads

**Means:** Uploads are validated by content (magic bytes) as well as declared type, size-capped, renamed, stored outside the served directory, and never executable.

**Detect:**
```bash
git grep -lnIE "multer|formidable|busboy|multipart|@vercel/blob|uploadthing|createSignedUploadUrl|storage\.from\(.*\.upload|UploadFile|FileField|ImageField|presigned"
git grep -nIE "mimetype|file\.type|Content-Type|fileFilter|accept=|allowedTypes|ALLOWED_EXTENSIONS"
git grep -nIE "file-type|fileTypeFromBuffer|magic|imghdr|python-magic|filetype\.guess|sharp\(.*metadata"
git grep -nIE "limits:\s*\{|maxFileSize|fileSize|MAX_CONTENT_LENGTH|maxSizeBytes|bodyParser.*sizeLimit"
git grep -nIE "originalname|originalFilename|file\.name|path\.join\([^)]*(originalname|filename)|secure_filename|randomUUID\(|nanoid\("
git ls-files | grep -E "^(public|static)/(uploads?|files|media)/" | head
```

**Verdicts:** PASS — server-side extension/MIME allowlist *plus* magic-byte verification, an enforced size cap, a server-generated random filename, storage in object storage or a non-served path, and image processing through a current library. FAIL — type trusted from extension or client `Content-Type` alone, no size limit, the client-supplied filename used as the storage path (traversal / overwrite), or uploads landing in `public/`. WARN — allowlist and size cap present but no magic-byte check, or SVG/HTML permitted in a bucket served from the app origin (stored XSS). N-A — no upload surface: state it.

**Fix:** Verify the first bytes against an allowlist (`file-type`/`python-magic`), enforce a byte cap at the parser *and* the platform, store under a generated UUID key in object storage with a non-executable content type, and serve user files from a separate origin or via signed URLs.

**Judgment:** Cross-ref check 20 — `sharp`/`libvips`/ImageMagick/Pillow CVEs turn any accepted image into RCE, so the dependency verdict feeds this one. Cross-ref check 24 for bucket ACLs. Re-derive `Content-Type` on download rather than echoing the stored one.

### 31. [+] Guard against SSRF

**Means:** Any server-side fetch of a URL that a user supplies — webhook targets, link previews, avatar-by-URL, importers, RSS, AI browsing tools — restricts scheme and destination address, and re-checks on redirect.

**Detect:**
```bash
git grep -nIE "fetch\((url|targetUrl|req|body|input|params|link|webhook|endpoint)|axios\.(get|post|request)\((url|body|input)|got\(|node-fetch|undici\.request"
git grep -nIE "requests\.(get|post)\(|httpx\.(get|post|AsyncClient)|urllib\.request\.urlopen|aiohttp\.ClientSession"
# controls
git grep -nIE "169\.254|metadata\.google|metadata\.aws|is_?private|isPrivateIp|ipaddress\.ip_address|net\.isIP|dns\.(lookup|resolve)|allowlist|allowedHosts|urlAllowlist|blockedRanges|new URL\(.*protocol|redirect:\s*['\"]manual|maxRedirects:\s*0|ssrf"
# proxy/image-optimizer style passthroughs
git grep -nIE "searchParams\.get\(['\"](url|src|image|target|redirect|next|callback)" -- 'app/api/**' 'pages/api/**'
for f in next.config.js next.config.mjs next.config.ts; do [ -e "$f" ] && grep -nE "remotePatterns|domains" "$f"; done
```

**Verdicts:** PASS — scheme restricted to `https:`, hostname resolved and checked against private/loopback/link-local/CGNAT ranges before connecting, redirects disabled or re-validated per hop, and a timeout plus response-size cap. FAIL — a server fetch of a user-supplied URL with no scheme or address restriction (cloud metadata at `169.254.169.254` and internal services are reachable). WARN — hostname allowlist or a string blocklist only (DNS-rebinding and decimal/IPv6-mapped encodings bypass string checks), or redirects followed without re-validation. N-A — the server never fetches a user-supplied URL: state it after checking webhooks, importers, previews, and AI tools.

**Fix:** Allow only `https:`, resolve the host and reject `127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `::1`, and IPv4-mapped equivalents; set `redirect: 'manual'` and re-run the check on each hop; add a timeout and response cap, and prefer a dedicated egress proxy.

**Judgment:** The check must happen on the resolved IP at connect time, not on the string — otherwise DNS rebinding defeats it. Open-redirect parameters (`?next=`, `?callback=`) belong here too: verify they only accept relative paths or allowlisted origins.

---

## Group 6 — API surface & transport

### 17. Trim API responses

**Means:** Responses serialize an explicit field allowlist. Whole ORM rows, password hashes, internal tokens, and other users' PII never leave the server.

**Detect:**
```bash
git grep -nIE "findMany\(\)|findMany\(\{[^}]*\}\)|findFirst\(|findUnique\(" -- 'app/api/**' 'server/**' | grep -v "select"
git grep -nIE "SELECT \*|\.select\(\)|\.select\(['\"]\*|objects\.all\(\)"
git grep -nIE "NextResponse\.json\((user|users|rows|data|result|record|items)\s*[,)]|res\.json\((user|rows|data)\s*\)|jsonify\(.*__dict__"
git grep -nIE "password|password_?hash|hashed|salt|refresh_?token|api_?key|stripe_customer|internal_?note|email" -- '*serializer*' '*dto*' '*schema*' 'app/api/**'
git grep -nIE "fields\s*=\s*['\"]__all__['\"]|exclude\s*=" -- '*serializers*'
```

**Verdicts:** PASS — every endpoint uses `select`/a DTO/a serializer with an explicit field list; no sensitive field appears in any response type. FAIL — a handler returns an un-`select`ed row or `SELECT *` result directly, or any response includes a password hash, a stored provider token, or another user's email/PII. WARN — allowlists used on most endpoints but relations are included wholesale (`include: { user: true }` drags the whole user row), or `fields = '__all__'` on a model with sensitive columns. N-A — no data-returning API: state it.

**Fix:** Add explicit `select` to every query (or a serializer/DTO layer at the edge) and include nested relations by explicit field, never `true`.

**Judgment:** Read the response shape, not just the query — a `select` that's correct at the top level often pulls a full related record. Also check error payloads and list endpoints' embedded author objects, the two usual leak paths.

### 18. Add security headers

**Means:** The app sends CSP, HSTS, `X-Content-Type-Options`, frame protection, and a restrictive `Referrer-Policy`.

**Detect:**
```bash
for f in next.config.js next.config.mjs next.config.ts vercel.json netlify.toml _headers nginx.conf Caddyfile .htaccess; do [ -e "$f" ] && echo "present: $f"; done
for f in next.config.js next.config.mjs next.config.ts vercel.json netlify.toml _headers nginx.conf Caddyfile .htaccess; do [ -e "$f" ] && grep -niE "Content-Security-Policy|Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options|frame-ancestors|Referrer-Policy|Permissions-Policy" "$f"; done
git grep -nIE "helmet\(|secure_headers|SecurityMiddleware|SECURE_HSTS_SECONDS|X_FRAME_OPTIONS|CSP_|contentSecurityPolicy|nonce"
git grep -nIE "unsafe-inline|unsafe-eval|default-src \*|script-src \*"
```

**Verdicts:** PASS — CSP with a `default-src`/`script-src` that excludes `unsafe-eval` and uses nonces or hashes for inline script, plus HSTS (`max-age` ≥ 15552000), `nosniff`, `frame-ancestors 'none'`/`X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`. FAIL — no security headers configured anywhere. WARN — headers present but CSP is permissive (`unsafe-inline` on `script-src`, wildcard sources) or CSP is report-only, or HSTS is missing while cookies are marked `Secure`. N-A — **never for a browser-facing app.** For a browser-less API (no HTML served, no cookies, no browser client — confirm against the Phase 0 delivery shape) CSP, `X-Frame-Options`/`frame-ancestors`, `Permissions-Policy`, and `Referrer-Policy` are inert: there is no document to frame, no script to constrain, and no referrer to send. Assess **HSTS** and **`X-Content-Type-Options: nosniff`** on their merits (both still matter — one protects the bearer token in transit, the other a JSON response a browser is later pointed at) and mark the remaining headers N-A with that reason. **Do not force a FAIL for headers that have no browser to protect** — a fix the app cannot use is noise that buries the real findings.

**Fix:** Add a headers block in `next.config.js`/`vercel.json`/helmet covering all five; start CSP in report-only, move to nonce-based `script-src` and drop `unsafe-inline`.

**Judgment:** A CSP with `unsafe-inline` in `script-src` provides little XSS protection — report it as WARN with that stated plainly rather than crediting the header's presence. `unsafe-inline` in `style-src` is a much smaller concern; distinguish them.

### 19. Force HTTPS

**Means:** All traffic is HTTPS: HTTP redirects to HTTPS, HSTS is sent, and the app never hardcodes `http://` URLs for itself or its APIs.

**Detect:**
```bash
rg -nP "http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker)" -g '!*.md' -g '!*.lock' -g '!node_modules' 2>/dev/null || git grep -nIE "http://[a-z0-9.-]+\.[a-z]{2,}"
git grep -nIE "Strict-Transport-Security|SECURE_SSL_REDIRECT|SECURE_HSTS|PREFERRED_URL_SCHEME|forceSSL|trustProxy|X-Forwarded-Proto|requireHTTPS"
git grep -nIE "NEXTAUTH_URL|APP_URL|BASE_URL|SITE_URL|VITE_API_URL" -- ':!*.md'
for f in netlify.toml vercel.json nginx.conf Caddyfile fly.toml; do [ -e "$f" ] && grep -nE "redirect|force_https|ssl" "$f"; done
```
Optional, only with an operator-supplied deployed URL: `curl -sSI http://<domain>` and confirm a 301/308 to `https://` plus an HSTS header on the HTTPS response.

**Verdicts:** PASS — platform enforces the redirect, HSTS is present, and no non-local `http://` URL appears in app config. FAIL — an `http://` production URL in config/code, or a self-hosted deployment with no redirect configured. WARN — hosted on a platform that redirects by default (Vercel/Netlify/Fly) but a custom domain's config is unverified, or the redirect exists without HSTS. N-A — **never for a browser-facing app.** Transport still applies to a browser-less API — a machine client's bearer token leaks over plaintext exactly as a cookie does — so judge the redirect and HSTS normally there; only the browser-specific portions (mixed content, `http://` asset URLs, HSTS preload) go N-A with that reason, never a forced FAIL.

**Fix:** Enforce the redirect at the platform or reverse proxy, send HSTS with `includeSubDomains`, and change every app URL to `https://`; trust `X-Forwarded-Proto` only behind a proxy you control.

**Judgment:** Don't assume platform defaults — verify custom-domain and apex/`www` configuration, which is where the redirect is usually missing. `Secure` cookies (check 9) depend on this being real.

### 23. [+] Lock admin & internal surface

**Means:** Admin pages/APIs enforce a role check; cron, queue, and job endpoints authenticate their caller; webhook receivers verify the provider's signature.

**Detect:**
```bash
find app pages src/routes -type d \( -iname '*admin*' -o -iname '*cron*' -o -iname '*webhook*' -o -iname '*internal*' -o -iname '*queue*' -o -iname '*job*' \) 2>/dev/null
# role checks
git grep -nIE "role\s*[=!]==?\s*['\"]admin|isAdmin|is_?staff|is_?superuser|requireRole|hasRole|permissions\.includes|ability\.can|@admin_required" 
# cron/job auth
grep -nE "crons|schedule" vercel.json 2>/dev/null
git grep -nIE "CRON_SECRET|x-vercel-cron|QSTASH_|INNGEST_SIGNING|TRIGGER_SECRET|authorization.*Bearer.*CRON"
# webhook signature verification
git grep -nIE "constructEvent|stripe\.webhooks|createHmac|timingSafeEqual|hmac\.compare_digest|verify_?signature|svix|Webhook\(|X-Hub-Signature|X-Signature|stripe-signature"
```

**Verdicts:** PASS — every admin route checks a server-side role, every cron/job handler validates a secret or platform signature *inside the handler*, and every webhook verifies an HMAC/provider signature with a constant-time compare before parsing. FAIL — an admin route protected only by an unguessable path or a client-side role check, a cron endpoint callable by anyone, or a webhook that trusts its body unverified (payment/entitlement forgery). WARN — signature verified but the raw body is re-parsed or the secret compared non-constant-time; or a cron secret exists in env but is not actually checked in the handler. N-A — no admin, cron, or webhook surface: state which of the three you checked.

**Fix:** Gate admin routes on a server-derived role claim; compare the cron secret (or verify the platform signature) as the handler's first statement; verify webhook signatures over the **raw** body with the provider SDK and reject on mismatch.

**Judgment:** Vercel cron: `vercel.json` declaring a cron proves the schedule, not the auth — read the handler for the `CRON_SECRET` check. Webhook handlers must use the raw body; a framework that JSON-parses first silently breaks signature verification, and agent-written code often "fixes" that by skipping verification.

### 24. [+] Deny web-root & bucket exposure

**Means:** Secrets, VCS metadata, dumps, and backups are not in the served directory and not deployed; source maps aren't public unless deliberately accepted; storage buckets are private by default with signed URLs for private assets.

**Detect:**
```bash
git ls-files public/ static/ dist/ 2>/dev/null | grep -Ei "\.(env|sql|dump|bak|old|zip|tar\.gz|tgz|pem|key|p12|sqlite3?|db|csv)$|/\.(env|git|ssh)"
ls -a public/ static/ 2>/dev/null
cat .vercelignore .dockerignore .gcloudignore 2>/dev/null
git grep -nIE "productionBrowserSourceMaps|sourcemap:\s*true|devtool:\s*['\"]source-map|GENERATE_SOURCEMAP"
# bucket / storage config
git grep -nIE "public:\s*true|publicAccess|acl:\s*['\"]public-read|BlockPublicAcls|getPublicUrl|createSignedUrl|createSignedUploadUrl|signedUrlExpires|allUsers"
cat storage.rules 2>/dev/null; ls supabase/migrations 2>/dev/null | head
git grep -nIE "storage\.(objects|buckets)|CREATE POLICY.*storage" -- '*.sql'
```
Optional, only with an operator-supplied deployed URL: `curl -sS -o /dev/null -w '%{http_code}\n' https://<domain>/.env https://<domain>/.git/HEAD` — expect 404.

**Verdicts:** PASS — nothing sensitive under the served root, ignore files exclude env/VCS/dumps, source maps not published (or published deliberately and noted), and buckets default to private with signed URLs for private objects. FAIL — a `.env`, DB dump, backup archive, private key, or `.git` directory inside the served/public path, or a bucket holding user data readable by `allUsers`/anonymous. WARN — public source maps on a closed-source app, an unignored large artifact directory, or a bucket that is private but whose signed URLs never expire. N-A — no public directory and no object storage: state it.

**Fix:** Move non-public files out of `public/`, add them to `.gitignore` and the platform ignore file, disable production source maps (or accept and document), and make buckets private with short-lived signed URLs plus storage RLS policies.

**Judgment:** Read the actual bucket policy or `storage.rules` — "we use Supabase Storage" says nothing about access. A public bucket serving user uploads from the app origin also reopens check 16's stored-XSS path.

### 25. [+] Kill debug leakage in prod

**Means:** Error responses carry no stack traces, ORM messages, or raw exception text; framework debug mode is off in production; logs don't print secrets.

**Detect:**
```bash
git grep -nIE "err(or)?\.(message|stack)|String\(e(rror)?\)|JSON\.stringify\(err|e\.args|traceback\.format_exc|repr\(e\)" -- 'app/api/**' 'pages/api/**' 'src/routes/**' 'server/**'
git grep -nIE "NextResponse\.json\(\{\s*(error|message):\s*(err|e|error)\.|res\.status\(500\)\.json\(|jsonify\(\{.*str\(e\)"
git grep -nIE "DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true|debug=True|app\.run\(.*debug|FLASK_DEBUG|FLASK_ENV\s*=\s*development|NODE_ENV\s*=\s*['\"]?development|reloadOnChange"
git grep -nIE "console\.(log|debug|info|error)\([^)]*(token|secret|apiKey|api_key|password|session|authorization|credential)"
git grep -nIE "logger?\.(info|debug)\(.*(req\.headers|req\.body|request\.headers)"
git grep -nIE "PrismaClientKnownRequestError|error\.code|detail:|hint:" -- 'app/api/**'   # ORM detail passthrough
```
Python: `git grep -nE "traceback\.format_exc|repr\(e\)|str\(e\)|detail=f[\"']|HTTPException\(.*detail=(str|repr)\(" -- '*.py'` — `detail=f"…{e}"` is the FastAPI shape of the stack-trace leak (it lands in the JSON response, not the log); `DEBUG = True`, `app.run(debug=True)`, and `--reload` in the prod start command are the Flask/Django/uvicorn shapes.

**Verdicts:** PASS — handlers return a generic message plus a correlation id and log the detail server-side; debug flags are false/absent in prod config; no secret-bearing log line. FAIL — raw `err.message`/stack in an HTTP response, `DEBUG = True` in production settings, or a log statement printing a token, password, or `Authorization` header. WARN — errors generic on most routes but one path echoes an ORM/validation detail (schema and column names leak), or debug mode is env-gated but defaults to on.

**Fix:** Add a single error boundary that logs the exception with a request id and returns `{ error: 'Internal error', requestId }`; force debug off in production config; redact `authorization`, `cookie`, and `set-cookie` in the logger.

**Judgment:** Validation errors are a nuance — echoing zod field errors is usually fine and good UX; echoing database constraint or Prisma error text is not. Judge per response.

---

## Group 7 — AI layer (conditional)

### 33. [+] Secure the AI layer

**Means:** Model output is untrusted input; tool/function permissions are minimal; system prompts hold no secrets and are assumed extractable; prompt-injection is considered wherever the model reads third-party content; spend is capped per user.

**Detect:**
```bash
# does an AI layer exist at all? (corroboration only — the Phase 0 inventory is the gate; see the N-A clause)
git grep -lnIE "openai|@anthropic-ai|@ai-sdk|generateText|streamText|generateObject|ChatCompletion|messages\.create|langchain|llamaindex|@google/generative-ai|groq|bedrock|ollama|elevenlabs|convai|cohere|mistral|together|fireworks|vertexai|azure\.openai|huggingface|transformers|litellm|instructor|openrouter|deepseek|xai\b|grok"
# realtime/voice sessions often import no model SDK at all — the model is on the far end of a socket
git grep -nIE "wss?://[^\"'\` ]*(conversation|realtime|convai)"
# model output reaching dangerous sinks
git grep -nIE "dangerouslySetInnerHTML|innerHTML|\{@html|v-html" -- 'app/**' 'src/**' 'components/**' | grep -iE "message|completion|content|answer|response|output|assistant|markdown"
git grep -nIE "eval\(|new Function\(|child_process|execSync|exec\(|spawn\(|subprocess|os\.system|vm\.runIn"
git grep -nIE "\$queryRawUnsafe|\.query\(`|execute\(f[\"']" -- 'app/**' 'server/**' 'agents/**' 'tools/**'
# tool surface and validation
git grep -nIE "tools:\s*[\{\[]|tool\(\{|function_call|toolChoice|@tool|StructuredTool|inputSchema|parameters:\s*z\."
git grep -nIE "writeFile|unlink|rm -rf|fetch\(|sendEmail|stripe\.|prisma\.[a-z]+\.(update|delete)" -- 'tools/**' 'agents/**' 'lib/ai/**'
# prompts, injection surface, caps
git grep -nIE "system(Prompt)?:\s*[\`'\"]|SYSTEM_PROMPT|instructions:" 
git grep -nIE "scrape|crawl|readUrl|fetchPage|pdf-parse|mammoth|extractText|attachment|email\.body|webSearch|browse" -- 'app/**' 'src/**' 'server/**' 'lib/**'
git grep -nIE "maxTokens|max_tokens|maxSteps|maxToolRoundtrips|quota|credits|usage_?limit|budget"
```

**Verdicts:** PASS — model output rendered as text or sanitized before HTML, never reaching eval/exec/shell/SQL; tool arguments validated with the same rigor as user input and tools scoped to the caller's own data; system prompt free of credentials; third-party content clearly delimited as untrusted with a stated injection posture; per-user token/spend caps enforced. FAIL — model output interpolated into HTML, a shell command, or raw SQL; a tool that can act outside the caller's scope (arbitrary DB write, arbitrary fetch, send-as-user) without confirmation; a secret or private URL embedded in a system prompt. WARN — output handled safely but a model-reachable tool is unvalidated or over-broad, or the app ingests third-party content (web pages, uploaded docs, emails) with no injection consideration, or `maxSteps`/`maxTokens` unbounded. N-A — **may be declared ONLY when the Phase 0 stack inventory also found no AI usage.** The grep above is corroboration, never the gate: if Phase 0 identified an AI layer — a model SDK in the manifest, a voice/realtime provider, an agent loop, a prompt template, a `wss://` model session — then an empty grep result is **irrelevant**, and means only that the pattern list is blind to this stack. Widen it, or read the code, and verdict the check on what the code actually does. When declaring N-A, cite the inventory line you relied on, not the grep.

**Fix:** Treat every model token like a request body — validate tool arguments against a schema, scope tool queries to the session subject, render output as text (sanitize if HTML is required), and never let output reach `eval`/shell/raw SQL. Keep secrets out of prompts, bound `maxSteps` and `maxTokens`, and meter spend per user.

**Judgment:** The load-bearing question is: *what can the model cause to happen, and who controls the text it reads?* Enumerate the tools and, for each, name the worst outcome if an attacker wrote the arguments — that is the finding, not the prompt wording. Assume the system prompt is public: if its leakage matters, that is itself the vulnerability. Cross-ref check 28 for denial-of-wallet and check 31 for model-driven fetches.

---

## Group 8 — Supply chain & ops

### 20. Scan dependencies

**Means:** Production dependencies carry no known critical/high vulnerabilities, the lockfile is committed, and security-relevant packages are not badly stale.

**Detect:**
```bash
git ls-files | grep -E "package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|uv\.lock|poetry\.lock|requirements\.txt|Cargo\.lock|Gemfile\.lock|go\.sum"
# EVERY auditor below: only if the tool is ALREADY installed — never install one, never mutate the project.
# Each line is gated on its own manifest existing; a missing manifest means that ecosystem is absent, not that the check failed.
[ -f package-lock.json ] && command -v npm && { npm audit --omit=dev --package-lock-only --json > "${TMPDIR:-/tmp}/audit.json"; npm audit --omit=dev; npm outdated --long | head -40; }
[ -f pnpm-lock.yaml ] && command -v pnpm && pnpm audit --prod
[ -f yarn.lock ] && command -v yarn && yarn npm audit --environment production
# lockfile-native and ecosystem-agnostic — the preferred path when present (reads the lockfile, installs nothing)
command -v osv-scanner && for l in uv.lock poetry.lock package-lock.json pnpm-lock.yaml Cargo.lock Gemfile.lock go.sum; do [ -f "$l" ] && osv-scanner --lockfile "$l"; done
```
Python / Rust / Ruby / Go — each conditional on its own manifest, none of them mutating the project:
```bash
{ [ -f pyproject.toml ] || [ -f uv.lock ] || [ -f requirements.txt ]; } && command -v uvx && uvx pip-audit   # ephemeral venv: audits WITHOUT adding a dep to the project (prefer over `uv run pip-audit`, which mutates it)
[ -f uv.lock ] && command -v uvx && uvx pip-audit --locked
[ -f requirements.txt ] && command -v pip-audit && pip-audit -r requirements.txt
{ [ -f pyproject.toml ] || [ -f poetry.lock ]; } && command -v pip-audit && pip-audit   # NEVER assume requirements.txt exists — uv/poetry/PEP-621 projects have none
[ -f Cargo.lock ] && command -v cargo-audit && cargo audit
[ -f Gemfile.lock ] && command -v bundler-audit && bundler-audit check
[ -f go.sum ] && command -v govulncheck && govulncheck ./...
```
**Staleness fallback when no auditor can run** (offline, or none installed): read the *resolved* versions straight out of the lockfile — not the manifest's ranges — and compare the security-relevant packages by hand against their known-bad floors.
```bash
grep -nE '^(name|version) = ' uv.lock 2>/dev/null | paste - - | grep -iE "fastapi|starlette|uvicorn|jinja2|requests|urllib3|cryptography|pillow|aiohttp|python-multipart|python-jose|pyjwt"
git grep -nE '"(next|express|sharp|jsonwebtoken|axios|ws|undici)":' -- package.json package-lock.json
```
Report that as **WARN** with the versions found plus `verify manually: no auditor available — advisories unchecked`. **Never a silent PASS.**

**Verdicts:** PASS — no critical/high advisories in production dependencies, lockfile committed, security-relevant packages within a supported major. FAIL — any critical or high advisory affecting a production dependency, or no lockfile committed (non-reproducible installs). WARN — critical/high only in dev dependencies, advisories with no fix available (state the exposure and whether the vulnerable path is reachable), or a security-relevant dep several majors behind (`next`, `express`, `sharp`, `jsonwebtoken`, `axios`, `Pillow`, `django`). N-A — no third-party dependencies: state it.

**Fix:** Upgrade the affected packages (or the framework major that carries the fix); where no patch exists, note reachability and pin plus monitor; commit the lockfile and enable Dependabot/Renovate.

**Judgment:** `npm audit` needs network and is advisory-count-noisy — judge by reachability, not count. `--package-lock-only` keeps it read-only (no install). Give framework CVEs (Next.js middleware bypass class, `jsonwebtoken` verification bugs) priority over transitive dev-only noise. If the auditor cannot run (no network, no lockfile, tool not installed), report WARN with the reason rather than a silent PASS. **Never install an auditor to satisfy this check** — an audit that mutates the repo it is auditing has broken its own first rule; `uvx pip-audit` and `osv-scanner` against an existing lockfile are the read-only paths, and a hand-read lockfile is the last resort.

### 32. [+] Log & alert on security events

**Means:** Authentication successes and failures, authorization denials, and rate-limit trips are logged with actor and timestamp; some alerting path exists. Inversely, logs never capture credentials or full PII.

**Detect:**
```bash
git grep -niE "logger\.|pino|winston|structlog|logging\.getLogger|@sentry|Sentry\.|datadog|dd-trace|axiom|logtail|betterstack|highlight\.run|posthog\.capture|newrelic"
git grep -niE "login (failed|success)|auth(entication)? (failure|success)|invalid credentials.*log|permission denied|forbidden.*log|rate limit exceeded|audit_?log|security_?event|AuditLog"
# are denials actually logged? list every 401/403 raise with context; a hit with no log/audit/capture line nearby is a SILENT denial
git grep -nE -B3 -A3 "HTTP_401_UNAUTHORIZED|HTTP_403_FORBIDDEN|HTTPException\(status_code=(401|403)|status\(40[13]\)|sendStatus\(40[13]\)|NextResponse\.json\([^)]*\{ *status: *40[13]" | grep -viE "log|audit|capture|sentry|track"
ls .github/workflows/ 2>/dev/null; grep -nirE "sentry|logdrain|alert|pagerduty|uptime" .github/ vercel.json 2>/dev/null
# INVERSE: secrets and PII in logs
git grep -nIE "log(ger)?\.(info|warn|error|debug)\([^)]*(password|passwd|token|secret|api_?key|authorization|cookie|ssn|card)"
git grep -nIE "console\.log\((req|request)\b|logger\.info\(.*req\.(body|headers)|print\(request\."
git grep -nIE "beforeSend|redact|scrubFields|sanitizeKeys|sendDefaultPii"
```

**Verdicts:** PASS — security-relevant events logged with actor identifier and timestamp through a structured logger, shipped somewhere durable (Sentry/log drain/hosted logs), and the logger redacts credential fields. FAIL — no logging of auth failures or permission denials at all (a breach would be invisible), or logs that write passwords, tokens, or `Authorization` headers. WARN — application logging exists but only to stdout with no retention or alert path, or an error tracker is wired with `sendDefaultPii` enabled / no redaction configured.

**Fix:** Emit structured events (`auth.login.failed`, `authz.denied`, `ratelimit.tripped`) with user id, IP, and timestamp; ship to a retained sink with an alert on failure spikes; configure logger redaction for `password`, `token`, `authorization`, `cookie`.

**Judgment:** The inverse half is the one that bites — Sentry with `sendDefaultPii` or a request-dump log line puts session cookies into a third-party system. Check the tracker's `beforeSend`/redaction config, not just its presence.

### 34. [+] Verify backups & rollback

**Means:** Database backups are enabled and restorable, and there is a tested or at least documented path to roll back a bad deploy.

**Detect:**
```bash
git grep -niE "pg_dump|pg_restore|backup|pitr|point-in-time|snapshot|litestream|wal-g|barman|restore|disaster"
find . -maxdepth 3 \( -iname 'RUNBOOK*' -o -iname 'OPERATIONS*' -o -iname 'DISASTER*' -o -iname 'DEPLOY*.md' -o -iname 'ROLLBACK*' \) -not -path '*/node_modules/*' 2>/dev/null
ls docs/ 2>/dev/null | grep -iE "backup|restore|runbook|ops|incident"
ls .github/workflows/ 2>/dev/null; grep -nirE "rollback|promote|revert|alias|--prod|previous" .github/workflows/ vercel.json fly.toml 2>/dev/null
git grep -niE "migrate deploy|migrate:down|alembic downgrade|migration.*rollback|prisma migrate resolve"
```
Operator-supplied evidence (ask; never log in): managed-provider backup plan and retention — Supabase daily backups / PITR add-on tier, Neon history retention window, RDS automated-backup + PITR settings.

**Verdicts:** PASS — backups enabled with a known retention/PITR window confirmed against the provider plan, a restore that has been performed or is documented step-by-step, and a one-action deploy rollback (promote previous deployment / revert tag). WARN — backups exist by provider default but retention is unverified, restore has never been exercised, or rollback exists for code but migrations are forward-only with no down path. FAIL — no backups at all (free-tier database with no snapshots), or destructive migrations with neither backup nor rollback. N-A — no persistent data store: state it.

**Fix:** Confirm the provider's backup tier actually covers the needed RPO (many free tiers do not) and enable PITR if not; document and once rehearse the restore; keep the previous deployment promotable and write reversible migrations (expand-then-contract).

**Judgment:** Do not infer backups from the provider's name — the plan tier decides whether they exist. Ask the operator for the setting rather than assuming. WARN rather than FAIL when partially present: this is launch-blocking ops hygiene, not an exploitable vulnerability, and it should be reported as such.

---

## Severity ordering

Report FAILs in this order, most urgent first:

1. **Group 1 & 2** — secrets and authorization. An exposed credential or a missing ownership check is exploitable now, by anyone, with no prerequisites, and the damage (full data exfiltration) is unbounded and often silent. Fix before launch, always.
2. **Group 3 & 4** — auth, sessions, account flows, abuse and request forgery. Account takeover and cost/abuse exposure: exploitable, but usually needs a target or a campaign.
3. **Group 5 & 6** — input handling, API surface, transport. Injection and leakage: high impact when reachable, but often gated behind a specific surface or a user interaction.
4. **Group 7 & 8** — AI layer, supply chain, ops. Real risk, generally requiring a further condition (a vulnerable path actually reachable, a malicious document, an incident already in progress).

Within a tier, order by blast radius: full-database access > single-account takeover > single-record disclosure. Report every WARN after the FAILs, and list N-A verdicts last with their reasons so the operator can confirm you assessed the surface rather than skipped it.
