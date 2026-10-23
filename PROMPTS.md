# PROMPTS.md

## Project: Strongroom: Every Door Logged

I used Antigravity (AI coding assistant) to generate code in small steps. I reviewed the changes, ran the tests myself, and recorded the problems I found below.

## 1. Reusable project instructions

`AGENTS.md` holds the security rules the assistant had to follow on every task: every document route calls `authorize()`, default deny, identity only from the server-side session, append-only audit log, encrypted files outside the web root, and a test for every security rule.

## 2. Mistakes found in AI-generated code

### Entry 1: Database path read too early (testing)
- **What went wrong:** The generated code read `DB_PATH` when the module loaded, so tests could not point at an isolated temporary database.
- **Fix:** Changed it to read the path lazily (commit `c28b777`, `src/db.ts` and `src/server.ts`).
- **Evidence:** `npm test` passes: 154 tests, 3 files.

### Entry 2: UI missing from the deployed image (deployment)
- **What went wrong:** The Docker runtime image did not include the `public/` folder, so the deployed container had no UI files.
- **Fix:** Added `COPY public ./public` to the runtime stage (commit `f48c59e`).
- **Evidence:** The live site now loads at https://strongroom-buas.onrender.com

### Entry 3: Login lockout matching (authentication)
- **What went wrong:** The per-email lockout counts failed logins stored in the audit log. It needed exact matching; a pattern match (`LIKE`) lets wildcard characters in an email interfere with the count.
- **Fix:** The query now uses exact `json_extract(detail_json, '$.email') = ?` equality, and emails are trimmed and lowercased first (`src/routes/auth.routes.ts`).
- **Evidence:** No automated test yet for the lockout. Listed as "test missing" in `THREATS.md`.

### Entry 4: Vulnerable dependency (supply chain)
- **What went wrong:** The generated `package.json` used `uuid@^9`, which `npm audit` flagged as moderate (GHSA-w5hq-g745-h8pq).
- **Fix:** I did not run `npm audit fix --force` (it would jump to a breaking major version). I installed `uuid@^11.1.1`, the patched version (commit `46dfbfb`).
- **Evidence:** Build passes, 154 tests pass, `npm audit --omit=dev` reports 0 vulnerabilities.

## 3. Verification

- **Tests:** `npm test` gives 154 passed (authorisation matrix, auth, documents).
- **Build:** `npm run build` succeeds.
- **Live site:** https://strongroom-buas.onrender.com (`/health` returns `{"status":"ok"}`).

## 4. Known limitations

See `THREATS.md` for the full list of closed and accepted risks.