# PROMPTS.md

## Project: Strongroom: Every Door Logged

I used Antigravity (AI coding agent) to generate the backend in small steps, and a chat assistant (Claude) for security review, documentation and the UI polish. I reviewed the changes, ran the tests myself, and recorded the problems I found below. The commit history is short because I had to finish early for another event.

## 1. Reusable project instructions

`AGENTS.md` holds the security rules the assistant had to follow on every task: every document route calls `authorize()`, default deny, identity only from the server-side session, append-only audit log, encrypted files outside the web root, and a test for every security rule.

## 2. Mistakes found

### Entry 1: Database path read too early (testing)
- **What went wrong:** The generated code read `DB_PATH` when the module loaded, so tests could not point at an isolated temporary database.
- **Fix:** Changed it to read the path lazily (commit `c28b777`, `src/db.ts` and `src/server.ts`).
- **Evidence:** `npm test` passes: 154 tests, 3 files.

### Entry 2: UI missing from the deployed image (deployment)
- **What went wrong:** The Docker runtime image did not include the `public/` folder, so the deployed container had no UI files.
- **Fix:** Added `COPY public ./public` to the runtime stage (commit `f48c59e`).
- **Evidence:** The live site now loads at https://strongroom-buas.onrender.com

### Entry 3: Login lockout matching (authentication, uses the audit log)
- **What went wrong:** The per-email lockout counts failed logins stored in the audit log. It needed exact matching; a pattern match (`LIKE`) lets wildcard characters in an email interfere with the count.
- **Fix:** The query now uses exact `json_extract(detail_json, '$.email') = ?` equality, and emails are trimmed and lowercased first (`src/routes/auth.routes.ts`).
- **Evidence:** No automated test yet for the lockout. Listed as "test missing" in `THREATS.md`.

### Entry 4: Vulnerable dependency (supply chain)
- **What went wrong:** The generated `package.json` used `uuid@^9`, which `npm audit` flagged as moderate (GHSA-w5hq-g745-h8pq). The suggested fix, `npm audit fix --force`, would have jumped to a breaking major version.
- **Fix:** I did not run it. I installed `uuid@^11.1.1`, the patched version (commit `46dfbfb`).
- **Evidence:** Build passes, 154 tests pass, `npm audit --omit=dev` reports 0 vulnerabilities. Five remaining findings are dev-only tooling that is not in the Docker image.

### Entry 5: Read-only panels write noisy audit rows (audit)
- **What went wrong:** The routes that only list a document's grants and chain of custody call `authorize()` with the `share` action. So just opening the Share panel writes `share` rows into the audit log, which clutters the chain of custody with entries that are not real sharing events.
- **Fix:** Not fixed. I decided it was not a security weakness (the log is still complete and correct), and recorded it as an accepted risk in `THREATS.md`. A cleaner design would use a separate read-only action for these panels.
- **Evidence:** Documented in `THREATS.md` under "Noisy audit rows".

### Entry 6: Duplicated user name in the header (UI)
- **What went wrong:** When adding the theme switcher, the user name and role badge ended up rendered twice in the top bar.
- **Fix:** Removed the duplicated line in `shell()` in `public/app.js`; the header now renders the name and badge once.
- **Evidence:** Seen in a screenshot, fixed and checked by reloading the page.

### Entry 7: Documentation claimed tests that do not exist (docs)
- **What went wrong:** A draft of the README said the test suite includes "lockout" tests. A search of the tests folder showed there are none, which contradicts `THREATS.md`.
- **Fix:** Corrected the README to list lockout, rate limiting, session fixation, the production `Secure` flag and encryption-at-rest as not yet covered by tests.
- **Evidence:** `Get-ChildItem tests | Select-String 'locked.out|rate.limit'` found no matches.

## 3. Process note

Two secret values were pasted into a chat assistant during development. I rotated both, and the keys now live only in Render environment variables (`.env` is git-ignored).

## 4. Verification

- **Tests:** `npm test` gives 154 passed (authorisation matrix, auth, documents).
- **Build:** `npm run build` succeeds.
- **Dependencies:** `npm audit --omit=dev` reports 0 vulnerabilities.
- **Live site:** https://strongroom-buas.onrender.com (`/health` returns `{"status":"ok"}`).

## 5. Known limitations

See `THREATS.md` for the full list of closed and accepted risks.