# THREATS.md

How I think Strongroom could be broken, what I did, and what I knowingly left open. Test names refer to `tests/*.test.ts`.

## Closed

| Threat | What I did | Test | Status |
|---|---|---|---|
| **IDOR**: guess another document's id | Every document route calls `authorize()`; ids must be UUID-shaped; refusal is an identical 404 and a DENIED audit row | `viewer with no grant cannot get a ticket`, `another owner cannot ticket, grant or read custody of it` | closed |
| **Admin overreach** | Admin may only `view_audit`. Document list returns empty for admin; grants to admins are refused | `admin1 / ... ` matrix (30 cases), `admin cannot list or download contents` | closed |
| **Forged or stale role** | `authorize()` re-reads the role from the DB, ignoring the caller's value | `FORGED ROLE: viewer claiming admin...` | closed |
| **Revoked but still has link** | Grants re-read on every call; tickets are single use, 60 s, bound to user + document, and `authorize()` runs again at redemption | `grant works, ticket is single-use, revoke between issue and redeem is refused` | closed |
| **Ticket replay / theft by another user** | Ticket deleted on first lookup; must be redeemed by the same logged-in user | `a ticket cannot be redeemed by a different user` (replay is in the revoke test) | closed |
| **Disabled user keeps access** | Sessions and `authorize()` both check `users.disabled` on every request | `disabled owner is denied`, `auth.test.ts` disabled-session test | closed |
| **Search leakage** | Authorisation is inside the SQL join, not a post-filter; `%` and `_` are escaped; no totals returned | `viewer search returns none of owner1 docs...`, `LIKE wildcard % does not widen search` | closed |
| **Audit tampering** | Hash chain over every column; triggers abort UPDATE and DELETE; verify detects dropped triggers and edited rows, and missing rows via id sequence | `UPDATE and DELETE on audit_log are blocked by triggers`, `if triggers are dropped, verify detects the edit`, `AUDIT: editing ip or detail_json breaks the hash` | closed |
| **Refusals not logged** | `authorize()` writes DENIED rows; failed uploads and logins are logged too | `AUDIT: every call writes exactly one row, DENIED included` | closed |
| **Brute force / credential stuffing** | 10 failures per IP and 5 per email in 15 min; email lowercased; lockout uses exact `json_extract` match, not `LIKE` | not covered by an automated test yet (fixed after review; see PROMPTS.md) | closed, **test missing** |
| **Account enumeration** | Same message and status for unknown email, wrong password, disabled user and lockout; bcrypt always runs against a real dummy hash | `auth.test.ts` identical-response test | closed |
| **Session theft after DB leak** | Only `sha256(token)` is stored; cookie is httpOnly, SameSite=Strict, Secure in production | `session token is not stored raw in the DB` | closed |
| **CSRF** | Cookies are SameSite=Strict, plus required `X-Requested-With` header and Origin check on state-changing methods | `csrfGuard rejects a POST without the header` | closed |
| **Session fixation** | Login revokes the user's older sessions and issues a new random token | none yet | closed, **test missing** |
| **Path traversal** | Files are stored under server-generated UUIDs; storage keys are validated against a UUID pattern; display names are sanitised | `traversal filename is sanitised, upload stores under uuid` | closed |
| **Malicious upload** | Extension allowlist, magic bytes must match, double extensions rejected, HTML/SVG/executables rejected, 5 MB cap, downloads are `attachment` + `nosniff` + `octet-stream` | `rejects .html, double extension, and content/extension mismatch` | closed |
| **Viewer uploads** | Upload route requires the owner role | `viewer cannot upload` | closed |
| **Stored XSS via file name** | UI never uses `innerHTML`; all text is set with `textContent`; Helmet CSP blocks inline script | manual check only | closed, **test missing** |
| **Files readable from disk** | AES-256-GCM per file; key only in an environment variable; integrity checked against stored sha256 on download | none | closed, **test missing** |
| **Secrets in the repo** | `.env` ignored; keys live only in Render environment variables. Two values were pasted into a chat during development, so both were rotated | n/a | closed |

## Knowingly accepted

| Threat | Why I left it | Status |
|---|---|---|
| **Someone with direct DB access rewrites the whole chain** | A hash chain proves internal consistency, not authorship. Mitigation not built: publish the head hash externally. The admin screen shows the current head so it can be recorded | accepted |
| **Ticket store is in memory** | Restart drops tickets (harmless, request again) and it cannot scale beyond one instance | accepted |
| **Ephemeral disk on the free tier** | Database and files reset on restart and reseed. Fine for a demo; a real deployment needs a persistent volume or Postgres plus object storage | accepted |
| **Single SQLite node** | No horizontal scaling | accepted |
| **User directory visible to owners** | Needed to pick who to share with. Only enabled non-admin users, names and emails | accepted |
| **Noisy audit rows** | Opening the Share panel writes `share` rows for the grants and custody lists. Not a security weakness, but it clutters the log | accepted |
| **Public demo passwords** | Required so judges can log in. Demo data only | accepted |
| **Dependency vulnerabilities** | `npm audit` reports 9 issues (mostly dev tooling). I did not run `audit fix --force`, which risks breaking the build. Needs triage | accepted |
| **No MFA, no password change or reset flow** | Out of scope for this week | accepted |
| **Tripwires are basic** | Repeated denials, attempts by disabled users, permission changes. Off-hours downloads and external-domain grants are not implemented | accepted |
| **`edit` and `delete` have no routes** | `authorize()` enforces them and the matrix tests them, but nothing calls them yet | accepted |
| **Timing differences between 404 causes** | Refusals all take a similar short path, but I did not measure it | accepted, unverified |
| **Rate limit keyed on proxy IP** | Behind Render the limiter depends on `trust proxy = 1` being correct | accepted, unverified |

## AI-in-product

Not built. The intended design: a suggestion endpoint that can only return suggestions, never writes a grant, with the owner confirming in a separate call and both events audited (SUGGESTION_MADE, GRANT_CONFIRMED_BY_HUMAN).