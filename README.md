# Strongroom

> Every door guarded. Every opening logged.

A secure document-sharing platform where the wrong person cannot reach a file, and every access (including refused attempts) is written to a tamper-evident ledger.

**Live demo:** https://strongroom-buas.onrender.com
**Repo:** https://github.com/Kruthi-chowdary/Strongroom
**Also read:** [THREATS.md](THREATS.md) (threats, tests, accepted risks) and [PROMPTS.md](PROMPTS.md) (how AI was used and where it was wrong)

> The demo runs on Render's free tier: it sleeps after ~15 min idle (first load can take 30-60 s) and its disk is ephemeral, so the database resets and **reseeds on every restart**. Demo data only.

## Demo accounts (public demo data only)

| Role | Email | Password |
|---|---|---|
| Admin | admin@strongroom.local | Admin$ecret1! |
| Owner | owner1@strongroom.local | Owner$ecret1! |
| Owner | owner2@strongroom.local | Owner$ecret2! |
| Viewer | viewer1@strongroom.local | Viewer$ecret1! |
| Viewer | viewer2@strongroom.local | Viewer$ecret2! |
| Viewer | viewer3@strongroom.local | Viewer$ecret3! |

The login page has one-click buttons that fill these in.

## What to try (2 minutes)

1. Log in as **Owner 1**, open "Upload a document", and upload a small .txt file.
2. Click **Share & custody**, grant it to Viewer 1 (read), then log in as Viewer 1 in another window and download it.
3. As Owner 1, click **Revoke**. Viewer 1's next download is refused immediately.
4. In the **Chain of custody** timeline, see the allowed (✓) and refused (✗) attempts.
5. Log in as **Admin**: open the Security console, then click **Verify ledger** to recompute the hash chain. Note the admin sees no document contents.
6. Use the **Light / Dark / System** switch in the top bar.

## Roles (written down)

| Role | Can do | Cannot do |
|---|---|---|
| **Admin** | View audit log, verify ledger, see tripwires, list users | Read, download, edit, delete or share any document content. Not even by grant (grants to admins are refused). |
| **Owner** | Upload; read/download/edit/delete/share own documents; grant and revoke access; see chain of custody of own documents | Touch other owners' documents unless granted |
| **Viewer** | Read/download documents granted to them (read or edit permission) | Upload, share, or see anything not granted |

## Permission model (in my own words)

**Per-document grants only.** A document has one owner. The owner may grant another (non-admin) user `read` or `edit`, optionally with an expiry, and may revoke at any time. There are no folders and no groups. I chose this deliberately: a smaller model that holds beats a bigger one with a hole in it, and "someone given a folder can now see forty files" cannot happen when there are no folders.

**One chokepoint.** Every route that touches a document calls `authorize(db, actor, docId, action, ctx)` in `src/auth/authorize.ts`. It is default-deny, re-reads the user (disabled flag and **role**), the document and the grants from the database on every call (no caching), and writes an audit row for every decision, ALLOWED or DENIED. The caller only learns `{ allowed }`, never why.

**Refusals look like "not found".** Unknown, deleted and not-granted documents all return the same `404 {"error":"not found"}`.

**Instant revocation.** Sessions are server-side rows (a revoked or disabled user is refused on the very next request). Downloads use single-use 60-second tickets, and `authorize()` runs again when the ticket is redeemed, so a grant revoked between issue and use is refused.

## Audit trail

Every row stores `hash = sha256(prev_hash + JSON of every column)`. SQLite triggers abort any `UPDATE` or `DELETE` on `audit_log`. `GET /api/admin/audit/verify` recomputes the whole chain and returns the first broken row; the admin screen's **Verify ledger** button animates it. If someone drops the triggers and edits a row, verification still detects it (tested). Refused attempts are logged too.

## Interface

Plain HTML, CSS and JavaScript (no framework) served by the same Express app. All text is set with `textContent`, never `innerHTML`, so file names cannot inject script. Includes a custody timeline with icons (not colour alone), stat tiles, a Security console for admins, a collapsible upload card, and a Light / Dark / System theme switch that remembers your choice.

## What I deliberately did not build

- Folders, groups and inheritance (see above)
- External (outside-company) sharing
- Document versions, delete, edit and recovery screens (`edit` and `delete` exist in `authorize()` but no routes use them yet)
- Retention policy
- AI access suggestions (the safe design is documented in THREATS.md, but it is not built)
- Off-hours download and external-domain grant tripwires
- Horizontal scaling: tickets live in memory and SQLite is a single node

## Run it locally (from a clean clone)

Requires Node 22+.

```bash
git clone https://github.com/Kruthi-chowdary/Strongroom.git
cd Strongroom
npm ci
npm test            # 154 tests
npm run build
```

Start it (PowerShell):

```powershell
$env:FILE_ENCRYPTION_KEY = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
$env:SEED_DEMO = 'true'
npm start
```

Bash:

```bash
export FILE_ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
export SEED_DEMO=true
npm start
```

Open http://localhost:3000.

### Environment variables

| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Required in production |
| `FILE_ENCRYPTION_KEY` | 64 hex chars; AES-256-GCM key for files at rest |
| `SEED_DEMO` | `true` seeds demo users and documents when the users table is empty |
| `DB_PATH` | SQLite file (default `./strongroom.db`) |
| `STORAGE_DIR` | Encrypted file folder (default `./storage`) |
| `PORT` | Default 3000 |

## Deploy (Render)

New Web Service, connect the repo, runtime **Docker**, Free plan, health check path `/health`, set `SESSION_SECRET`, `FILE_ENCRYPTION_KEY`, `SEED_DEMO=true`. The Dockerfile uses Node 22 (required by `better-sqlite3@13`), runs as a non-root user, and installs only production dependencies in the runtime image.

## Database

Schema: `src/schema.sql` (users, sessions, documents, grants, audit_log, plus the append-only triggers). It is applied idempotently on every start by `src/db.ts`. Seeding: `src/seed.ts`.

## API (who may call what)

All state-changing calls need the header `X-Requested-With: strongroom` and a session cookie. "Refused" means `404 {"error":"not found"}` unless noted. Every document route is gated by `authorize()`.

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /health` | Anyone | Liveness |
| `POST /api/auth/login` | Anyone | Same error for unknown email, wrong password, disabled user, lockout. 10 failures / 15 min per IP; 5 failures / 15 min per email |
| `POST /api/auth/logout` | Anyone with a session | Revokes the session |
| `GET /api/auth/me` | Any logged-in user | |
| `POST /api/documents` | Owner | Multipart upload; validated and encrypted; owner = session user |
| `GET /api/documents?q=&category=` | Any logged-in user | Returns only own + granted documents (auth inside the SQL). Admin always gets an empty list |
| `POST /api/documents/:id/download-ticket` | Owner, or user with read/edit grant | `authorize('download')`; refused otherwise |
| `GET /api/download/:ticket` | The user the ticket was issued to | Single use, 60 s; `authorize('download')` runs again |
| `POST /api/documents/:id/grants` | Document owner only | `authorize('share')`; never to admins or self |
| `DELETE /api/documents/:id/grants/:grantId` | Document owner only | Takes effect immediately |
| `GET /api/documents/:id/grants` | Document owner only | Active grants |
| `GET /api/documents/:id/custody` | Document owner only | Chain of custody |
| `GET /api/users` | Owner, Admin | Owners see enabled non-admins; admin sees all |
| `GET /api/admin/audit` | Admin | Filters: action, outcome, limit |
| `GET /api/admin/audit/verify` | Admin | Recomputes the hash chain |
| `GET /api/admin/notable` | Admin | Tripwires |

## Tests

`npm test` runs 154 tests: the full role x grant-state x action matrix for `authorize()`, auth/session/CSRF tests (login, logout, disabled user, revoked session, token not stored raw, enumeration), and isolation tests (IDOR, search leakage, ticket replay, revoke between issue and redeem, admin overreach, malicious uploads, audit tampering). I also removed individual checks on purpose: deleting `authorize()` from ticket issue fails 4 tests, deleting it from ticket redemption fails 1.

**Not covered by automated tests yet:** login lockout and rate limiting, session fixation, the production `Secure` cookie flag, and file encryption at rest. These are listed in THREATS.md as "test missing".

## AI use

See `PROMPTS.md` for the context file reused all week (`AGENTS.md`) and the specific places the AI was wrong.

## What is unfinished

No document delete/edit/version routes, no external sharing, tripwires are basic, tickets are in memory, the work was compressed into a few days rather than spread over the week (see commit history), and the Antigravity quota ran out twice, so part of the code was written in a chat assistant and pasted in by me after review.