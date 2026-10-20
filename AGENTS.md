Project: Strongroom, a secure document-sharing platform. Security is graded above everything.
Rules you must follow in every change:
1. Every route that reads, downloads, edits, deletes, lists, searches or shares a document MUST call authorize(actor, docId, action) from src/auth/authorize.ts. Never inline permission checks elsewhere.
2. Default deny. Unknown, deleted, or not-granted documents return an identical 404 to the caller, and the refusal is written to the audit log.
3. Never trust role, userId or ownerId from the request body. Take identity from the server-side session only.
4. Sessions are server-side rows (httpOnly, SameSite=Strict cookie). No long-lived bearer tokens, so revocation is instant.
5. The audit log is append-only and hash-chained. Log DENIED attempts too. Never log secrets.
6. Files are stored outside the web root under random UUIDs, encrypted at rest. Never build file paths from user input.
7. Every security rule gets a test in /tests. Name tests after the threat in THREATS.md.
8. Keep code small, typed and commented where a security decision is made.
9. Never amend, rebase or force-push. Always make a new commit.