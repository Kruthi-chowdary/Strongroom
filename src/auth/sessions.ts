/**
 * sessions.ts – server-side session management (Rule 4).
 *
 * Security decisions:
 * - The raw token NEVER touches the database. Only sha256(token) is stored so
 *   a DB dump cannot be used to hijack sessions (Rule 4 / Rule 6).
 * - loadActor re-queries on every call; no caching so revocations are instant.
 * - Sessions expire after 8 hours and may be revoked individually or in bulk.
 * - Identity (id, role) comes from the DB join, never from the cookie (Rule 3).
 */

import crypto from 'crypto';
import type Database from 'better-sqlite3';
import type { Actor } from './authorize';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** SHA-256 hex of the raw token – only this is stored in the DB. */
function hashToken(raw: string): string {
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

/** ISO timestamp offset from now by `ms` milliseconds. */
function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// ---------------------------------------------------------------------------
// DB row shapes (internal)
// ---------------------------------------------------------------------------

interface SessionUserRow {
  user_id:  string;
  role:     'admin' | 'owner' | 'viewer';
  revoked:  number;
  expires_at: string;
  disabled: number;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a new session for `userId`.
 * Generates a 32-byte cryptographically random token, stores ONLY its
 * SHA-256 hash as the session id, and returns the **raw** token to the
 * caller (who sets it as the cookie value).
 *
 * @returns The raw (unhashed) token string – treat as a secret.
 */
export function createSession(db: Database.Database, userId: string): string {
  const raw       = crypto.randomBytes(32).toString('hex');
  const hashed    = hashToken(raw);
  const expiresAt = isoOffset(SESSION_TTL_MS);

  // IMMEDIATE transaction: write lock before insert to avoid race conditions.
  const insert = db.transaction(() => {
    db.prepare<[string, string, string]>(
      'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)'
    ).run(hashed, userId, expiresAt);
  });
  insert.immediate();

  return raw; // caller sets this as the cookie value; never stored raw (Rule 4)
}

/**
 * Resolve a raw cookie token to an Actor.
 * Re-queries the DB on every call – no caching (Rule 3 / Rule 4).
 * Returns null if the session is missing, revoked, expired, or the user
 * is disabled – callers cannot distinguish between these cases (Rule 2).
 */
export function loadActor(
  db: Database.Database,
  rawToken: string
): Actor | null {
  if (!rawToken) return null;

  const hashed = hashToken(rawToken);

  const row = db
    .prepare<[string], SessionUserRow>(`
      SELECT s.user_id, u.role, s.revoked, s.expires_at, u.disabled
      FROM   sessions s
      JOIN   users    u ON u.id = s.user_id
      WHERE  s.id = ?
    `)
    .get(hashed);

  if (!row)                          return null; // unknown token
  if (row.revoked === 1)             return null; // revoked (Rule 4)
  if (row.expires_at < new Date().toISOString()) return null; // expired
  if (row.disabled === 1)            return null; // account locked (Rule 3)

  return { id: row.user_id, role: row.role };
}

/**
 * Revoke a single session identified by its raw token.
 * Used on logout.
 */
export function revokeSession(db: Database.Database, rawToken: string): void {
  const hashed = hashToken(rawToken);
  db.prepare<[string]>(
    'UPDATE sessions SET revoked = 1 WHERE id = ?'
  ).run(hashed);
}

/**
 * Revoke ALL active sessions for a user.
 * Used when an account is disabled or a password is changed so existing
 * sessions cannot be used after revocation (Rule 4 – instant revocation).
 */
export function revokeAllSessionsForUser(
  db: Database.Database,
  userId: string
): void {
  db.prepare<[string]>(
    'UPDATE sessions SET revoked = 1 WHERE user_id = ?'
  ).run(userId);
}
