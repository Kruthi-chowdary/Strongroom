/**
 * auth.routes.ts – login, logout, and /me endpoints.
 *
 * Security decisions:
 * - Timing-safe: bcrypt.compare runs against a REAL dummy hash even for
 *   unknown emails, so response time is indistinguishable.
 * - Identical error "invalid credentials" for wrong password, unknown email,
 *   disabled user and locked-out email (no account enumeration).
 * - Email is trimmed and lowercased before lookup and lockout counting.
 * - Lockout uses json_extract equality, not LIKE (no wildcard bypass).
 * - Login revokes the user's older sessions (no session fixation).
 * - Passwords and tokens NEVER appear in detail_json (Rule 5).
 */

import { Router } from 'express';
import type { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';

import { getDb } from '../db';
import { appendAudit } from '../audit/audit';
import { createSession, revokeSession, revokeAllSessionsForUser } from '../auth/sessions';
import { requireAuth } from '../auth/middleware';

export const authRouter = Router();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// A REAL bcrypt hash (cost 12), generated once at startup, so unknown emails
// cost the same time as real ones.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-never-used', 12);

const COOKIE_NAME = 'sid';
const SESSION_MS = 8 * 60 * 60 * 1000; // 8 hours
const SESSION_TTL_S = SESSION_MS / 1000;

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/** IP-level limit: 10 failed login attempts per 15 minutes. */
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many requests' },
  skipSuccessfulRequests: true,
});

/**
 * Per-email lockout: true if this (lowercased) email has 5 or more DENIED
 * logins in the last 15 minutes. Exact match via json_extract.
 */
function isEmailLockedOut(email: string): boolean {
  const db = getDb();
  const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const row = db
    .prepare(`
      SELECT COUNT(*) AS cnt
      FROM   audit_log
      WHERE  action  = 'LOGIN'
        AND  outcome = 'DENIED'
        AND  ts      >= ?
        AND  json_extract(detail_json, '$.email') = ?
    `)
    .get(since, email) as { cnt: number };
  return row.cnt >= 5;
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

function setSessionCookie(res: Response, token: string): void {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env['NODE_ENV'] === 'production',
    maxAge: SESSION_MS,
  });
}

function clearSessionCookie(res: Response): void {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict' });
}

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------

authRouter.post('/login', ipLimiter, async (req: Request, res: Response): Promise<void> => {
  const db = getDb();
  const ip = req.ip ?? null;

  // 1. Validate input types and lengths.
  const { email: rawEmail, password } = (req.body ?? {}) as Record<string, unknown>;

  if (
    typeof rawEmail !== 'string' || rawEmail.length < 1 || rawEmail.length > 254 ||
    typeof password !== 'string' || password.length < 1 || password.length > 1024
  ) {
    res.status(400).json({ error: 'invalid credentials' });
    return;
  }

  // Normalise so case rotation cannot dodge the lockout.
  const email = rawEmail.trim().toLowerCase();

  // 2. Per-email lockout.
  if (isEmailLockedOut(email)) {
    appendAudit(db, {
      actor_id: null,
      action: 'LOGIN',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      ip,
      detail_json: JSON.stringify({ reason: 'email_locked_out', email }),
    });
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }

  // 3. Look up the user.
  interface UserRow {
    id: string;
    name: string;
    email: string;
    password_hash: string;
    role: 'admin' | 'owner' | 'viewer';
    disabled: number;
  }

  const userRow = db
    .prepare<[string], UserRow>(
      'SELECT id, name, email, password_hash, role, disabled FROM users WHERE email = ?'
    )
    .get(email);

  // 4. Always run bcrypt.compare (real hash even for unknown users).
  const hashToCheck = userRow?.password_hash ?? DUMMY_HASH;
  const passwordOk = await bcrypt.compare(password, hashToCheck);

  // 5. One identical denial path.
  const isValid = passwordOk && userRow !== undefined && userRow.disabled === 0;

  if (!isValid) {
    appendAudit(db, {
      actor_id: userRow?.id ?? null,
      action: 'LOGIN',
      document_id: null,
      target_user_id: null,
      outcome: 'DENIED',
      ip,
      detail_json: JSON.stringify({ email }), // used by lockout query; no secrets
    });
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }

  // 6. Success: drop older sessions, create a new one, set cookie.
  revokeAllSessionsForUser(db, userRow!.id);
  const token = createSession(db, userRow!.id);
  setSessionCookie(res, token);

  appendAudit(db, {
    actor_id: userRow!.id,
    action: 'LOGIN',
    document_id: null,
    target_user_id: null,
    outcome: 'ALLOWED',
    ip,
    detail_json: null,
  });

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------

authRouter.post('/logout', (req: Request, res: Response): void => {
  const db = getDb();
  const ip = req.ip ?? null;
  const raw = req.cookies?.[COOKIE_NAME] as string | undefined;

  if (raw) {
    revokeSession(db, raw);
  }

  clearSessionCookie(res);

  // Only audit a logout that belonged to a real session.
  if (req.actor) {
    appendAudit(db, {
      actor_id: req.actor.id,
      action: 'LOGOUT',
      document_id: null,
      target_user_id: null,
      outcome: 'ALLOWED',
      ip,
      detail_json: null,
    });
  }

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------

authRouter.get('/me', requireAuth, (req: Request, res: Response): void => {
  const actor = req.actor!;
  const db = getDb();

  const row = db
    .prepare<[string], { name: string; email: string }>(
      'SELECT name, email FROM users WHERE id = ?'
    )
    .get(actor.id);

  if (!row) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }

  res.json({ id: actor.id, name: row.name, email: row.email, role: actor.role });
});

export { SESSION_TTL_S };