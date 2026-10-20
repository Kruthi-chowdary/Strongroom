/**
 * middleware.ts – Express authentication and CSRF middleware.
 *
 * Security decisions:
 * - attachActor reads ONLY the httpOnly "sid" cookie; never reads identity
 *   from body, query string, or Authorization header (Rule 3).
 * - The role on req.actor comes from loadActor's DB join, not from the cookie.
 * - csrfGuard requires X-Requested-With: strongroom on state-changing methods
 *   and validates the Origin header against our own origin (Rule 4 / CSRF).
 */

import type { Request, Response, NextFunction } from 'express';
import { loadActor }                            from './sessions';
import type { Actor }                           from './authorize';
import { getDb }                                from '../db';

// ---------------------------------------------------------------------------
// Augment the Express Request type so TypeScript knows about req.actor.
// ---------------------------------------------------------------------------
declare global {
  namespace Express {
    interface Request {
      /** The authenticated actor, or null if the request is unauthenticated. */
      actor: Actor | null;
    }
  }
}

// ---------------------------------------------------------------------------
// attachActor
// ---------------------------------------------------------------------------

/**
 * Reads the "sid" httpOnly cookie, resolves it to an Actor (re-querying the
 * DB every call – no caching), and sets req.actor.  Always continues to the
 * next handler; authentication enforcement is done by requireAuth.
 *
 * Identity is NEVER taken from the request body, query string or any header
 * other than the cookie (Rule 3).
 */
export function attachActor(
  req: Request,
  _res: Response,
  next: NextFunction
): void {
  const raw: unknown = req.cookies?.['sid'];
  if (typeof raw === 'string' && raw.length > 0) {
    req.actor = loadActor(getDb(), raw);
  } else {
    req.actor = null;
  }
  next();
}

// ---------------------------------------------------------------------------
// requireAuth
// ---------------------------------------------------------------------------

/**
 * Rejects the request with 401 if the caller is not authenticated.
 * Intentionally gives no detail about WHY (Rule 2 – default deny).
 */
export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.actor) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  next();
}

// ---------------------------------------------------------------------------
// requireRole
// ---------------------------------------------------------------------------

/**
 * Returns middleware that rejects with 403 if the actor's role (from the DB,
 * via loadActor) is not in the allowed set.
 *
 * @param roles - The set of roles that may proceed.
 */
export function requireRole(
  ...roles: Array<'admin' | 'owner' | 'viewer'>
): (req: Request, res: Response, next: NextFunction) => void {
  const allowed = new Set(roles);
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.actor || !allowed.has(req.actor.role)) {
      res.status(403).json({ error: 'forbidden' });
      return;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// csrfGuard
// ---------------------------------------------------------------------------

/** State-changing HTTP methods that require CSRF protection. */
const CSRF_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * CSRF guard for same-site form-equivalent protection.
 *
 * For POST/PUT/PATCH/DELETE requests:
 * 1. The header X-Requested-With must equal "strongroom".
 * 2. If an Origin header is present it must match our own origin
 *    (protocol + host, derived from the Host header).
 *
 * This is defence-in-depth on top of SameSite=Strict cookies.
 * Rejects with 403; no detail about which rule failed (Rule 2).
 */
export function csrfGuard(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!CSRF_METHODS.has(req.method)) {
    next();
    return;
  }

  // 1. Custom header check – browsers never send this automatically (CSRF).
  if (req.headers['x-requested-with'] !== 'strongroom') {
    res.status(403).json({ error: 'csrf check failed' });
    return;
  }

  // 2. Origin check – if the browser sends an Origin it must be ours.
  const origin = req.headers['origin'];
  if (origin) {
    // Build our expected origin from the Host header.
    const proto      = req.secure || req.headers['x-forwarded-proto'] === 'https'
      ? 'https' : 'http';
    const host       = req.headers['host'] ?? '';
    const ownOrigin  = `${proto}://${host}`;

    if (origin !== ownOrigin) {
      res.status(403).json({ error: 'csrf check failed' });
      return;
    }
  }

  next();
}
