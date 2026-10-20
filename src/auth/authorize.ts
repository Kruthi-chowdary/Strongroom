import type Database from 'better-sqlite3';
import { appendAudit } from '../audit/audit';

// ---------------------------------------------------------------------------
// Types (Rule 8 – typed everywhere a security decision is made)
// ---------------------------------------------------------------------------

export type Action =
  | 'read'
  | 'download'
  | 'edit'
  | 'delete'
  | 'share'
  | 'view_audit';

export interface Actor {
  id: string;
  role: 'admin' | 'owner' | 'viewer';
}

export interface AuthContext {
  ip?: string;
}

export interface AuthResult {
  allowed: boolean;
  // Intentionally NO reason field – callers must not be able to tell why
  // access was denied (Rule 2 / default-deny information hiding).
}

// ---------------------------------------------------------------------------
// DB row shapes (internal only)
// ---------------------------------------------------------------------------

interface UserRow {
  disabled: number;
  role: 'admin' | 'owner' | 'viewer';
}

interface DocumentRow {
  owner_id: string;
  deleted_at: string | null;
}

interface GrantRow {
  permission: 'read' | 'edit';
  revoked_at: string | null;
  expires_at: string | null;
}

// ---------------------------------------------------------------------------
// Permission matrix
// ---------------------------------------------------------------------------

/** Actions an owner may perform on their own document (Rule 1 spec). */
const OWNER_ALLOWED_ACTIONS: ReadonlySet<Action> = new Set([
  'read', 'download', 'edit', 'delete', 'share',
]);

/** Mapping from grant permission level to the set of actions it unlocks. */
const GRANT_ACTION_MAP: Record<'read' | 'edit', ReadonlySet<Action>> = {
  read: new Set(['read', 'download']),
  edit: new Set(['read', 'download', 'edit']),
};

// ---------------------------------------------------------------------------
// authorize
// ---------------------------------------------------------------------------

/**
 * Central authorization gate – every document-related route MUST call this
 * (Rule 1).  No route may inline permission logic.
 *
 * Design decisions:
 * - Default deny: anything not explicitly permitted returns { allowed: false }
 *   (Rule 2).
 * - Actor identity comes from the caller (who reads it from the server-side
 *   session) – never from the request body (Rule 3).
 * - Every call re-queries users, documents and grants from the DB; no caching
 *   so revocations take effect instantly (Rule 4 / session revocation).
 * - Every call (ALLOWED or DENIED) writes an audit_log row (Rule 5).
 * - The return type reports only { allowed } – no reason string – so the
 *   caller cannot distinguish "doc missing" from "not granted" (Rule 2).
 *
 * @param db     - Active better-sqlite3 Database instance (injected for testability).
 * @param actor  - Identity from the server-side session; null = unauthenticated.
 * @param docId  - The document UUID being acted upon.
 * @param action - The action being attempted.
 * @param ctx    - Request context (ip, etc.).
 */
export function authorize(
  db: Database.Database,
  actor: Actor | null,
  docId: string,
  action: Action,
  ctx: AuthContext = {}
): AuthResult {

  const ip = ctx.ip ?? null;

  /** Deny and log, then return { allowed: false }. */
  function deny(detail?: string): AuthResult {
    appendAudit(db, {
      actor_id: actor?.id ?? null,
      action,
      document_id: docId,
      target_user_id: null,
      outcome: 'DENIED',
      ip,
      // detail_json may hold machine-readable context for internal review;
      // it is never surfaced to the HTTP caller (Rule 2, Rule 5).
      detail_json: detail ? JSON.stringify({ reason: detail }) : null,
    });
    return { allowed: false };
  }

  /** Allow and log, then return { allowed: true }. */
  function allow(): AuthResult {
    appendAudit(db, {
      actor_id: actor?.id ?? null,
      action,
      document_id: docId,
      target_user_id: null,
      outcome: 'ALLOWED',
      ip,
      detail_json: null,
    });
    return { allowed: true };
  }

  // ── 1. Null actor → unauthenticated, always deny (Rule 2) ──────────────
  if (!actor) return deny('unauthenticated');

  // 2. Re-read disabled flag AND role from DB every call (Rule 3).
  //    The role passed in by the caller is ignored.
  const userRow = db
    .prepare<[string], UserRow>('SELECT disabled, role FROM users WHERE id = ?')
    .get(actor.id);

  if (!userRow || userRow.disabled === 1) return deny('user_disabled_or_missing');

  // 3. Admin may ONLY view_audit, no document-content access
  if (userRow.role === 'admin') {
    return action === 'view_audit' ? allow() : deny('admin_no_doc_access');
  }

  // ── 4. Load the document – re-query every call (Rule spec) ──────────────
  const docRow = db
    .prepare<[string], DocumentRow>(
      'SELECT owner_id, deleted_at FROM documents WHERE id = ?'
    )
    .get(docId);

  // Non-existent or soft-deleted → identical 404 treatment (Rule 2).
  if (!docRow || docRow.deleted_at !== null) return deny('doc_not_found_or_deleted');

  // view_audit on a real doc: only admin (handled above) may do this.
  // For non-admins: always deny.
  if (action === 'view_audit') return deny('non_admin_view_audit');

  // ── 5. Owner check ───────────────────────────────────────────────────────
  if (docRow.owner_id === actor.id) {
    // Owner may read, download, edit, delete, share their own doc (Rule spec).
    return OWNER_ALLOWED_ACTIONS.has(action) ? allow() : deny('owner_action_not_allowed');
  }

  // ── 6. Grant check for non-owners ────────────────────────────────────────
  // Only 'read' and 'edit' grants exist; delete and share are owner-only.
  if (action === 'delete' || action === 'share') {
    return deny('delete_share_owner_only');
  }

  // Load the best active grant for this (user, document) pair.
  // A grant is active if revoked_at IS NULL and (expires_at IS NULL OR expires_at > now).
  const grantRow = db
    .prepare<[string, string], GrantRow>(`
      SELECT permission, revoked_at, expires_at
      FROM   grants
      WHERE  document_id = ?
        AND  user_id     = ?
        AND  revoked_at  IS NULL
        AND  (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))
      ORDER BY CASE permission WHEN 'edit' THEN 1 ELSE 2 END
      LIMIT 1
    `)
    .get(docId, actor.id);

  if (!grantRow) return deny('no_active_grant');

  // Check the action is covered by the grant's permission level.
  const permitted = GRANT_ACTION_MAP[grantRow.permission];
  return permitted.has(action) ? allow() : deny('grant_insufficient');
}
