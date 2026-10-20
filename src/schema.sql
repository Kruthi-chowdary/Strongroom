-- Strongroom database schema
-- Foreign keys are enforced at the application layer via PRAGMA foreign_keys = ON (see db.ts).

-- Users: platform identities. Role is checked server-side, never from request body (Rule 3).
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,          -- UUID v4
  email       TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  password_hash TEXT NOT NULL,           -- bcrypt hash; never stored in plain text
  role        TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  department  TEXT,
  disabled    INTEGER NOT NULL DEFAULT 0, -- 1 = account locked; re-checked on every authorize() call
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Sessions: server-side only (Rule 4). No JWT/bearer tokens.
-- httpOnly + SameSite=Strict cookie holds only the session id.
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,          -- UUID v4, used as cookie value
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at  TEXT NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0 -- set to 1 on logout or password change
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Documents: storage_key is a random UUID path outside the web root (Rule 6).
-- Never build file paths from user-supplied input.
CREATE TABLE IF NOT EXISTS documents (
  id          TEXT PRIMARY KEY,          -- UUID v4
  owner_id    TEXT NOT NULL REFERENCES users(id),
  name        TEXT NOT NULL,             -- display name (not the storage path)
  category    TEXT,
  storage_key TEXT NOT NULL UNIQUE,      -- random UUID used for on-disk path
  mime        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,             -- integrity check on download
  version     INTEGER NOT NULL DEFAULT 1,
  deleted_at  TEXT,                      -- soft delete; treat as 404 (Rule 2)
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_deleted ON documents(deleted_at);

-- Grants: explicit per-document permission rows. Default deny (Rule 1 & 2).
CREATE TABLE IF NOT EXISTS grants (
  id          TEXT PRIMARY KEY,          -- UUID v4
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission  TEXT NOT NULL CHECK (permission IN ('read','edit')),
  granted_by  TEXT NOT NULL REFERENCES users(id),
  expires_at  TEXT,
  revoked_at  TEXT,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_grants_doc ON grants(document_id);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);

-- Audit log: append-only, hash-chained (Rule 5).
-- prev_hash and hash form an integrity chain; never log secrets.
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  actor_id      TEXT,                    -- NULL for unauthenticated attempts
  action        TEXT NOT NULL,
  document_id   TEXT,
  target_user_id TEXT,
  outcome       TEXT NOT NULL CHECK (outcome IN ('ALLOWED','DENIED')),
  ip            TEXT,
  detail_json   TEXT,                    -- extra context, must NOT contain secrets
  prev_hash     TEXT,                    -- SHA-256 of previous row's hash
  hash          TEXT NOT NULL            -- SHA-256(id||ts||actor_id||action||outcome||prev_hash)
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_doc   ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(ts);

-- Append-only audit log: block UPDATE and DELETE at the database level (Rule 5).
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;