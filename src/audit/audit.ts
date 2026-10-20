import crypto from 'crypto';
import type Database from 'better-sqlite3';

export interface AuditEntry {
  actor_id:       string | null;
  action:         string;
  document_id:    string | null;
  target_user_id: string | null;
  outcome:        'ALLOWED' | 'DENIED';
  ip:             string | null;
  /** Must NEVER contain passwords, keys or other secrets (Rule 5). */
  detail_json:    string | null;
}

export interface AuditRow extends AuditEntry {
  id:        number;
  ts:        string;
  prev_hash: string | null;
}

function sha256(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * hash = sha256(prev_hash + JSON array of EVERY data column).
 * Array form gives a fixed field order. Exported so the verifier (Prompt 6)
 * recomputes with the exact same function.
 */
export function computeHash(r: AuditRow): string {
  const canonical = JSON.stringify([
    r.id, r.ts, r.actor_id, r.action, r.document_id,
    r.target_user_id, r.outcome, r.ip, r.detail_json, r.prev_hash,
  ]);
  return sha256((r.prev_hash ?? '') + canonical);
}

/**
 * Append one row. Single INSERT, never an UPDATE, so DB triggers can block
 * UPDATE/DELETE on audit_log. IMMEDIATE transaction takes the write lock
 * before reading the last row, so the chain cannot fork (Rule 5).
 */
export function appendAudit(db: Database.Database, entry: AuditEntry): void {
  const write = db.transaction((e: AuditEntry) => {
    const prev = db
      .prepare('SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1')
      .get() as { id: number; hash: string } | undefined;

    const row: AuditRow = {
      ...e,
      id: (prev?.id ?? 0) + 1,
      ts: new Date().toISOString(),
      prev_hash: prev?.hash ?? null,
    };

    db.prepare(`
      INSERT INTO audit_log
        (id, ts, actor_id, action, document_id, target_user_id,
         outcome, ip, detail_json, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      row.id, row.ts, row.actor_id, row.action, row.document_id,
      row.target_user_id, row.outcome, row.ip, row.detail_json,
      row.prev_hash, computeHash(row)
    );
  });

  write.immediate(entry);
}
