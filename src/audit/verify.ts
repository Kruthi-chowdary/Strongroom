/**
 * verify.ts – recompute the hash chain; return the first broken row id.
 */
import type Database from 'better-sqlite3';
import { computeHash, type AuditRow } from './audit';

export interface VerifyResult { ok: boolean; rows: number; firstBrokenId: number | null; head: string | null }

export function verifyChain(db: Database.Database): VerifyResult {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id').all() as Array<AuditRow & { hash: string }>;
  let prev: string | null = null;
  let expectedId = 1;
  for (const r of rows) {
    if (r.id !== expectedId || r.prev_hash !== prev || computeHash(r) !== r.hash) {
      return { ok: false, rows: rows.length, firstBrokenId: r.id, head: prev };
    }
    prev = r.hash;
    expectedId++;
  }
  return { ok: true, rows: rows.length, firstBrokenId: null, head: prev };
}