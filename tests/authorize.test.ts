import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { authorize, type Action } from '../src/auth/authorize';
import { computeHash, type AuditRow } from '../src/audit/audit';

const ACTIONS: Action[] = ['read', 'download', 'edit', 'delete', 'share', 'view_audit'];
type Grant = 'none' | 'read' | 'edit' | 'revoked' | 'expired';
const GRANTS: Grant[] = ['none', 'read', 'edit', 'revoked', 'expired'];
const iso = (ms: number) => new Date(Date.now() + ms).toISOString();

function setup(grant: Grant = 'none', grantee = 'viewer1') {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(fs.readFileSync(path.join(__dirname, '../src/schema.sql'), 'utf8'));
  const u = db.prepare('INSERT INTO users (id,email,name,password_hash,role) VALUES (?,?,?,?,?)');
  u.run('admin1', 'admin@x.test', 'Admin', 'h', 'admin');
  u.run('owner1', 'o1@x.test', 'Owner1', 'h', 'owner');
  u.run('owner2', 'o2@x.test', 'Owner2', 'h', 'owner');
  u.run('viewer1', 'v1@x.test', 'Viewer1', 'h', 'viewer');
  db.prepare(`INSERT INTO documents (id,owner_id,name,storage_key,mime,size,sha256)
              VALUES ('doc1','owner1','d','key1','text/plain',1,'h')`).run();
  if (grant !== 'none') {
    const perm = grant === 'edit' ? 'edit' : 'read';
    db.prepare(`INSERT INTO grants (id,document_id,user_id,permission,granted_by,expires_at,revoked_at)
                VALUES ('g1','doc1',?,?,'owner1',?,?)`)
      .run(grantee, perm, grant === 'expired' ? iso(-60_000) : null, grant === 'revoked' ? iso(-1000) : null);
  }
  return db;
}

function expected(who: string, grant: Grant, action: Action): boolean {
  if (who === 'admin1') return action === 'view_audit';
  if (who === 'owner1') return action !== 'view_audit';
  if (action === 'view_audit' || action === 'delete' || action === 'share') return false;
  if (grant === 'read') return action === 'read' || action === 'download';
  if (grant === 'edit') return ['read', 'download', 'edit'].includes(action);
  return false;
}

const ACTORS: Array<[string, 'admin' | 'owner' | 'viewer']> = [
  ['admin1', 'admin'], ['owner1', 'owner'], ['owner2', 'owner'], ['viewer1', 'viewer'],
];

describe('authorize: role x grant state x action', () => {
  for (const [who, role] of ACTORS) {
    for (const grant of GRANTS) {
      for (const action of ACTIONS) {
        it(`${who} / grant=${grant} / ${action}`, () => {
          const db = setup(grant, who);
          const res = authorize(db, { id: who, role }, 'doc1', action, { ip: '1.1.1.1' });
          expect(res.allowed).toBe(expected(who, grant, action));
        });
      }
    }
  }
});

describe('authorize: edge cases', () => {
  it('null actor is denied', () => {
    expect(authorize(setup(), null, 'doc1', 'read').allowed).toBe(false);
  });
  it('disabled owner is denied', () => {
    const db = setup();
    db.prepare("UPDATE users SET disabled=1 WHERE id='owner1'").run();
    expect(authorize(db, { id: 'owner1', role: 'owner' }, 'doc1', 'read').allowed).toBe(false);
  });
  it('deleted document is denied even for owner', () => {
    const db = setup();
    db.prepare("UPDATE documents SET deleted_at=? WHERE id='doc1'").run(iso(0));
    expect(authorize(db, { id: 'owner1', role: 'owner' }, 'doc1', 'read').allowed).toBe(false);
  });
  it('nonexistent document is denied', () => {
    expect(authorize(setup(), { id: 'owner1', role: 'owner' }, 'nope', 'read').allowed).toBe(false);
  });
  it('FORGED ROLE: viewer claiming admin cannot view_audit (role read from DB)', () => {
    const db = setup();
    expect(authorize(db, { id: 'viewer1', role: 'admin' }, 'doc1', 'view_audit').allowed).toBe(false);
  });
  it('REVOCATION: grant revoked after first success is denied on the next call', () => {
    const db = setup('read');
    const a = { id: 'viewer1', role: 'viewer' as const };
    expect(authorize(db, a, 'doc1', 'download').allowed).toBe(true);
    db.prepare("UPDATE grants SET revoked_at=? WHERE id='g1'").run(iso(0));
    expect(authorize(db, a, 'doc1', 'download').allowed).toBe(false);
  });
  it('AUDIT: every call writes exactly one row, DENIED included, and the chain verifies', () => {
    const db = setup('read');
    const a = { id: 'viewer1', role: 'viewer' as const };
    authorize(db, a, 'doc1', 'read');
    authorize(db, a, 'doc1', 'delete');
    authorize(db, null, 'doc1', 'read');
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id').all() as Array<AuditRow & { hash: string }>;
    expect(rows.map(r => r.outcome)).toEqual(['ALLOWED', 'DENIED', 'DENIED']);
    let prev: string | null = null;
    for (const r of rows) {
      expect(r.prev_hash).toBe(prev);
      expect(computeHash(r)).toBe(r.hash);
      prev = r.hash;
    }
  });
  it('AUDIT: editing ip or detail_json breaks the hash', () => {
    const db = setup();
    authorize(db, { id: 'owner1', role: 'owner' }, 'doc1', 'read', { ip: '9.9.9.9' });
    db.prepare("UPDATE audit_log SET ip='1.2.3.4' WHERE id=1").run();
    const r = db.prepare('SELECT * FROM audit_log WHERE id=1').get() as AuditRow & { hash: string };
    expect(computeHash(r)).not.toBe(r.hash);
  });
});
