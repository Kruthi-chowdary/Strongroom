import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import path from 'path';
import os from 'os';
import fs from 'fs';

process.env['DB_PATH'] = path.join(os.tmpdir(), `sr-test-${Date.now()}.db`);
process.env['STORAGE_DIR'] = fs.mkdtempSync(path.join(os.tmpdir(), 'sr-files-'));
process.env['FILE_ENCRYPTION_KEY'] = 'a'.repeat(64);

import { app } from '../src/server';
import { getDb } from '../src/db';
import { seed } from '../src/seed';
import { verifyChain } from '../src/audit/verify';

const H = { 'X-Requested-With': 'strongroom' };
async function login(email: string, password: string) {
  const agent = request.agent(app);
  const r = await agent.post('/api/auth/login').set(H).send({ email, password });
  expect(r.status).toBe(200);
  return agent;
}
const idOf = (email: string) =>
  (getDb().prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string }).id;

let doc1: string; // owned by owner1

beforeAll(async () => {
  await seed();
  doc1 = (getDb().prepare("SELECT id FROM documents WHERE owner_id = ? LIMIT 1").get(idOf('owner1@strongroom.local')) as { id: string }).id;
}, 60_000);

describe('THREAT: IDOR / cross-user access', () => {
  it('viewer with no grant cannot get a ticket (404, DENIED audited)', async () => {
    const v = await login('viewer1@strongroom.local', 'Viewer$ecret1!');
    const r = await v.post(`/api/documents/${doc1}/download-ticket`).set(H);
    expect(r.status).toBe(404);
    const denied = getDb().prepare("SELECT COUNT(*) n FROM audit_log WHERE document_id=? AND outcome='DENIED'").get(doc1) as { n: number };
    expect(denied.n).toBeGreaterThan(0);
  });
  it('another owner cannot ticket, grant or read custody of it', async () => {
    const o2 = await login('owner2@strongroom.local', 'Owner$ecret2!');
    expect((await o2.post(`/api/documents/${doc1}/download-ticket`).set(H)).status).toBe(404);
    expect((await o2.post(`/api/documents/${doc1}/grants`).set(H).send({ userId: idOf('viewer1@strongroom.local'), permission: 'read' })).status).toBe(404);
    expect((await o2.get(`/api/documents/${doc1}/custody`)).status).toBe(404);
  });
  it('unauthenticated requests get 401', async () => {
    expect((await request(app).get('/api/documents')).status).toBe(401);
  });
});

describe('THREAT: search leakage', () => {
  it('viewer search returns none of owner1 docs; owner2 sees only own', async () => {
    const v = await login('viewer2@strongroom.local', 'Viewer$ecret2!');
    expect((await v.get('/api/documents?q=Salary')).body.items).toHaveLength(0);
    const o2 = await login('owner2@strongroom.local', 'Owner$ecret2!');
    const names = (await o2.get('/api/documents')).body.items.map((i: { owner_name: string }) => i.owner_name);
    expect(names.every((n: string) => n === 'Carol Owner')).toBe(true);
  });
  it('LIKE wildcard % does not widen search', async () => {
    const v = await login('viewer3@strongroom.local', 'Viewer$ecret3!');
    expect((await v.get('/api/documents?q=%25')).body.items).toHaveLength(0);
  });
});

describe('THREAT: revoked-but-still-has-link / ticket replay', () => {
  it('grant works, ticket is single-use, revoke between issue and redeem is refused', async () => {
    const o1 = await login('owner1@strongroom.local', 'Owner$ecret1!');
    const v = await login('viewer1@strongroom.local', 'Viewer$ecret1!');
    const g = await o1.post(`/api/documents/${doc1}/grants`).set(H).send({ userId: idOf('viewer1@strongroom.local'), permission: 'read' });
    expect(g.status).toBe(201);

    // happy path + replay
    const t1 = (await v.post(`/api/documents/${doc1}/download-ticket`).set(H)).body.ticket;
    expect((await v.get(`/api/download/${t1}`)).status).toBe(200);
    expect((await v.get(`/api/download/${t1}`)).status).toBe(404); // replay refused

    // issue, revoke, redeem
    const t2 = (await v.post(`/api/documents/${doc1}/download-ticket`).set(H)).body.ticket;
    expect((await o1.delete(`/api/documents/${doc1}/grants/${g.body.grantId}`).set(H)).status).toBe(200);
    expect((await v.get(`/api/download/${t2}`)).status).toBe(404);
    expect((await v.post(`/api/documents/${doc1}/download-ticket`).set(H)).status).toBe(404);
  });
  it('a ticket cannot be redeemed by a different user', async () => {
    const o1 = await login('owner1@strongroom.local', 'Owner$ecret1!');
    const v1 = await login('viewer1@strongroom.local', 'Viewer$ecret1!');
    const v2 = await login('viewer2@strongroom.local', 'Viewer$ecret2!');
    await o1.post(`/api/documents/${doc1}/grants`).set(H).send({ userId: idOf('viewer1@strongroom.local'), permission: 'read' });
    const t = (await v1.post(`/api/documents/${doc1}/download-ticket`).set(H)).body.ticket;
    expect((await v2.get(`/api/download/${t}`)).status).toBe(404);
  });
});

describe('THREAT: admin overreach', () => {
  it('admin cannot list or download contents, but can view and verify audit', async () => {
    const a = await login('admin@strongroom.local', 'Admin$ecret1!');
    expect((await a.get('/api/documents')).body.items).toHaveLength(0);
    expect((await a.post(`/api/documents/${doc1}/download-ticket`).set(H)).status).toBe(404);
    expect((await a.get('/api/admin/audit')).status).toBe(200);
    expect((await a.get('/api/admin/audit/verify')).body.ok).toBe(true);
  });
  it('non-admin cannot reach admin routes', async () => {
    const o1 = await login('owner1@strongroom.local', 'Owner$ecret1!');
    expect((await o1.get('/api/admin/audit')).status).toBe(403);
  });
});

describe('THREAT: malicious upload / path traversal', () => {
  it('rejects .html, double extension, and content/extension mismatch', async () => {
    const o1 = await login('owner1@strongroom.local', 'Owner$ecret1!');
    const up = (name: string, body: string) =>
      o1.post('/api/documents').set(H).attach('file', Buffer.from(body), name);
    expect((await up('x.html', '<script>1</script>')).status).toBe(400);
    expect((await up('x.php.txt', 'hello')).status).toBe(400);
    expect((await up('fake.pdf', 'not a pdf')).status).toBe(400);
  });
  it('traversal filename is sanitised, upload stores under uuid', async () => {
    const o1 = await login('owner1@strongroom.local', 'Owner$ecret1!');
    const r = await o1.post('/api/documents').set(H).attach('file', Buffer.from('hello'), '../../etc/passwd.txt');
    expect(r.status).toBe(201);
    expect(r.body.name).toBe('passwd.txt');
  });
  it('viewer cannot upload', async () => {
    const v = await login('viewer1@strongroom.local', 'Viewer$ecret1!');
    expect((await v.post('/api/documents').set(H).attach('file', Buffer.from('hi'), 'a.txt')).status).toBe(403);
  });
});

describe('THREAT: audit tampering', () => {
  it('UPDATE and DELETE on audit_log are blocked by triggers', () => {
    const db = getDb();
    expect(() => db.prepare("UPDATE audit_log SET ip='x' WHERE id=1").run()).toThrow(/append-only/);
    expect(() => db.prepare('DELETE FROM audit_log WHERE id=1').run()).toThrow(/append-only/);
  });
  it('if triggers are dropped, verify detects the edit', () => {
    const db = getDb();
    db.exec('DROP TRIGGER audit_no_update');
    db.prepare("UPDATE audit_log SET ip='6.6.6.6' WHERE id=3").run();
    const r = verifyChain(db);
    expect(r.ok).toBe(false);
    expect(r.firstBrokenId).toBe(3);
  });
});