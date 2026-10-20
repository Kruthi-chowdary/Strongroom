/**
 * auth.test.ts – integration tests for the auth routes and session system.
 *
 * Tests are named after threats from THREATS.md (Rule 7).
 * Uses an in-memory SQLite database so tests are fully isolated.
 *
 * Architecture note: we use vi.mock to intercept getDb() so every route
 * call uses our ephemeral in-memory DB, not the real file-based one.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Mock the DB module BEFORE any other imports load it (Rule 3 / isolation).
// vi.mock is hoisted to the top of the file by vitest.
// ---------------------------------------------------------------------------

// We use a module-level variable so each test can swap the DB instance.
let _testDb: Database.Database;

vi.mock('../src/db', () => ({
  getDb:   () => _testDb,
  closeDb: () => { /* no-op in tests */ },
}));

// Import app AFTER the mock is registered.
import { app } from '../src/server';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SCHEMA = fs.readFileSync(
  path.join(__dirname, '../src/schema.sql'),
  'utf8'
);

const CSRF_HEADER = { 'X-Requested-With': 'strongroom' };

/** Build a fresh in-memory DB with one owner user pre-seeded. */
function makeDb(opts: { disabled?: boolean } = {}): Database.Database {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);

  const hash = bcrypt.hashSync('ValidPass1!', 4); // low rounds for test speed
  db.prepare(
    'INSERT INTO users (id, email, name, password_hash, role, disabled) VALUES (?,?,?,?,?,?)'
  ).run(
    'user-1',
    'bob@example.com',
    'Bob',
    hash,
    'owner',
    opts.disabled ? 1 : 0
  );

  return db;
}

/** Log in and return the full response (including Set-Cookie). */
function doLogin(
  email    = 'bob@example.com',
  password = 'ValidPass1!'
): request.Test {
  return request(app)
    .post('/api/auth/login')
    .set(CSRF_HEADER)
    .send({ email, password });
}

/** Extract the raw sid cookie value from a Set-Cookie array. */
function extractSid(setCookieHeaders: string | string[]): string {
  const headers = Array.isArray(setCookieHeaders)
    ? setCookieHeaders
    : [setCookieHeaders];
  const entry = headers.find(h => h.startsWith('sid='));
  if (!entry) throw new Error('No sid cookie found in response');
  return entry.split(';')[0]!.slice('sid='.length);
}

// ---------------------------------------------------------------------------
// Suite setup: each test gets a fresh in-memory DB
// ---------------------------------------------------------------------------

beforeEach(() => {
  _testDb = makeDb();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('auth: login', () => {
  it('login success returns ok and sets httpOnly cookie', async () => {
    const res = await doLogin();

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });

    const cookies = res.headers['set-cookie'] as string | string[] | undefined;
    expect(cookies).toBeTruthy();
    const joined = Array.isArray(cookies) ? cookies.join('; ') : cookies!;
    expect(joined.toLowerCase()).toContain('httponly');
    expect(joined.toLowerCase()).toContain('samesite=strict');
  });

  it('wrong password returns 401 with identical message', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADER)
      .send({ email: 'bob@example.com', password: 'wrongpassword' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid credentials' });
  });

  it('THREAT: unknown email returns identical 401 (account enumeration prevention)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set(CSRF_HEADER)
      .send({ email: 'nobody@example.com', password: 'irrelevant' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid credentials' });
  });

  it('THREAT: disabled user cannot log in and gets identical message', async () => {
    _testDb = makeDb({ disabled: true });

    const res = await doLogin();

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid credentials' });
  });
});

describe('auth: session lifecycle', () => {
  it('THREAT: disabled user with live session gets 401 on /me on the very next request', async () => {
    const loginRes = await doLogin();
    expect(loginRes.status).toBe(200);

    const cookie = extractSid(loginRes.headers['set-cookie'] as string[]);

    // Disable the user mid-session.
    _testDb.prepare("UPDATE users SET disabled = 1 WHERE id = 'user-1'").run();

    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sid=${cookie}`);

    expect(meRes.status).toBe(401);
  });

  it('THREAT: revoked session returns 401 on /me', async () => {
    const loginRes = await doLogin();
    const cookie   = extractSid(loginRes.headers['set-cookie'] as string[]);

    // Revoke all sessions in the DB.
    _testDb.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = 'user-1'").run();

    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sid=${cookie}`);

    expect(meRes.status).toBe(401);
  });

  it('logout invalidates the session and subsequent /me returns 401', async () => {
    const loginRes = await doLogin();
    const cookie   = extractSid(loginRes.headers['set-cookie'] as string[]);

    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set(CSRF_HEADER)
      .set('Cookie', `sid=${cookie}`);

    expect(logoutRes.status).toBe(200);

    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sid=${cookie}`);

    expect(meRes.status).toBe(401);
  });

  it('/me returns correct user fields for authenticated user', async () => {
    const loginRes = await doLogin();
    const cookie   = extractSid(loginRes.headers['set-cookie'] as string[]);

    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `sid=${cookie}`);

    expect(meRes.status).toBe(200);
    expect(meRes.body).toMatchObject({
      id:    'user-1',
      email: 'bob@example.com',
      name:  'Bob',
      role:  'owner',
    });
  });

  it('/me without cookie returns 401', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });
});

describe('auth: CSRF guard', () => {
  it('THREAT: POST without X-Requested-With header is rejected with 403', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'bob@example.com', password: 'ValidPass1!' });

    expect(res.status).toBe(403);
  });

  it('GET /health passes csrfGuard without the custom header', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});

describe('auth: session token not stored raw in DB', () => {
  it('THREAT: session token is stored as SHA-256 hash only, never in plain text', async () => {
    const loginRes = await doLogin();
    const rawToken = extractSid(loginRes.headers['set-cookie'] as string[]);

    const rows = _testDb
      .prepare('SELECT id FROM sessions')
      .all() as { id: string }[];

    expect(rows.length).toBe(1);

    const storedId = rows[0]!.id;

    // Raw token must NOT be in the DB.
    expect(storedId).not.toBe(rawToken);

    // Stored id must equal sha256(rawToken).
    const expectedHash = crypto
      .createHash('sha256')
      .update(rawToken, 'utf8')
      .digest('hex');
    expect(storedId).toBe(expectedHash);
  });
});
