/**
 * seed.ts – demo users and sample documents with FIXED passwords so the
 * README credentials work. Runs only when called explicitly (server boot with
 * SEED_DEMO=true, or `npm run seed`). Skips if users already exist.
 */

import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDb, closeDb } from './db';
import { encryptAndStore } from './storage/crypto';

const BCRYPT_ROUNDS = 12;

interface DemoUser {
  email: string; name: string; password: string;
  role: 'admin' | 'owner' | 'viewer'; department: string;
}

export const DEMO_USERS: DemoUser[] = [
  { email: 'admin@strongroom.local', name: 'Alice Admin', password: 'Admin$ecret1!', role: 'admin', department: 'IT' },
  { email: 'owner1@strongroom.local', name: 'Bob Owner', password: 'Owner$ecret1!', role: 'owner', department: 'Legal' },
  { email: 'owner2@strongroom.local', name: 'Carol Owner', password: 'Owner$ecret2!', role: 'owner', department: 'Finance' },
  { email: 'viewer1@strongroom.local', name: 'Dave Viewer', password: 'Viewer$ecret1!', role: 'viewer', department: 'Sales' },
  { email: 'viewer2@strongroom.local', name: 'Eve Viewer', password: 'Viewer$ecret2!', role: 'viewer', department: 'Marketing' },
  { email: 'viewer3@strongroom.local', name: 'Frank Viewer', password: 'Viewer$ecret3!', role: 'viewer', department: 'Engineering' },
];

const SAMPLES = [
  ['Salary letter - A. Rao.txt', 'HR', 0], ['Customer contract - Acme.txt', 'Contracts', 0],
  ['Audit paper Q3.txt', 'Audit', 0], ['Partner drawing notes.txt', 'Engineering', 1],
  ['Budget forecast 2027.csv', 'Finance', 1], ['Regulator submission.txt', 'Audit', 1],
] as const;

export async function seed(): Promise<void> {
  const db = getDb();
  const count = (db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
  if (count > 0) {
    console.log('Users table already populated; skipping seed.');
    return;
  }

  const hashes: string[] = [];
  for (const u of DEMO_USERS) hashes.push(await bcrypt.hash(u.password, BCRYPT_ROUNDS));

  const insert = db.prepare(
    `INSERT INTO users (id, email, name, password_hash, role, department)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
  db.transaction(() => {
    DEMO_USERS.forEach((u, i) => {
      insert.run(uuidv4(), u.email.toLowerCase(), u.name, hashes[i]!, u.role, u.department);
    });
  })();
  console.log(`Seeded ${DEMO_USERS.length} demo users.`);

  // Sample documents (owned by the two owners) so judges see data.
  const owners = db.prepare("SELECT id, email FROM users WHERE role='owner' ORDER BY email").all() as { id: string; email: string }[];
  for (const [name, category, ownerIdx] of SAMPLES) {
    const owner = owners[ownerIdx]!;
    const body = Buffer.from(`CONFIDENTIAL DEMO DOCUMENT\n${name}\nOwned by ${owner.email}\n`);
    const storageKey = uuidv4();
    encryptAndStore(storageKey, body);
    db.prepare(`INSERT INTO documents (id, owner_id, name, category, storage_key, mime, size, sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(uuidv4(), owner.id, name, category, storageKey,
        name.endsWith('.csv') ? 'text/csv' : 'text/plain', body.length,
        crypto.createHash('sha256').update(body).digest('hex'));
  }
  console.log(`Seeded ${SAMPLES.length} sample documents.`);
}

if (require.main === module) {
  seed()
    .then(() => closeDb())
    .catch((err: unknown) => {
      console.error('Seed failed:', err);
      closeDb();
      process.exit(1);
    });
}