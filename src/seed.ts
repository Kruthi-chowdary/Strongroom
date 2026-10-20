/**
 * seed.ts – demo users with FIXED passwords so the README credentials work.
 * Runs only when called explicitly (server boot with SEED_DEMO=true, or
 * `npm run seed`). Skips if users already exist. Demo data only; the
 * passwords are public by design and the site holds no real data.
 */

import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { getDb, closeDb } from './db';

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