/**
 * seed.ts – populates the database with demo users for development.
 *
 * Passwords are hashed with bcrypt (cost 12, OWASP-acceptable for a dev scaffold).
 * Demo credentials are printed to STDOUT so developers know what to log in with.
 * This script must NEVER run in production (guarded below).
 *
 * NOTE: For production deployments, swap bcryptjs for argon2id (native build
 * tools required: Python + C++ compiler). The hash column stores the algorithm
 * prefix so migration is seamless.
 */

import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { getDb, closeDb } from './db';

if (process.env['NODE_ENV'] === 'production') {
  console.error('seed.ts must not run in production');
  process.exit(1);
}

/** bcrypt cost factor – OWASP recommends ≥10; we use 12 for the scaffold. */
const BCRYPT_ROUNDS = 12;

interface DemoUser {
  id: string;
  email: string;
  name: string;
  password: string;
  role: 'admin' | 'owner' | 'viewer';
  department: string;
}

const DEMO_USERS: DemoUser[] = [
  // 1 admin
  {
    id: uuidv4(),
    email: 'admin@strongroom.local',
    name: 'Alice Admin',
    password: 'Admin$ecret1!',
    role: 'admin',
    department: 'IT',
  },
  // 2 owners
  {
    id: uuidv4(),
    email: 'owner1@strongroom.local',
    name: 'Bob Owner',
    password: 'Owner$ecret1!',
    role: 'owner',
    department: 'Legal',
  },
  {
    id: uuidv4(),
    email: 'owner2@strongroom.local',
    name: 'Carol Owner',
    password: 'Owner$ecret2!',
    role: 'owner',
    department: 'Finance',
  },
  // 3 viewers
  {
    id: uuidv4(),
    email: 'viewer1@strongroom.local',
    name: 'Dave Viewer',
    password: 'Viewer$ecret1!',
    role: 'viewer',
    department: 'Sales',
  },
  {
    id: uuidv4(),
    email: 'viewer2@strongroom.local',
    name: 'Eve Viewer',
    password: 'Viewer$ecret2!',
    role: 'viewer',
    department: 'Marketing',
  },
  {
    id: uuidv4(),
    email: 'viewer3@strongroom.local',
    name: 'Frank Viewer',
    password: 'Viewer$ecret3!',
    role: 'viewer',
    department: 'Engineering',
  },
];

async function seed(): Promise<void> {
  const db = getDb();

  const insert = db.prepare<[string, string, string, string, string, string]>(`
    INSERT INTO users (id, email, name, password_hash, role, department)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT (email) DO NOTHING
  `);

  console.log('\n=== Strongroom demo seed ===\n');
  console.log('email'.padEnd(36), 'role'.padEnd(8), 'password');
  console.log('-'.repeat(68));

  // Hash all passwords up-front (async; bcryptjs rounds = 12).
  // Never store or log plain-text passwords in production (Rule 5).
  const hashes: string[] = [];
  for (const u of DEMO_USERS) {
    hashes.push(await bcrypt.hash(u.password, BCRYPT_ROUNDS));
  }

  // Insert inside a single transaction for atomicity.
  const insertAll = db.transaction(() => {
    for (let i = 0; i < DEMO_USERS.length; i++) {
      const u = DEMO_USERS[i]!;
      const h = hashes[i]!;
      insert.run(u.id, u.email, u.name, h, u.role, u.department);
      // Safe to print demo passwords to console – development only.
      console.log(u.email.padEnd(36), u.role.padEnd(8), u.password);
    }
  });

  insertAll();

  console.log('\nSeed complete.\n');
  closeDb();
}

seed().catch((err: unknown) => {
  console.error('Seed failed:', err);
  closeDb();
  process.exit(1);
});
