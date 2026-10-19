import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

// Database file lives outside the web root – never under public/ or dist/ (Rule 6).
// The path is resolved from an env var or a safe default; never from user input.
const DB_PATH = process.env['DB_PATH'] ?? path.join(process.cwd(), 'strongroom.db');

let _db: Database.Database | undefined;

/**
 * Returns the singleton database connection.
 * On first call it opens the file, applies security PRAGMAs and runs the schema.
 */
export function getDb(): Database.Database {
  if (_db) return _db;

  _db = new Database(DB_PATH);

  // Security PRAGMAs applied before any other statement:
  // - foreign_keys: enforces referential integrity (required for cascade deletes on sessions/grants).
  // - journal_mode WAL: allows concurrent reads without blocking writes.
  // - busy_timeout: avoids "database is locked" errors under load.
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  _db.pragma('busy_timeout = 5000');

  // Run schema DDL – IF NOT EXISTS guards make this idempotent.
  const schema = fs.readFileSync(
    path.join(__dirname, 'schema.sql'),
    'utf8'
  );
  _db.exec(schema);

  return _db;
}

/** Closes the database (used in tests to release the file lock). */
export function closeDb(): void {
  _db?.close();
  _db = undefined;
}
