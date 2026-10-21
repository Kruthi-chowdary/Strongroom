import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

// Path comes from an env var or a safe default, never from user input (Rule 6).
// Read lazily so tests can point at a temp database before the first connection.
function dbPath(): string {
  return process.env['DB_PATH'] ?? path.join(process.cwd(), 'strongroom.db');
}

let _db: Database.Database | undefined;

/** Singleton connection. Applies PRAGMAs and the idempotent schema on first call. */
export function getDb(): Database.Database {
  if (_db) return _db;

  _db = new Database(dbPath());
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  _db.pragma('busy_timeout = 5000');

  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  _db.exec(schema);
  return _db;
}

/** Closes the database (used in tests to release the file lock). */
export function closeDb(): void {
  _db?.close();
  _db = undefined;
}