import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import { attachActor, csrfGuard } from './auth/middleware';
import { authRouter }             from './routes/auth.routes';

// App is exported separately from the listen call so test suites can
// import it without binding to a port (Rule 8 – keep it small and testable).
export const app = express();

// Trust exactly one reverse-proxy hop so req.ip is the real client IP.
// Required for express-rate-limit to key on the actual IP (Rule 8).
app.set('trust proxy', 1);

// helmet sets secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
app.use(helmet());

// Restrict JSON body size to 1 MB to mitigate DoS via large payloads.
app.use(express.json({ limit: '1mb' }));

// cookie-parser reads the httpOnly session cookie.
// SESSION_SECRET signs the cookie; absence in production is a startup error.
const SESSION_SECRET = process.env['SESSION_SECRET'];
if (!SESSION_SECRET && process.env['NODE_ENV'] === 'production') {
  throw new Error('SESSION_SECRET must be set in production');
}
app.use(cookieParser(SESSION_SECRET));

// attachActor resolves the "sid" cookie to an Actor (or null) on every
// request.  Identity is NEVER read from body, query or Authorization header
// (Rule 3).
app.use(attachActor);

// csrfGuard: for state-changing methods, require X-Requested-With and
// validate the Origin header (Rule 4 / CSRF defence-in-depth).
app.use(csrfGuard);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/** Health check – public, no auth required, no document access. */
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// Auth routes: login, logout, me.
app.use('/api/auth', authRouter);

// All document-handling routes will be added in later modules and MUST call
// authorize(actor, docId, action) from src/auth/authorize.ts (Rule 1).

// ---------------------------------------------------------------------------
// Entry point (only reached when this file is run directly, not imported)
// ---------------------------------------------------------------------------
if (require.main === module) {
  // getDb() initialises the database (schema, WAL, foreign-keys) on startup.
  const { getDb } = require('./db') as typeof import('./db');
  getDb();

  // Auto-seed on boot when SEED_DEMO=true and the users table is empty.
  if (process.env['SEED_DEMO'] === 'true') {
    const db = (require('./db') as typeof import('./db')).getDb();
    const count = (db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
    if (count === 0) {
      // Dynamic import avoids bundling seed logic into the prod binary.
      void import('./seed');
    }
  }

  const PORT = Number(process.env['PORT'] ?? 3000);
  app.listen(PORT, () => {
    console.log(`Strongroom listening on port ${PORT}`);
  });
}
