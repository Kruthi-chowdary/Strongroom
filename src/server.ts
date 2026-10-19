import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

// App is exported separately from the listen call so test suites can
// import it without binding to a port (Rule 8 – keep it small and testable).
export const app = express();

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

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/** Health check – public, no auth required, no document access. */
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// All document-handling routes will be added in later modules and MUST call
// authorize(actor, docId, action) from src/auth/authorize.ts (Rule 1).

// ---------------------------------------------------------------------------
// Entry point (only reached when this file is run directly, not imported)
// ---------------------------------------------------------------------------
if (require.main === module) {
  // getDb() initialises the database (schema, WAL, foreign-keys) on startup.
  require('./db').getDb();

  const PORT = Number(process.env['PORT'] ?? 3000);
  app.listen(PORT, () => {
    console.log(`Strongroom listening on port ${PORT}`);
  });
}
