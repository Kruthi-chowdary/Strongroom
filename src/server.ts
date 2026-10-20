import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

import { attachActor, csrfGuard } from './auth/middleware';
import { authRouter }             from './routes/auth.routes';

export const app = express();

// One reverse-proxy hop (Render) so req.ip is the real client IP.
app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Identity comes only from the server-side session cookie (Rule 3).
app.use(attachActor);
// CSRF defence for state-changing methods (Rule 4).
app.use(csrfGuard);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/auth', authRouter);

// Placeholder landing page until the React UI is built.
app.get('/', (_req, res) => {
  res.type('html').send(
    '<!doctype html><title>Strongroom</title>' +
    '<body style="background:#0b0b0d;color:#d9a441;font-family:monospace;padding:3rem">' +
    '<h1>Strongroom</h1><p>Every door guarded. Every opening logged.</p>' +
    '<p>API is live: <code>/health</code></p></body>'
  );
});

// All document routes (later) MUST call authorize() (Rule 1).

if (require.main === module) {
  if (process.env['NODE_ENV'] === 'production' && !process.env['SESSION_SECRET']) {
    throw new Error('SESSION_SECRET must be set in production');
  }

  void (async () => {
    // Open DB (runs schema), then optionally seed BEFORE accepting traffic.
    const { getDb } = await import('./db');
    getDb();
    if (process.env['SEED_DEMO'] === 'true') {
      const { seed } = await import('./seed');
      await seed();
    }
    const PORT = Number(process.env['PORT'] ?? 3000);
    app.listen(PORT, () => console.log(`Strongroom listening on port ${PORT}`));
  })();
}