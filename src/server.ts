import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import path from 'path';

import { attachActor, csrfGuard } from './auth/middleware';
import { authRouter } from './routes/auth.routes';
import { docsRouter, downloadRouter } from './documents/documents.routes';
import { adminRouter } from './routes/admin.routes';
import { usersRouter } from './routes/users.routes';

export const app = express();

app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Static UI (public/ holds only index.html, style.css, app.js – no secrets, no uploads).
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(attachActor);
app.use(csrfGuard);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/auth', authRouter);
app.use('/api/documents', docsRouter);
app.use('/api/download', downloadRouter);
app.use('/api/admin', adminRouter);
app.use('/api/users', usersRouter);

// All document routes MUST call authorize() (Rule 1).

if (require.main === module) {
  if (process.env['NODE_ENV'] === 'production' && !process.env['SESSION_SECRET']) {
    throw new Error('SESSION_SECRET must be set in production');
  }

  void (async () => {
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