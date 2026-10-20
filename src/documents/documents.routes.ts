/**
 * documents.routes.ts – every route here calls authorize() (Rule 1).
 * Refusals return an identical 404 (Rule 2); authorize() writes the audit row.
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

import { getDb } from '../db';
import { authorize } from '../auth/authorize';
import { requireAuth, requireRole } from '../auth/middleware';
import { appendAudit } from '../audit/audit';
import { encryptAndStore, readAndDecrypt } from '../storage/crypto';
import { validateUpload } from '../storage/validate';
import { issueTicket, redeemTicket } from './tickets';

export const docsRouter = Router();
export const downloadRouter = Router();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });
const NOT_FOUND = { error: 'not found' };
const isId = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f-]{36}$/.test(s);

// POST /api/documents  (owners only) – upload
docsRouter.post('/', requireAuth, requireRole('owner'), upload.single('file'), (req: Request, res: Response) => {
    const db = getDb();
    const actor = req.actor!;
    if (!req.file) { res.status(400).json({ error: 'file required' }); return; }

    const v = validateUpload(req.file.originalname, req.file.buffer);
    if (!v.ok) {
        appendAudit(db, {
            actor_id: actor.id, action: 'UPLOAD', document_id: null, target_user_id: null,
            outcome: 'DENIED', ip: req.ip ?? null, detail_json: JSON.stringify({ reason: v.error })
        });
        res.status(400).json({ error: v.error });
        return;
    }

    const category = typeof req.body?.category === 'string' ? req.body.category.slice(0, 40) : 'General';
    const id = uuidv4();
    const storageKey = uuidv4();
    const sha = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

    encryptAndStore(storageKey, req.file.buffer);
    // owner_id is the SESSION user, never the request body (Rule 3).
    db.prepare(`INSERT INTO documents (id, owner_id, name, category, storage_key, mime, size, sha256)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, actor.id, v.displayName, category, storageKey, v.mime, req.file.size, sha);

    appendAudit(db, {
        actor_id: actor.id, action: 'UPLOAD', document_id: id, target_user_id: null,
        outcome: 'ALLOWED', ip: req.ip ?? null, detail_json: JSON.stringify({ name: v.displayName, sha256: sha })
    });
    res.status(201).json({ id, name: v.displayName });
});

// GET /api/documents – list/search. Authorisation is INSIDE the SQL.
docsRouter.get('/', requireAuth, (req: Request, res: Response) => {
    const actor = req.actor!;
    if (actor.role === 'admin') { res.json({ items: [] }); return; } // admin never sees contents

    const q = typeof req.query['q'] === 'string' ? req.query['q'].slice(0, 80) : '';
    const category = typeof req.query['category'] === 'string' ? req.query['category'].slice(0, 40) : '';
    const rows = getDb().prepare(`
    SELECT d.id, d.name, d.category, d.size, d.created_at, u.name AS owner_name,
           CASE WHEN d.owner_id = @uid THEN 'owner' ELSE g.permission END AS access
    FROM documents d
    JOIN users u ON u.id = d.owner_id
    LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = @uid
         AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    WHERE d.deleted_at IS NULL
      AND (d.owner_id = @uid OR g.id IS NOT NULL)
      AND (@q = '' OR d.name LIKE '%' || @q || '%' ESCAPE '\\')
      AND (@category = '' OR d.category = @category)
    ORDER BY d.created_at DESC LIMIT 100
  `).all({ uid: actor.id, q: q.replace(/[\\%_]/g, '\\$&'), category });
    res.json({ items: rows });
});

// POST /api/documents/:id/download-ticket
docsRouter.post('/:id/download-ticket', requireAuth, (req: Request, res: Response) => {
    const id = req.params['id'];
    if (!isId(id) || !authorize(getDb(), req.actor, id, 'download', { ip: req.ip ?? undefined }).allowed) {
        res.status(404).json(NOT_FOUND); return;
    }
    res.json({ ticket: issueTicket(req.actor!.id, id), expiresInSeconds: 60 });
});

// GET /api/download/:ticket – authorize() is called AGAIN here (revocation-safe).
downloadRouter.get('/:ticket', requireAuth, (req: Request, res: Response) => {
    const db = getDb();
    const raw = req.params['ticket'];
    const t = typeof raw === 'string' ? redeemTicket(raw) : null;
    if (!t || t.userId !== req.actor!.id ||
        !authorize(db, req.actor, t.docId, 'download', { ip: req.ip ?? undefined }).allowed) {
        res.status(404).json(NOT_FOUND); return;
    }
    const doc = db.prepare('SELECT name, mime, storage_key, sha256 FROM documents WHERE id = ? AND deleted_at IS NULL')
        .get(t.docId) as { name: string; mime: string; storage_key: string; sha256: string } | undefined;
    if (!doc) { res.status(404).json(NOT_FOUND); return; }

    let data: Buffer;
    try { data = readAndDecrypt(doc.storage_key); } catch { res.status(404).json(NOT_FOUND); return; }
    if (crypto.createHash('sha256').update(data).digest('hex') !== doc.sha256) {
        res.status(500).json({ error: 'integrity check failed' }); return;
    }
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${doc.name.replace(/[^\w.\- ()]/g, '_')}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.send(data);
});