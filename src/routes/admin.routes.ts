/**
 * admin.routes.ts – admin sees audit and activity, never document contents.
 * Every call goes through authorize(..., 'view_audit') (Rule 1).
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import { getDb } from '../db';
import { requireAuth, requireRole } from '../auth/middleware';
import { verifyChain } from '../audit/verify';

export const adminRouter = Router();
adminRouter.use(requireAuth, requireRole('admin'));

// GET /api/admin/audit?action=&outcome=&limit=
adminRouter.get('/audit', (req: Request, res: Response) => {
    const action = typeof req.query['action'] === 'string' ? req.query['action'].slice(0, 40) : '';
    const outcome = req.query['outcome'] === 'DENIED' || req.query['outcome'] === 'ALLOWED' ? req.query['outcome'] : '';
    const limit = Math.min(Math.max(parseInt(String(req.query['limit'] ?? '100'), 10) || 100, 1), 500);
    const rows = getDb().prepare(`
    SELECT id, ts, actor_id, action, document_id, target_user_id, outcome, ip, detail_json, hash
    FROM audit_log
    WHERE (@action = '' OR action = @action) AND (@outcome = '' OR outcome = @outcome)
    ORDER BY id DESC LIMIT @limit
  `).all({ action, outcome, limit });
    res.json({ items: rows });
});

// GET /api/admin/audit/verify
adminRouter.get('/audit/verify', (_req: Request, res: Response) => {
    res.json(verifyChain(getDb()));
});

// GET /api/admin/notable – simple tripwires
adminRouter.get('/notable', (_req: Request, res: Response) => {
    const db = getDb();
    const since = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const repeatedDenials = db.prepare(`
    SELECT actor_id, COUNT(*) AS denials FROM audit_log
    WHERE outcome = 'DENIED' AND ts >= ? AND actor_id IS NOT NULL
    GROUP BY actor_id HAVING COUNT(*) >= 5
  `).all(since);
    const disabledUserAttempts = db.prepare(`
    SELECT a.id, a.ts, a.actor_id, a.action FROM audit_log a
    JOIN users u ON u.id = a.actor_id
    WHERE u.disabled = 1 AND a.outcome = 'DENIED' ORDER BY a.id DESC LIMIT 50
  `).all();
    const recentGrantsRevokes = db.prepare(`
    SELECT id, ts, actor_id, action, document_id, target_user_id FROM audit_log
    WHERE action IN ('GRANT','REVOKE') ORDER BY id DESC LIMIT 50
  `).all();
    res.json({ repeatedDenials, disabledUserAttempts, recentGrantsRevokes });
});