/**
 * users.routes.ts – directory used by the Share dialog and the admin audit view.
 * Owners see only enabled non-admin users (never admins, never themselves).
 * Admins see everyone (they manage people).
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import { getDb } from '../db';
import { requireAuth, requireRole } from '../auth/middleware';

export const usersRouter = Router();

usersRouter.get('/', requireAuth, requireRole('owner', 'admin'), (req: Request, res: Response) => {
    const isAdmin = req.actor!.role === 'admin';
    const rows = getDb().prepare(`
    SELECT id, name, email, role, department, disabled FROM users
    WHERE (@all = 1 OR (role != 'admin' AND disabled = 0 AND id != @me))
    ORDER BY name
  `).all({ all: isAdmin ? 1 : 0, me: req.actor!.id });
    res.json({ items: rows });
});