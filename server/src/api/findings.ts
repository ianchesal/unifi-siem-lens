import { Router } from 'express';
import { z } from 'zod';
import { listFindings } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';

const StatusUpdate = z.object({
  status: z.enum(['acknowledged', 'dismissed']),
});

export function createFindingsRouter(lensDb: LensDb): Router {
  const router = Router();

  router.get('/findings', (req, res) => {
    const status = typeof req.query.status === 'string' ? req.query.status : undefined;
    res.json(listFindings(lensDb, status ? { status: status as never } : {}));
  });

  router.post('/findings/:id/status', (req, res) => {
    const parsed = StatusUpdate.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'status must be "acknowledged" or "dismissed"' });
      return;
    }
    const row = lensDb.conn
      .prepare('UPDATE findings SET status = ? WHERE id = ? RETURNING *')
      .get(parsed.data.status, Number(req.params.id));
    if (!row) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    res.json({ ...row, triggers: JSON.parse((row as { triggers: string }).triggers) });
  });

  return router;
}
