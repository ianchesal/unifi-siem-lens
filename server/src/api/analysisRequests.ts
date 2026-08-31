import { Router } from 'express';
import { createAnalysisRequest, getPendingAnalysisRequests } from '../db/analysisRequestsStore.js';
import { listFindings } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';

export function createAnalysisRequestsRouter(lensDb: LensDb): Router {
  const router = Router();

  router.post('/findings/:id/analyze', (req, res) => {
    const findingId = Number(req.params.id);
    const finding = listFindings(lensDb).find((f) => f.id === findingId);
    if (!finding) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    const request = createAnalysisRequest(lensDb, findingId, { finding }, new Date().toISOString());
    res.json(request);
  });

  router.get('/analysis-requests', (req, res) => {
    const findingId = req.query.findingId ? Number(req.query.findingId) : undefined;
    const pending = getPendingAnalysisRequests(lensDb);
    res.json(findingId ? pending.filter((r) => r.finding_id === findingId) : pending);
  });

  return router;
}
