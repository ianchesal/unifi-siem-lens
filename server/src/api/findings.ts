import { Router } from 'express';
import { z } from 'zod';
import { splitSignatureKey } from '../analysis/newEntity.js';
import { listFindings, setFindingStatus } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import { eventsForSignature, eventsForSourceIp } from '../db/sinkQueries.js';

const StatusUpdate = z.object({
  status: z.enum(['acknowledged', 'dismissed']),
});

export function createFindingsRouter(lensDb: LensDb, sinkDb: SinkDb | null): Router {
  const router = Router();

  router.get('/findings', (req, res) => {
    const status = typeof req.query.status === 'string' ? req.query.status : undefined;
    // Default view excludes dismissed/resolved findings — with new_source_ip a
    // permanent, never-auto-resolving trigger, an unfiltered list only grows.
    // Callers that explicitly want dismissed/resolved rows can ask via ?status=,
    // or ?status=all for every finding regardless of status.
    res.json(
      listFindings(
        lensDb,
        status === 'all'
          ? {}
          : status
            ? { status: status as never }
            : { excludeStatuses: ['dismissed', 'resolved'] }
      )
    );
  });

  router.post('/findings/:id/status', (req, res) => {
    const parsed = StatusUpdate.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'status must be "acknowledged" or "dismissed"' });
      return;
    }
    const updated = setFindingStatus(lensDb, Number(req.params.id), parsed.data.status);
    if (!updated) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    res.json(updated);
  });

  router.get('/findings/:id/events', (req, res) => {
    const finding = listFindings(lensDb, {}).find((f) => f.id === Number(req.params.id));
    if (!finding) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    if (!sinkDb) {
      res.status(503).json({ error: 'Sink DB is unavailable.' });
      return;
    }
    if (finding.entity_type === 'source_ip') {
      res.json(eventsForSourceIp(sinkDb, finding.entity_key));
      return;
    }
    const { category, signature } = splitSignatureKey(finding.entity_key);
    res.json(eventsForSignature(sinkDb, category, signature));
  });

  return router;
}
