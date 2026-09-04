import { Router } from 'express';
import { splitSignatureKey } from '../analysis/newEntity.js';
import {
  createAnalysisRequest,
  getAnalysisRequestsForFinding,
  getPendingAnalysisRequests,
} from '../db/analysisRequestsStore.js';
import { listFindings } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import { eventsForSignature, eventsForSourceIp, type StoredEvent } from '../db/sinkQueries.js';
import {
  annotateHomelabDestinations,
  type HomelabRegistry,
} from '../enrichment/homelabServices.js';
import type { UnifiMcpClient } from '../enrichment/unifiMcpClient.js';

const RECENT_EVENTS_LIMIT = 20;
const BASELINE_HISTORY_LIMIT = 14;

interface BaselineRow {
  day: string;
  count: number;
}

function getBaselineHistory(lensDb: LensDb, category: string, signature: string): BaselineRow[] {
  return lensDb.conn
    .prepare(
      `SELECT day, count FROM baselines WHERE category = ? AND signature = ?
       ORDER BY day DESC LIMIT ?`
    )
    .all(category, signature, BASELINE_HISTORY_LIMIT) as unknown as BaselineRow[];
}

export function createAnalysisRequestsRouter(
  lensDb: LensDb,
  unifiMcp: UnifiMcpClient,
  sinkDb: SinkDb | null,
  homelabServices: HomelabRegistry = {}
): Router {
  const router = Router();

  router.post('/findings/:id/analyze', async (req, res) => {
    const findingId = Number(req.params.id);
    const finding = listFindings(lensDb).find((f) => f.id === findingId);
    if (!finding) {
      res.status(404).json({ error: 'finding not found' });
      return;
    }
    const knownClient =
      finding.entity_type === 'source_ip' ? await unifiMcp.resolveClient(finding.entity_key) : null;
    const firewallSummary = await unifiMcp.getFirewallSummary();

    let recentEvents: StoredEvent[] = [];
    let baselineHistory: BaselineRow[] = [];
    if (sinkDb) {
      if (finding.entity_type === 'source_ip') {
        recentEvents = eventsForSourceIp(sinkDb, finding.entity_key, RECENT_EVENTS_LIMIT);
      } else {
        const { category, signature } = splitSignatureKey(finding.entity_key);
        recentEvents = eventsForSignature(sinkDb, category, signature, RECENT_EVENTS_LIMIT);
        baselineHistory = getBaselineHistory(lensDb, category, signature);
      }
    }

    const request = createAnalysisRequest(
      lensDb,
      findingId,
      {
        finding,
        knownClient,
        firewallSummary,
        recentEvents: annotateHomelabDestinations(recentEvents, homelabServices),
        baselineHistory,
      },
      new Date().toISOString()
    );
    res.json(request);
  });

  router.get('/analysis-requests', (req, res) => {
    const findingId = req.query.findingId ? Number(req.query.findingId) : undefined;
    if (findingId !== undefined) {
      res.json(getAnalysisRequestsForFinding(lensDb, findingId));
      return;
    }
    res.json(getPendingAnalysisRequests(lensDb));
  });

  return router;
}
