import { Router } from 'express';
import type { SinkDb } from '../db/sinkDb.js';
import {
  eventsOverTime,
  listEvents,
  severityDistribution,
  topSignatures,
  topSourceIps,
} from '../db/sinkQueries.js';

export function createEventsRouter(db: SinkDb | null): Router {
  const router = Router();

  // Sink DB failed to open at boot (e.g. missing file) — serve a clear 503
  // instead of crashing on a null `db.conn` in the query layer. Scoped to just the
  // paths this router owns (not a path-less `use()`) so it doesn't intercept sibling
  // /api routes — e.g. /api/analysis/run, which doesn't touch sinkDb at all — mounted
  // alongside this router under the same /api prefix.
  router.use(
    [
      '/events',
      '/stats/events-over-time',
      '/stats/top-signatures',
      '/stats/top-source-ips',
      '/stats/severity-distribution',
    ],
    (_req, res, next) => {
      if (!db) {
        res.status(503).json({ error: 'Sink DB is unavailable.' });
        return;
      }
      next();
    }
  );

  router.get('/events', (req, res) => {
    const since = typeof req.query.since === 'string' ? req.query.since : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    res.json(listEvents(db as SinkDb, { since, limit }));
  });

  router.get('/stats/events-over-time', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 30;
    res.json(eventsOverTime(db as SinkDb, { sinceDays }));
  });

  router.get('/stats/top-signatures', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    const limit = req.query.limit ? Number(req.query.limit) : 10;
    res.json(topSignatures(db as SinkDb, { sinceDays, limit }));
  });

  router.get('/stats/top-source-ips', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    const limit = req.query.limit ? Number(req.query.limit) : 10;
    res.json(topSourceIps(db as SinkDb, { sinceDays, limit }));
  });

  router.get('/stats/severity-distribution', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    res.json(severityDistribution(db as SinkDb, { sinceDays }));
  });

  return router;
}
