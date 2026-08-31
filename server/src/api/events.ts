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
  // instead of crashing on a null `db.conn` in the query layer.
  router.use((_req, res, next) => {
    if (!db) {
      res.status(503).json({ error: 'Sink DB is unavailable.' });
      return;
    }
    next();
  });

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
