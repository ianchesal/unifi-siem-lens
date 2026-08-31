import { Router } from 'express';
import type { SinkDb } from '../db/sinkDb.js';
import {
  eventsOverTime,
  listEvents,
  severityDistribution,
  topSignatures,
  topSourceIps,
} from '../db/sinkQueries.js';

export function createEventsRouter(db: SinkDb): Router {
  const router = Router();

  router.get('/events', (req, res) => {
    const since = typeof req.query.since === 'string' ? req.query.since : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    res.json(listEvents(db, { since, limit }));
  });

  router.get('/stats/events-over-time', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 30;
    res.json(eventsOverTime(db, { sinceDays }));
  });

  router.get('/stats/top-signatures', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    const limit = req.query.limit ? Number(req.query.limit) : 10;
    res.json(topSignatures(db, { sinceDays, limit }));
  });

  router.get('/stats/top-source-ips', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    const limit = req.query.limit ? Number(req.query.limit) : 10;
    res.json(topSourceIps(db, { sinceDays, limit }));
  });

  router.get('/stats/severity-distribution', (req, res) => {
    const sinceDays = req.query.sinceDays ? Number(req.query.sinceDays) : 7;
    res.json(severityDistribution(db, { sinceDays }));
  });

  return router;
}
