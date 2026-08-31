import express from 'express';
import { type RunnerDeps, runHourlyChecks } from './analysis/runner.js';
import { createEventsRouter } from './api/events.js';
import { createFindingsRouter } from './api/findings.js';
import type { Config } from './config.js';
import type { LensDb } from './db/lensDb.js';
import type { SinkDb } from './db/sinkDb.js';

export function createApp(
  sinkDb: SinkDb | null,
  lensDb: LensDb,
  runnerDeps: RunnerDeps | null,
  _config: Config
) {
  const app = express();
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.json({ status: sinkDb ? 'ok' : 'degraded', sinkDb: sinkDb ? 'connected' : 'unavailable' });
  });

  app.use('/api', createEventsRouter(sinkDb));
  app.use('/api', createFindingsRouter(lensDb));

  app.post('/api/analysis/run', (_req, res) => {
    if (!runnerDeps) {
      res.status(503).json({ error: 'Sink DB is unavailable; analysis cannot run.' });
      return;
    }
    const result = runHourlyChecks(runnerDeps);
    res.json(result);
  });

  return app;
}
