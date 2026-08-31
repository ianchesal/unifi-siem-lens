import express from 'express';
import { createEventsRouter } from './api/events.js';
import type { SinkDb } from './db/sinkDb.js';

export function createApp(sinkDb: SinkDb) {
  const app = express();
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.use('/api', createEventsRouter(sinkDb));

  return app;
}
