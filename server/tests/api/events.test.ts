import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { openSinkDb } from '../../src/db/sinkDb.js';
import { createEventsRouter } from '../../src/api/events.js';

describe('GET /api/events and /api/stats/*', () => {
  const db = openSinkDb('tests/fixtures/events.db');
  const app = express();
  app.use('/api', createEventsRouter(db));

  it('GET /api/events returns 200 and a JSON array', async () => {
    const res = await request(app).get('/api/events');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('GET /api/stats/top-signatures returns 200 and a JSON array', async () => {
    const res = await request(app).get('/api/stats/top-signatures');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});
