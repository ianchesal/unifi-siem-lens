import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import { createFindingsRouter } from '../../src/api/findings.js';

describe('findings API', () => {
  it('GET /api/findings lists findings, POST /:id/status updates status', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb));

    const listRes = await request(app).get('/api/findings');
    expect(listRes.status).toBe(200);
    expect(listRes.body).toHaveLength(1);

    const updateRes = await request(app)
      .post(`/api/findings/${finding.id}/status`)
      .send({ status: 'acknowledged' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.status).toBe('acknowledged');
  });

  it('excludes dismissed/resolved findings by default, but includes them when explicitly requested', async () => {
    const lensDb = openLensDb(':memory:');
    const active = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.1.1.1'));
    const dismissed = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '2.2.2.2'));

    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb));

    await request(app).post(`/api/findings/${dismissed.id}/status`).send({ status: 'dismissed' });

    const defaultRes = await request(app).get('/api/findings');
    expect(defaultRes.status).toBe(200);
    const defaultIds = defaultRes.body.map((f: { id: number }) => f.id);
    expect(defaultIds).toContain(active.id);
    expect(defaultIds).not.toContain(dismissed.id);

    const explicitRes = await request(app).get('/api/findings?status=dismissed');
    expect(explicitRes.status).toBe(200);
    const explicitIds = explicitRes.body.map((f: { id: number }) => f.id);
    expect(explicitIds).toEqual([dismissed.id]);
  });

  it('rejects an invalid status', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const app = express();
    app.use(express.json());
    app.use('/api', createFindingsRouter(lensDb));

    const res = await request(app).post(`/api/findings/${finding.id}/status`).send({ status: 'bogus' });
    expect(res.status).toBe(400);
  });
});
