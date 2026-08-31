import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { submitAnalysis } from '../../src/db/analysisRequestsStore.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import { createAnalysisRequestsRouter } from '../../src/api/analysisRequests.js';

describe('analysis-requests API', () => {
  it('POST /findings/:id/analyze creates a pending request; GET /analysis-requests lists it', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));

    const app = express();
    app.use(express.json());
    app.use('/api', createAnalysisRequestsRouter(lensDb));

    const analyzeRes = await request(app).post(`/api/findings/${finding.id}/analyze`);
    expect(analyzeRes.status).toBe(200);
    expect(analyzeRes.body.status).toBe('pending');
    expect(analyzeRes.body.finding_id).toBe(finding.id);

    const listRes = await request(app).get(`/api/analysis-requests?findingId=${finding.id}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body).toHaveLength(1);
    expect(listRes.body[0].id).toBe(analyzeRes.body.id);
  });

  it('GET /analysis-requests?findingId= includes answered requests, not just pending ones', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '9.9.9.9'));

    const app = express();
    app.use(express.json());
    app.use('/api', createAnalysisRequestsRouter(lensDb));

    const analyzeRes = await request(app).post(`/api/findings/${finding.id}/analyze`);
    expect(analyzeRes.status).toBe(200);
    const requestId = analyzeRes.body.id;

    submitAnalysis(lensDb, requestId, 'quarantine the host', 'high', new Date().toISOString());

    const listRes = await request(app).get(`/api/analysis-requests?findingId=${finding.id}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body).toHaveLength(1);
    expect(listRes.body[0].id).toBe(requestId);
    expect(listRes.body[0].status).toBe('answered');
    expect(listRes.body[0].recommendation).toBe('quarantine the host');
    expect(listRes.body[0].risk_level).toBe('high');

    // Unfiltered listing (no findingId) must remain pending-only per existing behavior.
    const unfilteredRes = await request(app).get('/api/analysis-requests');
    expect(unfilteredRes.status).toBe(200);
    expect(unfilteredRes.body).toHaveLength(0);
  });
});
