import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { signatureKey } from '../../src/analysis/newEntity.js';
import { submitAnalysis } from '../../src/db/analysisRequestsStore.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import type { SinkDb } from '../../src/db/sinkDb.js';
import { createAnalysisRequestsRouter } from '../../src/api/analysisRequests.js';
import { createUnifiMcpClient } from '../../src/enrichment/unifiMcpClient.js';

const EVENTS_SCHEMA = `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
  category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
  dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
  signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`;

function makeSinkDb(): SinkDb {
  const conn = new DatabaseSync(':memory:');
  conn.exec(EVENTS_SCHEMA);
  return { conn };
}

describe('analysis-requests API', () => {
  it('POST /findings/:id/analyze creates a pending request; GET /analysis-requests lists it', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));

    const app = express();
    app.use(express.json());
    app.use('/api', createAnalysisRequestsRouter(lensDb, createUnifiMcpClient(null), null));

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
    app.use('/api', createAnalysisRequestsRouter(lensDb, createUnifiMcpClient(null), null));

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

  it('includes recent raw events matching the finding entity when sinkDb has rows (source_ip)', async () => {
    const lensDb = openLensDb(':memory:');
    const sinkDb = makeSinkDb();
    sinkDb.conn
      .prepare(
        `INSERT INTO events (received_at, category, source_ip, signature, raw)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run('2026-08-30T00:00:00Z', 'firewall', '5.5.5.5', 'blocked-port-scan', '{}');
    sinkDb.conn
      .prepare(
        `INSERT INTO events (received_at, category, source_ip, signature, raw)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run('2026-08-30T00:00:01Z', 'firewall', '6.6.6.6', 'other', '{}');

    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '5.5.5.5'));

    const app = express();
    app.use(express.json());
    app.use('/api', createAnalysisRequestsRouter(lensDb, createUnifiMcpClient(null), sinkDb));

    const analyzeRes = await request(app).post(`/api/findings/${finding.id}/analyze`);
    expect(analyzeRes.status).toBe(200);

    const stored = lensDb.conn
      .prepare('SELECT context FROM analysis_requests WHERE id = ?')
      .get(analyzeRes.body.id) as { context: string };
    const context = JSON.parse(stored.context);
    expect(context.recentEvents).toHaveLength(1);
    expect(context.recentEvents[0].source_ip).toBe('5.5.5.5');
  });

  it('includes recent raw events and baseline history for a signature finding', async () => {
    const lensDb = openLensDb(':memory:');
    const sinkDb = makeSinkDb();
    sinkDb.conn
      .prepare(
        `INSERT INTO events (received_at, category, signature, raw)
         VALUES (?, ?, ?, ?)`
      )
      .run('2026-08-30T00:00:00Z', 'firewall', 'weird-sig', '{}');
    lensDb.conn
      .prepare('INSERT INTO baselines (category, signature, day, count) VALUES (?, ?, ?, ?)')
      .run('firewall', 'weird-sig', '2026-08-29', 4);

    const key = signatureKey('firewall', 'weird-sig');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'new_signature', 't0', 'signature', key));

    const app = express();
    app.use(express.json());
    app.use('/api', createAnalysisRequestsRouter(lensDb, createUnifiMcpClient(null), sinkDb));

    const analyzeRes = await request(app).post(`/api/findings/${finding.id}/analyze`);
    expect(analyzeRes.status).toBe(200);

    const stored = lensDb.conn
      .prepare('SELECT context FROM analysis_requests WHERE id = ?')
      .get(analyzeRes.body.id) as { context: string };
    const context = JSON.parse(stored.context);
    expect(context.recentEvents).toHaveLength(1);
    expect(context.recentEvents[0].signature).toBe('weird-sig');
    expect(context.baselineHistory).toHaveLength(1);
    expect(context.baselineHistory[0].count).toBe(4);
  });

  it('degrades gracefully with sinkDb=null: no recentEvents, request still created', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '7.7.7.7'));

    const app = express();
    app.use(express.json());
    app.use('/api', createAnalysisRequestsRouter(lensDb, createUnifiMcpClient(null), null));

    const analyzeRes = await request(app).post(`/api/findings/${finding.id}/analyze`);
    expect(analyzeRes.status).toBe(200);

    const stored = lensDb.conn
      .prepare('SELECT context FROM analysis_requests WHERE id = ?')
      .get(analyzeRes.body.id) as { context: string };
    const context = JSON.parse(stored.context);
    expect(context.recentEvents).toEqual([]);
  });
});
