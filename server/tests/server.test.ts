import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { openLensDb } from '../src/db/lensDb.js';
import type { SinkDb } from '../src/db/sinkDb.js';
import { createApp } from '../src/server.js';

const baseConfig = {
  port: 3002,
  host: '127.0.0.1',
  sinkDbPath: '/dev/null',
  lensDbPath: ':memory:',
  lanCidrs: [],
  unifiMcpServerUrl: null,
  logLevel: 'error' as const,
  mcpSecret: 'test-secret',
};

const fakeSinkDb = {} as SinkDb;

describe('createApp /health', () => {
  it('reports ok when sinkDb is present and schema matches', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(fakeSinkDb, lensDb, null, baseConfig, { ok: true, missingColumns: [] });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.sinkDb).toBe('available');
    expect(res.body.schema).toBe('ok');
  });

  it('reports degraded with a distinguishable "schema" mismatch when sinkDb is present but schema check failed', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(fakeSinkDb, lensDb, null, baseConfig, {
      ok: false,
      missingColumns: ['signature'],
    });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('degraded');
    expect(res.body.sinkDb).toBe('available');
    expect(res.body.schema).toBe('mismatch');
    expect(res.body.missingColumns).toEqual(['signature']);
  });

  it('reports degraded with sinkDb unavailable when sinkDb is null, distinct from a schema mismatch', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(null, lensDb, null, baseConfig, null);
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('degraded');
    expect(res.body.sinkDb).toBe('unavailable');
    expect(res.body.schema).toBe('unknown');
    expect(res.body.missingColumns).toBeUndefined();
  });
});

describe('createApp /mcp auth', () => {
  it('rejects requests with no Authorization header', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(null, lensDb, null, baseConfig, null);
    const res = await request(app).post('/mcp').send({});
    expect(res.status).toBe(401);
  });

  it('rejects requests with the wrong bearer token', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(null, lensDb, null, baseConfig, null);
    const res = await request(app).post('/mcp').set('Authorization', 'Bearer wrong').send({});
    expect(res.status).toBe(401);
  });
});

describe('createApp /api/admin/backfill-rule-triage', () => {
  it('returns 503 when the sink DB is unavailable (runnerDeps null)', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(null, lensDb, null, baseConfig, null);
    const res = await request(app).post('/api/admin/backfill-rule-triage');
    expect(res.status).toBe(503);
  });

  it('runs the backfill and returns its result shape when the sink DB is available', async () => {
    const lensDb = openLensDb(':memory:');
    const runnerDeps = {
      sinkDb: fakeSinkDb,
      lensDb,
      lanCidrs: [],
      trustedAdminNames: [],
      safeSignaturePrefixes: ['ET DROP'],
    };
    const app = createApp(fakeSinkDb, lensDb, runnerDeps, baseConfig, { ok: true, missingColumns: [] });
    const res = await request(app).post('/api/admin/backfill-rule-triage');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      checked: 0,
      dismissed: 0,
      byRule: {
        admin_login: 0,
        operational_noise: 0,
        reputation_blocklist: 0,
        homelab_service_egress: 0,
      },
    });
  });
});

describe('createApp route precedence', () => {
  it('does not let the static/SPA fallback swallow /api or /health routes', async () => {
    const lensDb = openLensDb(':memory:');
    const app = createApp(null, lensDb, null, baseConfig, null);

    const health = await request(app).get('/health');
    expect(health.status).toBe(200);

    const findings = await request(app).get('/api/findings');
    expect(findings.status).toBe(200);
    expect(Array.isArray(findings.body)).toBe(true);
  });
});
