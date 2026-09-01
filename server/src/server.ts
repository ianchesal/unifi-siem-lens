import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { type RunnerDeps, runHourlyChecks, runRuleTriageBackfill } from './analysis/runner.js';
import { createAnalysisRequestsRouter } from './api/analysisRequests.js';
import { createEventsRouter } from './api/events.js';
import { createFindingsRouter } from './api/findings.js';
import type { Config } from './config.js';
import type { LensDb } from './db/lensDb.js';
import type { SinkDb } from './db/sinkDb.js';
import { createUnifiMcpClient } from './enrichment/unifiMcpClient.js';
import { registerAnalysisTools } from './mcp/tools.js';

export interface SchemaCheckResult {
  ok: boolean;
  missingColumns: string[];
}

export function createApp(
  sinkDb: SinkDb | null,
  lensDb: LensDb,
  runnerDeps: RunnerDeps | null,
  config: Config,
  schemaCheck: SchemaCheckResult | null = null
) {
  const app = express();
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 300,
      standardHeaders: true,
      legacyHeaders: false,
    })
  );
  app.use(express.json());

  const unifiMcp = createUnifiMcpClient(config.unifiMcpServerUrl);

  const mcpAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== `Bearer ${config.mcpSecret}`) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };

  app.get('/health', (_req, res) => {
    const schemaOk = !sinkDb || !schemaCheck || schemaCheck.ok;
    const status = sinkDb && schemaOk ? 'ok' : 'degraded';
    const body: {
      status: 'ok' | 'degraded';
      sinkDb: 'available' | 'unavailable';
      schema: 'ok' | 'mismatch' | 'unknown';
      missingColumns?: string[];
    } = {
      status,
      sinkDb: sinkDb ? 'available' : 'unavailable',
      schema: !sinkDb ? 'unknown' : schemaCheck ? (schemaCheck.ok ? 'ok' : 'mismatch') : 'unknown',
    };
    if (sinkDb && schemaCheck && !schemaCheck.ok) {
      body.missingColumns = schemaCheck.missingColumns;
    }
    res.json(body);
  });

  app.use('/api', createEventsRouter(sinkDb));
  app.use('/api', createFindingsRouter(lensDb));
  app.use('/api', createAnalysisRequestsRouter(lensDb, unifiMcp, sinkDb));

  app.post('/api/analysis/run', (_req, res) => {
    if (!runnerDeps) {
      res.status(503).json({ error: 'Sink DB is unavailable; analysis cannot run.' });
      return;
    }
    const result = runHourlyChecks(runnerDeps);
    res.json(result);
  });

  app.post('/api/admin/backfill-rule-triage', (_req, res) => {
    if (!runnerDeps) {
      res.status(503).json({ error: 'Sink DB is unavailable; backfill cannot run.' });
      return;
    }
    const result = runRuleTriageBackfill(runnerDeps);
    res.json(result);
  });

  app.post('/mcp', mcpAuthMiddleware, async (req, res, next) => {
    const mcpServer = new McpServer({ name: 'unifi-siem-lens', version: '0.1.0' });
    registerAnalysisTools(mcpServer, lensDb);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close();
      mcpServer.close();
    });
    try {
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      next(err);
    }
  });

  // Production: serve web's built static output (web/dist) as a single process.
  // Resolved relative to this module's *built* location (server/dist/server.js),
  // not its source location, so it works when running the compiled dist/index.js:
  // server/dist/server.js -> ../../web/dist -> web/dist.
  // Mounted AFTER all /api, /mcp, and /health routes above so it can never shadow
  // them. If web/dist doesn't exist (e.g. server-only development), no-op rather
  // than crash the server at boot.
  const webDistDir = join(fileURLToPath(new URL('.', import.meta.url)), '../../web/dist');
  if (existsSync(webDistDir)) {
    app.use(express.static(webDistDir));
    // Express 5 (path-to-regexp v6+) no longer accepts a bare '*' route pattern,
    // so use a path-less middleware instead — it matches every method/path.
    app.use((req, res, next) => {
      if (
        req.method !== 'GET' ||
        req.path.startsWith('/api') ||
        req.path.startsWith('/mcp') ||
        req.path.startsWith('/health')
      ) {
        next();
        return;
      }
      res.sendFile(join(webDistDir, 'index.html'));
    });
  }

  return app;
}
