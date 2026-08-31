import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { type RunnerDeps, runHourlyChecks } from './analysis/runner.js';
import { createAnalysisRequestsRouter } from './api/analysisRequests.js';
import { createEventsRouter } from './api/events.js';
import { createFindingsRouter } from './api/findings.js';
import type { Config } from './config.js';
import type { LensDb } from './db/lensDb.js';
import type { SinkDb } from './db/sinkDb.js';
import { registerAnalysisTools } from './mcp/tools.js';

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
  app.use('/api', createAnalysisRequestsRouter(lensDb));

  app.post('/api/analysis/run', (_req, res) => {
    if (!runnerDeps) {
      res.status(503).json({ error: 'Sink DB is unavailable; analysis cannot run.' });
      return;
    }
    const result = runHourlyChecks(runnerDeps);
    res.json(result);
  });

  app.post('/mcp', async (req, res, next) => {
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

  return app;
}
