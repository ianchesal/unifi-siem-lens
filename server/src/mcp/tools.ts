import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  getAnalysisRequest,
  getPendingAnalysisRequests,
  submitAnalysis,
} from '../db/analysisRequestsStore.js';
import { listFindings } from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';

function toolResult(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function toolError(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: 'text' as const, text: `Error: ${message}` }],
    isError: true as const,
  };
}

export function registerAnalysisTools(server: McpServer, lensDb: LensDb): void {
  server.tool(
    'get_pending_analyses',
    'List pending analysis requests awaiting a recommendation.',
    {},
    async () => {
      try {
        return toolResult(getPendingAnalysisRequests(lensDb));
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'get_analysis_context',
    'Get full context for one analysis request: the request, its finding, and finding history.',
    { id: z.number().int() },
    async (p) => {
      try {
        const request = getAnalysisRequest(lensDb, p.id);
        if (!request) throw new Error(`Analysis request ${p.id} not found`);
        const findings = listFindings(lensDb);
        const finding = findings.find((f) => f.id === request.finding_id);
        return toolResult({ request, finding, context: JSON.parse(request.context) });
      } catch (e) {
        return toolError(e);
      }
    }
  );

  server.tool(
    'submit_analysis',
    'Submit a recommendation for a pending analysis request, marking it answered.',
    {
      id: z.number().int(),
      recommendation: z.string().min(1),
      risk_level: z.enum(['low', 'medium', 'high']),
    },
    async (p) => {
      try {
        const result = submitAnalysis(
          lensDb,
          p.id,
          p.recommendation,
          p.risk_level,
          new Date().toISOString()
        );
        return toolResult(result);
      } catch (e) {
        return toolError(e);
      }
    }
  );
}
