import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { createAnalysisRequest } from '../../src/db/analysisRequestsStore.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import { registerAnalysisTools } from '../../src/mcp/tools.js';

async function connectedClient(lensDb: ReturnType<typeof openLensDb>) {
  const server = new McpServer({ name: 'test', version: '0.1.0' });
  registerAnalysisTools(server, lensDb);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe('MCP analysis tools', () => {
  it('get_pending_analyses then submit_analysis completes the loop', async () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const request = createAnalysisRequest(lensDb, finding.id as number, { note: 'ctx' }, 't1');

    const client = await connectedClient(lensDb);
    const pending = await client.callTool({ name: 'get_pending_analyses', arguments: {} });
    expect(JSON.stringify(pending)).toContain(String(request.id));

    const submitted = await client.callTool({
      name: 'submit_analysis',
      arguments: { id: request.id, recommendation: 'benign, known device', risk_level: 'low' },
    });
    expect(JSON.stringify(submitted)).not.toMatch(/isError.*true/);

    const pendingAfter = await client.callTool({ name: 'get_pending_analyses', arguments: {} });
    expect(JSON.stringify(pendingAfter)).not.toContain(String(request.id));
  });
});
