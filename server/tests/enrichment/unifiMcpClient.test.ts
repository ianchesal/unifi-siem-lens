import { describe, expect, it } from 'vitest';
import { createUnifiMcpClient } from '../../src/enrichment/unifiMcpClient.js';

describe('createUnifiMcpClient', () => {
  it('resolveClient is a no-op returning null when no URL is configured', async () => {
    const client = createUnifiMcpClient(null);
    expect(await client.resolveClient('10.0.0.5')).toBeNull();
  });

  it('getFirewallSummary is a no-op returning null when no URL is configured', async () => {
    const client = createUnifiMcpClient(null);
    expect(await client.getFirewallSummary()).toBeNull();
  });

  it('resolveClient swallows connection errors and returns null rather than throwing', async () => {
    const client = createUnifiMcpClient('http://127.0.0.1:1/mcp'); // nothing listening
    await expect(client.resolveClient('10.0.0.5')).resolves.toBeNull();
  });
});
