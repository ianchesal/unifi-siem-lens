import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
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

  describe('with a token configured', () => {
    let server: http.Server;
    let receivedAuth: string | undefined;

    afterEach(() => {
      server?.close();
    });

    it('sends the token as a Bearer Authorization header', async () => {
      server = http.createServer((req, res) => {
        receivedAuth = req.headers.authorization;
        res.writeHead(401).end();
      });
      await new Promise<void>((resolve) => server.listen(0, resolve));
      const port = (server.address() as AddressInfo).port;

      const client = createUnifiMcpClient(`http://127.0.0.1:${port}/mcp`, 'my-token');
      await client.resolveClient('10.0.0.5');

      expect(receivedAuth).toBe('Bearer my-token');
    });
  });
});
