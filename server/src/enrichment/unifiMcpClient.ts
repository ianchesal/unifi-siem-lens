import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

export interface UnifiMcpClient {
  resolveClient(ip: string): Promise<{ name: string; network: string } | null>;
  getFirewallSummary(): Promise<unknown | null>;
}

async function withClient<T>(
  url: string,
  token: string | null,
  fn: (client: Client) => Promise<T>
): Promise<T | null> {
  const client = new Client({ name: 'unifi-siem-lens', version: '0.1.0' });
  try {
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: token ? { headers: { Authorization: `Bearer ${token}` } } : undefined,
    });
    await client.connect(transport);
    const result = await fn(client);
    await client.close();
    return result;
  } catch {
    // unifi-mcp-server unreachable, unauthorized, or not configured — enrichment
    // is optional, lens must degrade gracefully rather than fail the request it's enriching.
    return null;
  }
}

export function createUnifiMcpClient(
  url: string | null,
  token: string | null = null
): UnifiMcpClient {
  if (!url) {
    return {
      resolveClient: async () => null,
      getFirewallSummary: async () => null,
    };
  }

  return {
    resolveClient: async (ip) =>
      withClient(url, token, async (client) => {
        const result = await client.callTool({ name: 'get_client', arguments: { ip } });
        const text = (result.content as { text?: string }[])?.[0]?.text;
        if (!text) return null;
        const parsed = JSON.parse(text) as { name?: string; network?: string };
        if (!parsed.name) return null;
        return { name: parsed.name, network: parsed.network ?? 'unknown' };
      }),
    getFirewallSummary: async () =>
      withClient(url, token, async (client) => {
        const result = await client.callTool({ name: 'list_firewall_rules', arguments: {} });
        return (result.content as { text?: string }[])?.[0]?.text ?? null;
      }),
  };
}
