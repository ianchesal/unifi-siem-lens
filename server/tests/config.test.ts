import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    process.env.SINK_DB_PATH = '/tmp/events.db';
    process.env.MCP_SECRET = 'test-secret';
  });

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('applies defaults', () => {
    delete process.env.LAN_CIDRS;
    delete process.env.PORT;
    const config = loadConfig();
    expect(config.port).toBe(3100);
    expect(config.host).toBe('127.0.0.1');
    expect(config.lanCidrs).toEqual([]);
    expect(config.unifiMcpServerUrl).toBeNull();
  });

  it('parses LAN_CIDRS as a comma-separated list', () => {
    process.env.LAN_CIDRS = '10.0.0.0/8, 192.168.1.0/24';
    const config = loadConfig();
    expect(config.lanCidrs).toEqual(['10.0.0.0/8', '192.168.1.0/24']);
  });

  it('throws when SINK_DB_PATH is missing', () => {
    delete process.env.SINK_DB_PATH;
    expect(() => loadConfig()).toThrow(/SINK_DB_PATH/);
  });

  it('throws when MCP_SECRET is missing', () => {
    delete process.env.MCP_SECRET;
    expect(() => loadConfig()).toThrow(/MCP_SECRET/);
  });
});
