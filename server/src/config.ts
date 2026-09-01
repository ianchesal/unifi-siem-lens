import type { LogLevel } from './logger.js';

export interface Config {
  port: number;
  host: string;
  sinkDbPath: string;
  lensDbPath: string;
  lanCidrs: string[];
  unifiMcpServerUrl: string | null;
  logLevel: LogLevel;
  mcpSecret: string;
}

function parseIntEnv(key: string, defaultValue: number): number {
  const raw = process.env[key];
  if (!raw) return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Environment variable ${key} must be a number, got: "${raw}"`);
  }
  return parsed;
}

export function loadConfig(): Config {
  if (!process.env.SINK_DB_PATH?.trim()) {
    throw new Error('Missing required environment variable: SINK_DB_PATH');
  }

  if (!process.env.MCP_SECRET?.trim()) {
    throw new Error('Missing required environment variable: MCP_SECRET');
  }

  const validLevels: LogLevel[] = ['error', 'warn', 'info', 'debug'];
  const rawLogLevel = process.env.LOG_LEVEL ?? 'info';
  if (!validLevels.includes(rawLogLevel as LogLevel)) {
    throw new Error(`LOG_LEVEL must be one of: ${validLevels.join(', ')}, got: "${rawLogLevel}"`);
  }

  const lanCidrs = (process.env.LAN_CIDRS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    port: parseIntEnv('PORT', 3100),
    host: process.env.HOST ?? '127.0.0.1',
    sinkDbPath: process.env.SINK_DB_PATH,
    lensDbPath: process.env.LENS_DB_PATH ?? './data/lens.db',
    lanCidrs,
    unifiMcpServerUrl: process.env.UNIFI_MCP_SERVER_URL?.trim() || null,
    logLevel: rawLogLevel as LogLevel,
    mcpSecret: process.env.MCP_SECRET,
  };
}
