import { loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { createApp } from './server.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);

logger.info('Starting unifi-siem-lens');

const app = createApp();
const httpServer = app.listen(config.port, config.host, () => {
  logger.info(`Listening on ${config.host}:${config.port}`);
  logger.info(`GET http://${config.host}:${config.port}/health`);
});

async function shutdown(signal: string): Promise<void> {
  logger.info(`Received ${signal}, shutting down`);
  httpServer.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
