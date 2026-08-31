import { loadConfig } from './config.js';
import { openSinkDb, verifySchema } from './db/sinkDb.js';
import { createLogger } from './logger.js';
import { createApp } from './server.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);

logger.info('Starting unifi-siem-lens');

const sinkDb = openSinkDb(config.sinkDbPath);
const schemaCheck = verifySchema(sinkDb);
if (!schemaCheck.ok) {
  logger.error(
    `Sink DB schema mismatch, missing columns: ${schemaCheck.missingColumns.join(', ')}`
  );
}

const app = createApp(sinkDb);
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
