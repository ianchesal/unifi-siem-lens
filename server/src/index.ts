import { type RunnerDeps, runDailyAnomalyCheck, runHourlyChecks } from './analysis/runner.js';
import { loadConfig } from './config.js';
import { openLensDb } from './db/lensDb.js';
import { openSinkDb, type SinkDb, verifySchema } from './db/sinkDb.js';
import { createLogger } from './logger.js';
import { createApp, type SchemaCheckResult } from './server.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);

logger.info('Starting unifi-siem-lens');

// openSinkDb throws a raw native error if SINK_DB_PATH points to a file that
// doesn't exist (or isn't readable). That shouldn't take the whole process
// down: boot degraded instead, so /health and the rest of the API still come
// up and can report the problem, and retry is just a restart away once the
// sink DB shows up.
let sinkDb: SinkDb | null = null;
let schemaCheck: SchemaCheckResult | null = null;
try {
  sinkDb = openSinkDb(config.sinkDbPath);
  schemaCheck = verifySchema(sinkDb);
  if (!schemaCheck.ok) {
    logger.error(
      `Sink DB schema mismatch, missing columns: ${schemaCheck.missingColumns.join(', ')}`
    );
  }
} catch (err) {
  logger.error(`Failed to open sink DB at ${config.sinkDbPath}; starting in degraded mode`, err);
  sinkDb = null;
}

const lensDb = openLensDb(config.lensDbPath);
const runnerDeps: RunnerDeps | null = sinkDb ? { sinkDb, lensDb, lanCidrs: config.lanCidrs } : null;

function runChecksSafely(): void {
  if (!runnerDeps) {
    logger.warn('Skipping hourly analysis checks: sink DB unavailable');
    return;
  }
  try {
    const hourly = runHourlyChecks(runnerDeps);
    logger.info(`Hourly analysis checks touched ${hourly.findingsTouched} finding(s)`);
  } catch (err) {
    logger.error('Hourly analysis checks failed', err);
  }
}

runChecksSafely();
const hourlyTimer = setInterval(runChecksSafely, 60 * 60 * 1000);

function runDailyCheckSafely(): void {
  if (!runnerDeps) {
    logger.warn('Skipping daily anomaly check: sink DB unavailable');
    return;
  }
  try {
    const daily = runDailyAnomalyCheck(runnerDeps);
    logger.info(`Daily anomaly check touched ${daily.findingsTouched} finding(s)`);
  } catch (err) {
    logger.error('Daily anomaly check failed', err);
  }
}

runDailyCheckSafely();
const dailyTimer = setInterval(runDailyCheckSafely, 24 * 60 * 60 * 1000);

const app = createApp(sinkDb, lensDb, runnerDeps, config, schemaCheck);
const httpServer = app.listen(config.port, config.host, () => {
  logger.info(`Listening on ${config.host}:${config.port}`);
  logger.info(`GET http://${config.host}:${config.port}/health`);
});

async function shutdown(signal: string): Promise<void> {
  logger.info(`Received ${signal}, shutting down`);
  clearInterval(hourlyTimer);
  clearInterval(dailyTimer);
  httpServer.close();
  lensDb.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
