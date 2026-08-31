export const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 } as const;

export type LogLevel = keyof typeof LEVELS;

export interface Logger {
  error(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  info(msg: string, ...args: unknown[]): void;
  debug(msg: string, ...args: unknown[]): void;
}

export function createLogger(level: LogLevel): Logger {
  const threshold = LEVELS[level];
  return {
    error: (msg, ...args) =>
      threshold >= LEVELS.error &&
      console.error(`[ERROR] ${new Date().toISOString()}`, msg, ...args),
    warn: (msg, ...args) =>
      threshold >= LEVELS.warn && console.warn(`[WARN]  ${new Date().toISOString()}`, msg, ...args),
    info: (msg, ...args) =>
      threshold >= LEVELS.info && console.log(`[INFO]  ${new Date().toISOString()}`, msg, ...args),
    debug: (msg, ...args) =>
      threshold >= LEVELS.debug && console.log(`[DEBUG] ${new Date().toISOString()}`, msg, ...args),
  };
}
