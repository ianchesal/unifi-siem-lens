export const ANOMALY_Z_THRESHOLD = 3;

export interface BaselineStats {
  mean: number;
  stddev: number;
}

export function computeBaseline(dailyCounts: number[]): BaselineStats {
  if (dailyCounts.length === 0) return { mean: 0, stddev: 0 };
  const mean = dailyCounts.reduce((a, b) => a + b, 0) / dailyCounts.length;
  const variance =
    dailyCounts.reduce((sum, v) => sum + (v - mean) ** 2, 0) / dailyCounts.length;
  return { mean, stddev: Math.sqrt(variance) };
}

export function zScore(value: number, stats: BaselineStats): number {
  if (stats.stddev === 0) return value > stats.mean ? Number.POSITIVE_INFINITY : 0;
  return (value - stats.mean) / stats.stddev;
}

export function isAnomalous(value: number, stats: BaselineStats): boolean {
  return zScore(value, stats) >= ANOMALY_Z_THRESHOLD;
}
