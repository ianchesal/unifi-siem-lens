import { describe, expect, it } from 'vitest';
import { ANOMALY_Z_THRESHOLD, computeBaseline, isAnomalous, zScore } from '../../src/analysis/baseline.js';

describe('computeBaseline', () => {
  it('computes mean and stddev of a series', () => {
    const stats = computeBaseline([10, 10, 10, 10]);
    expect(stats.mean).toBe(10);
    expect(stats.stddev).toBe(0);
  });

  it('handles an empty series without dividing by zero', () => {
    const stats = computeBaseline([]);
    expect(stats.mean).toBe(0);
    expect(stats.stddev).toBe(0);
  });
});

describe('zScore / isAnomalous', () => {
  it('a value far from the mean has a high z-score and is anomalous', () => {
    const stats = computeBaseline([10, 12, 9, 11, 10, 11, 9]);
    const z = zScore(100, stats);
    expect(z).toBeGreaterThan(ANOMALY_Z_THRESHOLD);
    expect(isAnomalous(100, stats)).toBe(true);
  });

  it('a value close to the mean is not anomalous', () => {
    const stats = computeBaseline([10, 12, 9, 11, 10, 11, 9]);
    expect(isAnomalous(10, stats)).toBe(false);
  });

  it('zero-stddev baseline does not throw or return Infinity as "anomalous" for the same value', () => {
    const stats = computeBaseline([5, 5, 5]);
    expect(isAnomalous(5, stats)).toBe(false);
    expect(isAnomalous(50, stats)).toBe(true);
    expect(isAnomalous(2, stats)).toBe(false); // below the mean — a drop, not a spike, should not be flagged
  });
});
