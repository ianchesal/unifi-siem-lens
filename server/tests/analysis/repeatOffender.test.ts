import { describe, expect, it } from 'vitest';
import { REPEAT_OFFENDER_MIN_DAYS, isSustained } from '../../src/analysis/repeatOffender.js';

describe('isSustained', () => {
  it('is true at or above the threshold', () => {
    expect(isSustained(REPEAT_OFFENDER_MIN_DAYS)).toBe(true);
    expect(isSustained(REPEAT_OFFENDER_MIN_DAYS + 5)).toBe(true);
  });

  it('is false below the threshold', () => {
    expect(isSustained(REPEAT_OFFENDER_MIN_DAYS - 1)).toBe(false);
  });
});
