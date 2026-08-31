export const REPEAT_OFFENDER_MIN_DAYS = 3;
export const REPEAT_OFFENDER_WINDOW_DAYS = 14;

export function isSustained(distinctDaysActive: number): boolean {
  return distinctDaysActive >= REPEAT_OFFENDER_MIN_DAYS;
}
