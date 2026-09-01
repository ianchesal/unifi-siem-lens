export type SeverityBand = 'crit' | 'high' | 'med' | 'low';

export function severityBand(score: number): SeverityBand {
  if (score >= 7) return 'crit';
  if (score >= 5) return 'high';
  if (score >= 3) return 'med';
  return 'low';
}

export const SEVERITY_COLORS: Record<SeverityBand, string> = {
  crit: '#e2534f',
  high: '#ec835a',
  med: '#fab219',
  low: '#8a93a6',
};
