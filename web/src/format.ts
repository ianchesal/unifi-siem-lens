export function truncateLabel(value: string, max = 20): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}
