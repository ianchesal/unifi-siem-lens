export function signatureKey(category: string, signature: string): string {
  return `${category}|${signature}`;
}

export function detectNewSignatures(
  events: { category: string; signature: string | null }[],
  seen: Set<string>
): { category: string; signature: string }[] {
  const found = new Map<string, { category: string; signature: string }>();
  for (const e of events) {
    if (!e.signature) continue;
    const key = signatureKey(e.category, e.signature);
    if (seen.has(key) || found.has(key)) continue;
    found.set(key, { category: e.category, signature: e.signature });
  }
  return [...found.values()];
}

export function detectNewSourceIps(events: { source_ip: string | null }[], seen: Set<string>): string[] {
  const found = new Set<string>();
  for (const e of events) {
    if (!e.source_ip || seen.has(e.source_ip)) continue;
    found.add(e.source_ip);
  }
  return [...found];
}
