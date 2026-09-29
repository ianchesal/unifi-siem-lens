export function signatureKey(category: string, signature: string): string {
  return `${category}|${signature}`;
}

// Inverse of signatureKey(). Splits only on the FIRST '|' so a signature that
// itself contains a '|' doesn't get mangled by a naive key.split('|') (the bug
// flagged in Task 12's review) — category never contains '|', signature might.
export function splitSignatureKey(key: string): { category: string; signature: string } {
  const sep = key.indexOf('|');
  if (sep === -1) return { category: key, signature: '' };
  return { category: key.slice(0, sep), signature: key.slice(sep + 1) };
}

// (category, signature) pairs the lens excludes from analysis entirely — no
// new-signature finding, no anomaly baseline. Unlike the ruleTriage.ts rules
// (which auto-dismiss a finding after it's created, leaving an audit trail),
// these are event types with no security meaning at all, so they never
// become findings in the first place. Keyed on the exact signatureKey() pair,
// not the bare signature: UniFi's numeric event codes are only unique within
// a category.
//   - siteactivity|2154: UniFi Protect doorbell ring ("Someone is ringing
//     <door>."), physical-site activity, not network security.
export const IGNORED_SIGNATURE_KEYS: ReadonlySet<string> = new Set(['siteactivity|2154']);

export function isIgnoredSignature(category: string, signature: string): boolean {
  return IGNORED_SIGNATURE_KEYS.has(signatureKey(category, signature));
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

export function detectNewSourceIps(
  events: { source_ip: string | null }[],
  seen: Set<string>
): string[] {
  const found = new Set<string>();
  for (const e of events) {
    if (!e.source_ip || seen.has(e.source_ip)) continue;
    found.add(e.source_ip);
  }
  return [...found];
}
