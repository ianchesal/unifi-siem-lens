export const NON_SECURITY_OPERATIONAL_CATEGORIES = ['internet_and_wan'];

// Matches the sink's fixed audit-log template exactly (see
// unifi-siem-sink's normalize.ts UNIFIcategory=Audit / "Network Accessed"
// event shape). Anchored full-string match, not a substring/includes check
// — a name mentioned mid-sentence in an unrelated message must not match.
const AUDIT_LOGIN_PATTERN =
  /^(.+) accessed UniFi Network using the \w+\. Source IP: [\d.:a-fA-F]+$/;

export function parseAdminAuditName(message: string): string | null {
  const match = AUDIT_LOGIN_PATTERN.exec(message.trim());
  return match ? match[1] : null;
}

export interface EntityEventCounts {
  total: number;
  matching: number;
}

export interface TriageVerdict {
  recommendation: string;
  riskLevel: 'low';
}

function isComplete(counts: EntityEventCounts): boolean {
  return counts.total > 0 && counts.total === counts.matching;
}

export function tryAdminAuditLoginRule(
  events: { category: string; message: string | null }[],
  trustedAdminNames: string[]
): TriageVerdict | null {
  if (events.length === 0) return null;
  const trusted = new Set(trustedAdminNames);
  const allMatch = events.every((e) => {
    if (e.category !== 'audit' || !e.message) return false;
    const name = parseAdminAuditName(e.message);
    return name !== null && trusted.has(name);
  });
  if (!allMatch) return null;
  return {
    recommendation:
      'Every event behind this finding is an admin console login from a trusted account (UniFi audit log). Auto-dismissed by rule; no security review needed.',
    riskLevel: 'low',
  };
}

export function tryOperationalNoiseRule(counts: EntityEventCounts): TriageVerdict | null {
  if (!isComplete(counts)) return null;
  return {
    recommendation:
      'Every event behind this finding is operational/WAN-health telemetry (internet_and_wan category), not a security signal. Auto-dismissed by rule.',
    riskLevel: 'low',
  };
}

export function tryReputationBlocklistRule(counts: EntityEventCounts): TriageVerdict | null {
  if (!isComplete(counts)) return null;
  return {
    recommendation:
      'Every event behind this finding is a blocked hit from a known reputation/blocklist IDS/IPS rule (ET DROP/CINS/TOR/COMPROMISED/DSHIELD family). Routine untargeted scanning, already blocked. Auto-dismissed by rule.',
    riskLevel: 'low',
  };
}
