export type TriggerType =
  | 'anomaly'
  | 'repeat_offender'
  | 'new_signature'
  | 'new_source_ip'
  | 'internal_source';

// Only these two triggers represent an ongoing condition that can revert —
// see spec "Auto-resolve": a first-seen event or an IP's internal-ness
// can't "un-happen", so those trigger types always require manual dismissal.
export const STANDING_TRIGGER_TYPES: TriggerType[] = ['anomaly', 'repeat_offender'];

export interface Trigger {
  type: TriggerType;
  first_seen: string;
  last_seen: string;
  active: boolean;
}

export type FindingStatus = 'new' | 'acknowledged' | 'dismissed' | 'resolved';

export interface Finding {
  id?: number;
  entity_type: 'signature' | 'source_ip';
  entity_key: string;
  first_seen: string;
  last_seen: string;
  triggers: Trigger[];
  severity_score: number;
  status: FindingStatus;
}

const TRIGGER_WEIGHTS: Record<TriggerType, number> = {
  anomaly: 3,
  repeat_offender: 2,
  new_signature: 2,
  new_source_ip: 1,
  internal_source: 3,
};

export function computeSeverityScore(triggers: Trigger[]): number {
  return triggers.filter((t) => t.active).reduce((sum, t) => sum + TRIGGER_WEIGHTS[t.type], 0);
}

export function applyTrigger(
  existing: Finding | null,
  type: TriggerType,
  now: string,
  entityType: Finding['entity_type'],
  entityKey: string
): Finding {
  if (!existing) {
    const triggers: Trigger[] = [{ type, first_seen: now, last_seen: now, active: true }];
    return {
      entity_type: entityType,
      entity_key: entityKey,
      first_seen: now,
      last_seen: now,
      triggers,
      severity_score: computeSeverityScore(triggers),
      status: 'new',
    };
  }

  const hasType = existing.triggers.some((t) => t.type === type);
  const triggers: Trigger[] = hasType
    ? existing.triggers.map((t) => (t.type === type ? { ...t, active: true, last_seen: now } : t))
    : [...existing.triggers, { type, first_seen: now, last_seen: now, active: true }];

  // Rule 5 (refresh preserves status) has a narrow exception: a resolved
  // finding is machine-set on the premise "all triggers currently inactive."
  // If a standing trigger the finding already carries reactivates, that
  // premise no longer holds, so the finding must reopen rather than stay
  // silently resolved with a nonzero severity score.
  const status: FindingStatus = hasType
    ? existing.status === 'resolved'
      ? 'new'
      : existing.status
    : 'new';

  return {
    ...existing,
    last_seen: now,
    triggers,
    severity_score: computeSeverityScore(triggers),
    status,
  };
}

export function reevaluateTrigger(
  finding: Finding,
  type: TriggerType,
  active: boolean,
  now: string
): Finding {
  if (!finding.triggers.some((t) => t.type === type)) {
    return finding;
  }

  const triggers = finding.triggers.map((t) =>
    t.type === type ? { ...t, active, last_seen: active ? now : t.last_seen } : t
  );

  const allStandingAndInactive =
    triggers.every((t) => STANDING_TRIGGER_TYPES.includes(t.type)) &&
    triggers.every((t) => !t.active);

  const status: FindingStatus =
    !active &&
    allStandingAndInactive &&
    (finding.status === 'new' || finding.status === 'acknowledged')
      ? 'resolved'
      : finding.status;

  return {
    ...finding,
    triggers,
    severity_score: computeSeverityScore(triggers),
    status,
    last_seen: active ? now : finding.last_seen,
  };
}
