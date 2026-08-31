import { describe, expect, it } from 'vitest';
import {
  applyTrigger,
  computeSeverityScore,
  reevaluateTrigger,
  STANDING_TRIGGER_TYPES,
  type Trigger,
} from '../../src/analysis/findings.js';

describe('applyTrigger', () => {
  it('creates a new finding with status new', () => {
    const finding = applyTrigger(null, 'new_signature', '2026-08-31T00:00:00Z', 'signature', 'ips_alert|sig-1');
    expect(finding.status).toBe('new');
    expect(finding.triggers).toHaveLength(1);
    expect(finding.triggers[0]).toMatchObject({ type: 'new_signature', active: true });
  });

  it('refreshes an existing trigger of the same type without reopening status', () => {
    let finding = applyTrigger(null, 'repeat_offender', 't0', 'source_ip', '1.2.3.4');
    finding = { ...finding, status: 'acknowledged' };
    finding = applyTrigger(finding, 'repeat_offender', 't1', 'source_ip', '1.2.3.4');
    expect(finding.status).toBe('acknowledged');
    expect(finding.triggers).toHaveLength(1);
    expect(finding.triggers[0].last_seen).toBe('t1');
  });

  it('escalation: adding a new trigger type reopens a dismissed finding', () => {
    let finding = applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4');
    finding = { ...finding, status: 'dismissed' };
    finding = applyTrigger(finding, 'repeat_offender', 't1', 'source_ip', '1.2.3.4');
    expect(finding.status).toBe('new');
    expect(finding.triggers.map((t) => t.type).sort()).toEqual(['internal_source', 'repeat_offender']);
  });

  it('reopens a resolved finding to new when a previously-inactive standing trigger reactivates', () => {
    let finding = applyTrigger(null, 'anomaly', 't0', 'signature', 'ips_alert|sig-1');
    finding = reevaluateTrigger(finding, 'anomaly', false, 't1'); // resolves (only trigger, standing, now inactive)
    expect(finding.status).toBe('resolved');
    finding = applyTrigger(finding, 'anomaly', 't2', 'signature', 'ips_alert|sig-1'); // anomaly recurs
    expect(finding.status).toBe('new');
  });
});

describe('reevaluateTrigger', () => {
  it('marks a standing trigger inactive when its condition lifts', () => {
    let finding = applyTrigger(null, 'anomaly', 't0', 'signature', 'ips_alert|sig-1');
    finding = reevaluateTrigger(finding, 'anomaly', false, 't1');
    expect(finding.triggers[0].active).toBe(false);
  });

  it('auto-resolves a finding whose only trigger is a standing type that just went inactive', () => {
    let finding = applyTrigger(null, 'repeat_offender', 't0', 'source_ip', '1.2.3.4');
    finding = reevaluateTrigger(finding, 'repeat_offender', false, 't1');
    expect(finding.status).toBe('resolved');
  });

  it('does NOT auto-resolve when the finding also carries an event-based trigger', () => {
    let finding = applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4');
    finding = applyTrigger(finding, 'repeat_offender', 't1', 'source_ip', '1.2.3.4');
    finding = reevaluateTrigger(finding, 'repeat_offender', false, 't2');
    expect(finding.status).toBe('new');
    const repeatTrigger = finding.triggers.find((t) => t.type === 'repeat_offender') as Trigger;
    expect(repeatTrigger.active).toBe(false);
  });

  it('does not resolve a dismissed finding automatically (only new/acknowledged auto-resolve)', () => {
    let finding = applyTrigger(null, 'anomaly', 't0', 'signature', 'ips_alert|sig-1');
    finding = { ...finding, status: 'dismissed' };
    finding = reevaluateTrigger(finding, 'anomaly', false, 't1');
    expect(finding.status).toBe('dismissed');
  });

  it('classification: only anomaly and repeat_offender are standing (auto-resolving) trigger types', () => {
    expect([...STANDING_TRIGGER_TYPES].sort()).toEqual(['anomaly', 'repeat_offender']);
  });

  it('never auto-resolves a finding carrying an event trigger, even when EVERY trigger is inactive', () => {
    let finding = applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4');
    finding = applyTrigger(finding, 'repeat_offender', 't1', 'source_ip', '1.2.3.4');
    finding = reevaluateTrigger(finding, 'internal_source', false, 't2'); // event trigger ALSO inactive now
    finding = reevaluateTrigger(finding, 'repeat_offender', false, 't3');
    expect(finding.triggers.every((t) => !t.active)).toBe(true); // clause (c) satisfied
    expect(finding.status).toBe('new'); // must still NOT be resolved — exact status, not just "not resolved"
  });

  it('reevaluateTrigger is a no-op when the finding does not carry that trigger type', () => {
    const finding = applyTrigger(null, 'repeat_offender', 't0', 'source_ip', '1.2.3.4');
    const result = reevaluateTrigger(finding, 'anomaly', false, 't1'); // finding has no anomaly trigger
    expect(result).toEqual(finding);
  });
});

describe('computeSeverityScore', () => {
  it('sums weights of active triggers only', () => {
    const triggers: Trigger[] = [
      { type: 'internal_source', first_seen: 't', last_seen: 't', active: true },
      { type: 'repeat_offender', first_seen: 't', last_seen: 't', active: false },
    ];
    expect(computeSeverityScore(triggers)).toBe(3); // only internal_source (weight 3) is active
    expect(
      computeSeverityScore([
        { type: 'internal_source', first_seen: 't', last_seen: 't', active: true },
        { type: 'repeat_offender', first_seen: 't', last_seen: 't', active: true },
      ])
    ).toBe(5); // 3 + 2
    expect(computeSeverityScore([])).toBe(0);
  });
});
