import { describe, expect, it } from 'vitest';
import {
  applyTrigger,
  computeSeverityScore,
  reevaluateTrigger,
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
    expect(finding.status).not.toBe('resolved');
    const repeatTrigger = finding.triggers.find((t) => t.type === 'repeat_offender') as Trigger;
    expect(repeatTrigger.active).toBe(false);
  });

  it('does not resolve a dismissed finding automatically (only new/acknowledged auto-resolve)', () => {
    let finding = applyTrigger(null, 'anomaly', 't0', 'signature', 'ips_alert|sig-1');
    finding = { ...finding, status: 'dismissed' };
    finding = reevaluateTrigger(finding, 'anomaly', false, 't1');
    expect(finding.status).toBe('dismissed');
  });
});

describe('computeSeverityScore', () => {
  it('sums weights of active triggers only', () => {
    const triggers: Trigger[] = [
      { type: 'internal_source', first_seen: 't', last_seen: 't', active: true },
      { type: 'repeat_offender', first_seen: 't', last_seen: 't', active: false },
    ];
    const score = computeSeverityScore(triggers);
    expect(score).toBeGreaterThan(0);
    const allActive = computeSeverityScore([
      { type: 'internal_source', first_seen: 't', last_seen: 't', active: true },
      { type: 'repeat_offender', first_seen: 't', last_seen: 't', active: true },
    ]);
    expect(allActive).toBeGreaterThan(score);
  });
});
