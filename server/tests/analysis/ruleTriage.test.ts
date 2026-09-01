import { describe, expect, it } from 'vitest';
import {
  NON_SECURITY_OPERATIONAL_CATEGORIES,
  parseAdminAuditName,
  tryAdminAuditLoginRule,
  tryOperationalNoiseRule,
  tryReputationBlocklistRule,
} from '../../src/analysis/ruleTriage.js';

describe('parseAdminAuditName', () => {
  it('extracts the admin name from a well-formed audit login message', () => {
    expect(
      parseAdminAuditName('Ian C. accessed UniFi Network using the web. Source IP: 192.168.1.134')
    ).toBe('Ian C.');
  });

  it('returns null for a differently-worded message', () => {
    expect(parseAdminAuditName('Ian C. logged in via app')).toBeNull();
  });

  it('returns null for a message missing the Source IP suffix', () => {
    expect(parseAdminAuditName('Ian C. accessed UniFi Network using the web.')).toBeNull();
  });
});

describe('tryAdminAuditLoginRule', () => {
  const trusted = ['Ian C.'];

  it('matches when every event is a trusted admin login', () => {
    const events = [
      { category: 'audit', message: 'Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4' },
      { category: 'audit', message: 'Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4' },
    ];
    const verdict = tryAdminAuditLoginRule(events, trusted);
    expect(verdict).not.toBeNull();
    expect(verdict?.riskLevel).toBe('low');
  });

  it('does not match when the admin name is not in the trusted list', () => {
    const events = [
      { category: 'audit', message: 'Mallory accessed UniFi Network using the web. Source IP: 1.2.3.4' },
    ];
    expect(tryAdminAuditLoginRule(events, trusted)).toBeNull();
  });

  it('does not match a substring hit inside an unrelated message', () => {
    const events = [{ category: 'audit', message: 'Something mentions Ian C. accessed but is not the login line' }];
    expect(tryAdminAuditLoginRule(events, trusted)).toBeNull();
  });

  it('does not match a mixed set of events (one non-audit event present)', () => {
    const events = [
      { category: 'audit', message: 'Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4' },
      { category: 'ips_alert', message: null },
    ];
    expect(tryAdminAuditLoginRule(events, trusted)).toBeNull();
  });

  it('does not match an empty event list', () => {
    expect(tryAdminAuditLoginRule([], trusted)).toBeNull();
  });
});

describe('tryOperationalNoiseRule', () => {
  it('matches when total equals matching and both are nonzero', () => {
    const verdict = tryOperationalNoiseRule({ total: 2, matching: 2 });
    expect(verdict).not.toBeNull();
    expect(verdict?.riskLevel).toBe('low');
  });

  it('does not match when some events fall outside the operational category set', () => {
    expect(tryOperationalNoiseRule({ total: 3, matching: 2 })).toBeNull();
  });

  it('does not match a zero-total window', () => {
    expect(tryOperationalNoiseRule({ total: 0, matching: 0 })).toBeNull();
  });
});

describe('tryReputationBlocklistRule', () => {
  it('matches when total equals matching and both are nonzero', () => {
    const verdict = tryReputationBlocklistRule({ total: 4, matching: 4 });
    expect(verdict).not.toBeNull();
    expect(verdict?.riskLevel).toBe('low');
  });

  it('does not match when at least one event is not a blocked reputation-list hit', () => {
    expect(tryReputationBlocklistRule({ total: 4, matching: 3 })).toBeNull();
  });
});

describe('NON_SECURITY_OPERATIONAL_CATEGORIES', () => {
  it('includes internet_and_wan', () => {
    expect(NON_SECURITY_OPERATIONAL_CATEGORIES).toContain('internet_and_wan');
  });

  it('includes unifi_devices', () => {
    expect(NON_SECURITY_OPERATIONAL_CATEGORIES).toContain('unifi_devices');
  });
});
