import { describe, expect, it } from 'vitest';
import { detectNewSignatures, detectNewSourceIps, signatureKey } from '../../src/analysis/newEntity.js';

describe('detectNewSignatures', () => {
  it('flags signatures not already in the seen set', () => {
    const events = [
      { category: 'ips_alert', signature: 'ET SCAN Nmap' },
      { category: 'ips_alert', signature: 'ET SCAN Nmap' },
      { category: 'ips_alert', signature: 'ET TROJAN Foo' },
    ];
    const seen = new Set([signatureKey('ips_alert', 'ET SCAN Nmap')]);
    const result = detectNewSignatures(events, seen);
    expect(result).toEqual([{ category: 'ips_alert', signature: 'ET TROJAN Foo' }]);
  });

  it('excludes null/empty signatures', () => {
    const events = [
      { category: 'ips_alert', signature: null },
      { category: 'ips_alert', signature: '' },
    ];
    expect(detectNewSignatures(events, new Set())).toEqual([]);
  });
});

describe('detectNewSourceIps', () => {
  it('flags source IPs not already seen, ignoring nulls', () => {
    const events = [{ source_ip: '1.2.3.4' }, { source_ip: null }, { source_ip: '5.6.7.8' }];
    const result = detectNewSourceIps(events, new Set(['1.2.3.4']));
    expect(result).toEqual(['5.6.7.8']);
  });
});
