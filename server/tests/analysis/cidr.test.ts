import { describe, expect, it } from 'vitest';
import { ipInCidr, isInternalSource } from '../../src/analysis/cidr.js';

describe('ipInCidr', () => {
  it('matches an IP inside a CIDR range', () => {
    expect(ipInCidr('10.0.30.5', '10.0.0.0/8')).toBe(true);
  });

  it('rejects an IP outside the range', () => {
    expect(ipInCidr('192.168.1.1', '10.0.0.0/8')).toBe(false);
  });

  it('returns false, not throw, for an IPv6 address (known limitation)', () => {
    expect(ipInCidr('fe80::1', '10.0.0.0/8')).toBe(false);
  });
});

describe('isInternalSource', () => {
  it('is true when the IP matches any configured LAN CIDR', () => {
    expect(isInternalSource('10.0.30.5', ['192.168.0.0/16', '10.0.0.0/8'])).toBe(true);
  });

  it('is false when lanCidrs is empty', () => {
    expect(isInternalSource('10.0.30.5', [])).toBe(false);
  });
});
