import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  annotateHomelabDestinations,
  loadHomelabServices,
  lookupHomelabService,
} from '../../src/enrichment/homelabServices.js';

describe('loadHomelabServices', () => {
  let dir: string | null = null;

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it('returns an empty registry when the file does not exist', () => {
    expect(loadHomelabServices('/nonexistent/path.json')).toEqual({});
  });

  it('returns an empty registry when the file is malformed JSON', () => {
    dir = mkdtempSync(join(tmpdir(), 'homelab-'));
    const path = join(dir, 'bad.json');
    writeFileSync(path, '{not valid json');
    expect(loadHomelabServices(path)).toEqual({});
  });

  it('loads a valid registry file', () => {
    dir = mkdtempSync(join(tmpdir(), 'homelab-'));
    const path = join(dir, 'homelab-services.json');
    const registry = {
      '192.168.1.26': { label: 'tranquility', services: [{ port: 8989, name: 'sonarr' }] },
    };
    writeFileSync(path, JSON.stringify(registry));
    expect(loadHomelabServices(path)).toEqual(registry);
  });
});

describe('lookupHomelabService', () => {
  const registry = {
    '192.168.1.26': {
      label: 'tranquility',
      services: [{ port: 8989, name: 'sonarr' }, { port: 7878, name: 'radarr' }],
    },
  };

  it('returns null for an unknown host', () => {
    expect(lookupHomelabService(registry, '10.0.0.1', 80)).toBeNull();
  });

  it('returns the host label with a matched service', () => {
    expect(lookupHomelabService(registry, '192.168.1.26', 8989)).toEqual({
      host: 'tranquility',
      service: { port: 8989, name: 'sonarr' },
    });
  });

  it('returns the host label with a null service when the port is unknown', () => {
    expect(lookupHomelabService(registry, '192.168.1.26', 9999)).toEqual({
      host: 'tranquility',
      service: null,
    });
  });

  it('returns the host label with a null service when no port is given', () => {
    expect(lookupHomelabService(registry, '192.168.1.26', null)).toEqual({
      host: 'tranquility',
      service: null,
    });
  });
});

describe('annotateHomelabDestinations', () => {
  const registry = {
    '192.168.1.26': { label: 'tranquility', services: [{ port: 8989, name: 'sonarr' }] },
  };

  it('attaches a homelab match keyed off dest_ip/dest_port', () => {
    const events = [{ dest_ip: '192.168.1.26', dest_port: 8989 }];
    expect(annotateHomelabDestinations(events, registry)).toEqual([
      { dest_ip: '192.168.1.26', dest_port: 8989, homelab: { host: 'tranquility', service: { port: 8989, name: 'sonarr' } } },
    ]);
  });

  it('sets homelab to null when dest_ip is null or unmatched', () => {
    const events = [
      { dest_ip: null, dest_port: null },
      { dest_ip: '8.8.8.8', dest_port: 53 },
    ];
    const result = annotateHomelabDestinations(events, registry);
    expect(result[0].homelab).toBeNull();
    expect(result[1].homelab).toBeNull();
  });
});
