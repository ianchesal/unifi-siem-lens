import { describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { openLensDb } from '../../src/db/lensDb.js';
import { listFindings } from '../../src/db/findingsStore.js';
import {
  getAnalysisRequestsForFinding,
} from '../../src/db/analysisRequestsStore.js';
import { runDailyAnomalyCheck, runHourlyChecks } from '../../src/analysis/runner.js';

function seededSinkDb(
  rows: {
    received_at: string;
    category: string;
    signature: string | null;
    source_ip: string | null;
    action?: string | null;
    message?: string | null;
  }[]
) {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT,
     signature TEXT, source_ip TEXT, severity INTEGER, action TEXT, message TEXT)`
  );
  const stmt = conn.prepare(
    'INSERT INTO events (received_at, category, signature, source_ip, action, message) VALUES (?, ?, ?, ?, ?, ?)'
  );
  for (const r of rows) stmt.run(r.received_at, r.category, r.signature, r.source_ip, r.action ?? null, r.message ?? null);
  return { conn };
}

describe('runHourlyChecks', () => {
  it('flags a brand-new signature and a brand-new source IP', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, now);

    const findings = listFindings(lensDb);
    const types = findings.flatMap((f) => f.triggers.map((t) => t.type));
    expect(types).toContain('new_signature');
    expect(types).toContain('new_source_ip');
  });

  it('flags an internal-source event', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '10.0.30.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: ['10.0.0.0/8'], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, now);

    const finding = listFindings(lensDb).find((f) => f.entity_key === '10.0.30.5');
    expect(finding?.triggers.some((t) => t.type === 'internal_source')).toBe(true);
  });

  it('flags a repeat offender once it crosses the distinct-day threshold', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const days = ['2026-08-29', '2026-08-30', '2026-08-31'];
    const sinkDb = seededSinkDb(
      days.map((d) => ({ received_at: `${d}T01:00:00Z`, category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.9' }))
    );
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, now);

    const finding = listFindings(lensDb).find((f) => f.entity_key === '203.0.113.9');
    expect(finding?.triggers.some((t) => t.type === 'repeat_offender' && t.active)).toBe(true);
  });
});

describe('runDailyAnomalyCheck', () => {
  it('flags a signature whose count is far above its 14-day baseline', () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT,
       signature TEXT, source_ip TEXT, severity INTEGER)`
    );
    const stmt = conn.prepare(
      'INSERT INTO events (received_at, category, signature, source_ip) VALUES (?, ?, ?, ?)'
    );
    // 13 quiet days at count 1, then a spike day at count 50
    for (let i = 13; i >= 1; i--) {
      const day = new Date(Date.UTC(2026, 7, 31 - i)).toISOString().slice(0, 10);
      stmt.run(`${day}T01:00:00Z`, 'ips_alert', 'ET TROJAN Foo', '203.0.113.1');
    }
    const spikeDay = '2026-08-30';
    for (let i = 0; i < 50; i++) {
      stmt.run(`${spikeDay}T01:00:00Z`, 'ips_alert', 'ET TROJAN Foo', '203.0.113.1');
    }
    const sinkDb = { conn };
    const lensDb = openLensDb(':memory:');
    runDailyAnomalyCheck({ sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, spikeDay);

    const finding = listFindings(lensDb).find((f) => f.entity_key === 'ips_alert|ET TROJAN Foo');
    expect(finding?.triggers.some((t) => t.type === 'anomaly' && t.active)).toBe(true);
  });
});

describe('rule-based triage', () => {
  it('auto-dismisses a reputation-blocklist new_source_ip finding with a rule-sourced analysis', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET DROP Dshield Block Listed Source group 1',
        source_ip: '203.0.113.5',
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '203.0.113.5');
    expect(finding).toBeDefined();
    const requests = getAnalysisRequestsForFinding(lensDb, finding?.id as number);
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe('rule');
    expect(requests[0].status).toBe('answered');
    expect(requests[0].risk_level).toBe('low');
  });

  it('does not auto-dismiss a signature outside the safe-prefix list', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic',
        source_ip: '203.0.113.6',
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb).find((f) => f.entity_key === '203.0.113.6');
    expect(finding?.status).toBe('new');
    expect(getAnalysisRequestsForFinding(lensDb, finding?.id as number)).toHaveLength(0);
  });

  it('auto-dismisses a trusted admin audit-login new_source_ip finding', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'audit',
        signature: null,
        source_ip: '192.168.1.134',
        message: 'Ian C. accessed UniFi Network using the web. Source IP: 192.168.1.134',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: ['Ian C.'], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '192.168.1.134');
    expect(finding).toBeDefined();
  });

  it('leaves an untrusted admin audit login for manual/AI review', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'audit',
        signature: null,
        source_ip: '192.168.1.200',
        message: 'Mallory accessed UniFi Network using the web. Source IP: 192.168.1.200',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: ['Ian C.'], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb).find((f) => f.entity_key === '192.168.1.200');
    expect(finding?.status).toBe('new');
  });

  it('auto-dismisses an operational-noise new_source_ip finding', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'internet_and_wan', signature: null, source_ip: '192.168.1.1' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '192.168.1.1');
    expect(finding).toBeDefined();
  });

  it('same-pass reopen: a rule-dismissed source IP that also trips internal-source ends the pass as new', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET DROP Dshield Block Listed Source group 1',
        source_ip: '10.0.30.5',
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      {
        sinkDb,
        lensDb,
        lanCidrs: ['10.0.0.0/8'],
        trustedAdminNames: [],
        safeSignaturePrefixes: ['ET DROP'],
      },
      now
    );

    const finding = listFindings(lensDb).find((f) => f.entity_key === '10.0.30.5');
    expect(finding?.status).toBe('new');
    expect(finding?.triggers.some((t) => t.type === 'internal_source' && t.active)).toBe(true);
    expect(finding?.triggers.some((t) => t.type === 'new_source_ip' && t.active)).toBe(true);
  });
});
