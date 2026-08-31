import { describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { openLensDb } from '../../src/db/lensDb.js';
import { listFindings } from '../../src/db/findingsStore.js';
import { runDailyAnomalyCheck, runHourlyChecks } from '../../src/analysis/runner.js';

function seededSinkDb(rows: { received_at: string; category: string; signature: string | null; source_ip: string | null }[]) {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT,
     signature TEXT, source_ip TEXT, severity INTEGER)`
  );
  const stmt = conn.prepare(
    'INSERT INTO events (received_at, category, signature, source_ip) VALUES (?, ?, ?, ?)'
  );
  for (const r of rows) stmt.run(r.received_at, r.category, r.signature, r.source_ip);
  return { conn };
}

describe('runHourlyChecks', () => {
  it('flags a brand-new signature and a brand-new source IP', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: [] }, now);

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
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: ['10.0.0.0/8'] }, now);

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
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: [] }, now);

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
    runDailyAnomalyCheck({ sinkDb, lensDb, lanCidrs: [] }, spikeDay);

    const finding = listFindings(lensDb).find((f) => f.entity_key === 'ips_alert|ET TROJAN Foo');
    expect(finding?.triggers.some((t) => t.type === 'anomaly' && t.active)).toBe(true);
  });
});
