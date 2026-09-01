import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { openSinkDb, type SinkDb } from '../../src/db/sinkDb.js';
import {
  auditCandidateEvents,
  eventsForSignature,
  eventsForSourceIp,
  eventsOverTime,
  listEvents,
  severityDistribution,
  signatureEventCounts,
  sourceIpEventCounts,
  topSignatures,
  topSourceIps,
} from '../../src/db/sinkQueries.js';

function seededEventsDb(
  rows: {
    received_at: string;
    category: string;
    signature?: string | null;
    source_ip?: string | null;
    action?: string | null;
    message?: string | null;
  }[]
): SinkDb {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
     category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
     dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
     signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
  );
  const stmt = conn.prepare(
    `INSERT INTO events (received_at, category, signature, source_ip, action, message, raw, parsed)
     VALUES (?, ?, ?, ?, ?, ?, '', 1)`
  );
  for (const r of rows) {
    stmt.run(r.received_at, r.category, r.signature ?? null, r.source_ip ?? null, r.action ?? null, r.message ?? null);
  }
  return { conn };
}

describe('sinkQueries', () => {
  it('listEvents returns rows without throwing against the fixture', () => {
    const db = openSinkDb('tests/fixtures/events.db');
    const events = listEvents(db, { limit: 10 });
    expect(Array.isArray(events)).toBe(true);
  });

  it('listEvents on an empty/:memory: db returns an empty array, not an error', () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, event_time TEXT,
       category TEXT, subcategory TEXT, severity INTEGER, name TEXT, source_ip TEXT,
       dest_ip TEXT, source_port INTEGER, dest_port INTEGER, protocol TEXT, action TEXT,
       signature TEXT, message TEXT, device_host TEXT, raw TEXT, parsed INTEGER)`
    );
    const db: SinkDb = { conn };
    expect(listEvents(db, {})).toEqual([]);
    expect(eventsOverTime(db, { sinceDays: 7 })).toEqual([]);
    expect(topSignatures(db, { sinceDays: 7, limit: 5 })).toEqual([]);
    expect(topSourceIps(db, { sinceDays: 7, limit: 5 })).toEqual([]);
    expect(severityDistribution(db, { sinceDays: 7 })).toEqual([]);
  });
});

describe('eventsForSourceIp / eventsForSignature action column', () => {
  it('includes the action column in returned rows', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
    ]);
    expect(eventsForSourceIp(db, '1.2.3.4')[0].action).toBe('blocked');
    expect(eventsForSignature(db, 'ips_alert', 'ET DROP Foo')[0].action).toBe('blocked');
  });
});

describe('sourceIpEventCounts / signatureEventCounts', () => {
  it('reports total and matching counts for a source IP within a window', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-31T02:00:00Z', category: 'ips_alert', signature: 'ET MALWARE Bar', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-30T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
    ]);
    const counts = sourceIpEventCounts(
      db,
      '1.2.3.4',
      '2026-08-31T00:00:00Z',
      "category = 'ips_alert' AND action = 'blocked' AND signature LIKE ?",
      ['ET DROP%']
    );
    expect(counts.total).toBe(2);
    expect(counts.matching).toBe(1);
  });

  it('reports total and matching counts for a signature within a window', () => {
    const db = seededEventsDb([
      { received_at: '2026-08-31T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '1.2.3.4', action: 'blocked' },
      { received_at: '2026-08-31T02:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '5.6.7.8', action: 'allowed' },
    ]);
    const counts = signatureEventCounts(
      db,
      'ips_alert',
      'ET DROP Foo',
      '2026-08-31T00:00:00Z',
      "action = 'blocked'"
    );
    expect(counts.total).toBe(2);
    expect(counts.matching).toBe(1);
  });
});

describe('auditCandidateEvents', () => {
  it('returns category and message for all events for a source IP in the window, unbounded', () => {
    const db = seededEventsDb(
      Array.from({ length: 25 }, (_, i) => ({
        received_at: `2026-08-31T${String(i).padStart(2, '0')}:00:00Z`,
        category: 'audit',
        source_ip: '1.2.3.4',
        message: `Ian C. accessed UniFi Network using the web. Source IP: 1.2.3.4`,
      }))
    );
    const events = auditCandidateEvents(db, '1.2.3.4', '2026-08-31T00:00:00Z');
    expect(events).toHaveLength(25);
    expect(events[0].category).toBe('audit');
  });
});
