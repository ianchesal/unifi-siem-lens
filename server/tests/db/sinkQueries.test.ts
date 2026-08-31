import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { openSinkDb, type SinkDb } from '../../src/db/sinkDb.js';
import {
  eventsOverTime,
  listEvents,
  severityDistribution,
  topSignatures,
  topSourceIps,
} from '../../src/db/sinkQueries.js';

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
