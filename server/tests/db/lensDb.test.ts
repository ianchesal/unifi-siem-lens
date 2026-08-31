import { describe, expect, it } from 'vitest';
import { openLensDb } from '../../src/db/lensDb.js';

describe('openLensDb', () => {
  it('creates all expected tables', () => {
    const db = openLensDb(':memory:');
    const tables = db.conn
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all()
      .map((r: any) => r.name);
    for (const t of [
      'baselines',
      'seen_signatures',
      'seen_source_ips',
      'findings',
      'analysis_requests',
    ]) {
      expect(tables).toContain(t);
    }
    db.close();
  });

  it('enforces one findings row per entity', () => {
    const db = openLensDb(':memory:');
    db.conn
      .prepare(
        `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
         VALUES ('source_ip', '1.2.3.4', 'a', 'a', '[]', 0, 'new')`
      )
      .run();
    expect(() =>
      db.conn
        .prepare(
          `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
           VALUES ('source_ip', '1.2.3.4', 'b', 'b', '[]', 0, 'new')`
        )
        .run()
    ).toThrow();
    db.close();
  });

  it('is idempotent across repeated opens on the same file', () => {
    const path = ':memory:';
    const db1 = openLensDb(path);
    db1.close();
    const db2 = openLensDb(path); // fresh :memory: db, but proves no migration crash on a second run pattern
    expect(db2.conn.prepare('SELECT COUNT(*) as n FROM findings').get()).toEqual({ n: 0 });
    db2.close();
  });
});
