import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export interface LensDb {
  conn: DatabaseSync;
  close(): void;
}

const MIGRATIONS: { version: number; sql: string }[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE baselines (
        category TEXT NOT NULL,
        signature TEXT NOT NULL,
        day TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (category, signature, day)
      );
      CREATE TABLE seen_signatures (
        category TEXT NOT NULL,
        signature TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        PRIMARY KEY (category, signature)
      );
      CREATE TABLE seen_source_ips (
        source_ip TEXT NOT NULL PRIMARY KEY,
        first_seen TEXT NOT NULL
      );
      CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        triggers TEXT NOT NULL,
        severity_score REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'new',
        UNIQUE (entity_type, entity_key)
      );
      CREATE TABLE analysis_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id),
        status TEXT NOT NULL DEFAULT 'pending',
        context TEXT NOT NULL,
        recommendation TEXT,
        risk_level TEXT,
        created_at TEXT NOT NULL,
        answered_at TEXT
      );
      CREATE INDEX idx_analysis_requests_finding ON analysis_requests(finding_id);
      CREATE INDEX idx_analysis_requests_status ON analysis_requests(status);
    `,
  },
];

export function openLensDb(path: string): LensDb {
  if (path !== ':memory:') {
    const dir = dirname(path);
    if (dir && dir !== '.') mkdirSync(dir, { recursive: true });
  }

  const conn = new DatabaseSync(path);
  conn.exec('PRAGMA journal_mode = WAL;');
  conn.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);');

  const applied = new Set(
    (conn.prepare('SELECT version FROM schema_migrations').all() as { version: number }[]).map(
      (row) => row.version
    )
  );

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    conn.exec('BEGIN');
    try {
      conn.exec(migration.sql);
      conn.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(migration.version);
      conn.exec('COMMIT');
    } catch (err) {
      conn.exec('ROLLBACK');
      throw err;
    }
  }

  return {
    conn,
    close: () => {
      if (conn.isOpen) conn.close();
    },
  };
}
