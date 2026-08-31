import type { Finding, FindingStatus } from '../analysis/findings.js';
import type { LensDb } from './lensDb.js';

interface FindingRow {
  id: number;
  entity_type: string;
  entity_key: string;
  first_seen: string;
  last_seen: string;
  triggers: string;
  severity_score: number;
  status: string;
}

function rowToFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    entity_type: row.entity_type as Finding['entity_type'],
    entity_key: row.entity_key,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    triggers: JSON.parse(row.triggers),
    severity_score: row.severity_score,
    status: row.status as FindingStatus,
  };
}

export function getFinding(
  db: LensDb,
  entityType: Finding['entity_type'],
  entityKey: string
): Finding | null {
  const row = db.conn
    .prepare('SELECT * FROM findings WHERE entity_type = ? AND entity_key = ?')
    .get(entityType, entityKey) as FindingRow | undefined;
  return row ? rowToFinding(row) : null;
}

export function upsertFinding(db: LensDb, finding: Finding): Finding {
  const triggersJson = JSON.stringify(finding.triggers);
  db.conn
    .prepare(
      `INSERT INTO findings (entity_type, entity_key, first_seen, last_seen, triggers, severity_score, status)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(entity_type, entity_key) DO UPDATE SET
         last_seen = excluded.last_seen,
         triggers = excluded.triggers,
         severity_score = excluded.severity_score,
         status = excluded.status`
    )
    .run(
      finding.entity_type,
      finding.entity_key,
      finding.first_seen,
      finding.last_seen,
      triggersJson,
      finding.severity_score,
      finding.status
    );
  return getFinding(db, finding.entity_type, finding.entity_key) as Finding;
}

export function listFindings(db: LensDb, opts: { status?: FindingStatus } = {}): Finding[] {
  const rows = opts.status
    ? (db.conn
        .prepare('SELECT * FROM findings WHERE status = ? ORDER BY severity_score DESC')
        .all(opts.status) as unknown as FindingRow[])
    : (db.conn
        .prepare('SELECT * FROM findings ORDER BY severity_score DESC')
        .all() as unknown as FindingRow[]);
  return rows.map(rowToFinding);
}

export function hasSeenSignature(db: LensDb, category: string, signature: string): boolean {
  const row = db.conn
    .prepare('SELECT 1 FROM seen_signatures WHERE category = ? AND signature = ?')
    .get(category, signature);
  return row !== undefined;
}

export function markSeenSignature(
  db: LensDb,
  category: string,
  signature: string,
  now: string
): void {
  db.conn
    .prepare(
      'INSERT OR IGNORE INTO seen_signatures (category, signature, first_seen) VALUES (?, ?, ?)'
    )
    .run(category, signature, now);
}

export function hasSeenSourceIp(db: LensDb, sourceIp: string): boolean {
  const row = db.conn.prepare('SELECT 1 FROM seen_source_ips WHERE source_ip = ?').get(sourceIp);
  return row !== undefined;
}

export function markSeenSourceIp(db: LensDb, sourceIp: string, now: string): void {
  db.conn
    .prepare('INSERT OR IGNORE INTO seen_source_ips (source_ip, first_seen) VALUES (?, ?)')
    .run(sourceIp, now);
}
