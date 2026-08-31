import { DatabaseSync } from 'node:sqlite';

export interface SinkDb {
  conn: DatabaseSync;
}

// Columns lens depends on, as of the sink's schema version 1
// (unifi-siem-sink/src/storage/db.ts MIGRATIONS[0]). If the sink's schema
// changes in a way that drops or renames one of these, lens should fail
// loud via verifySchema() rather than error obscurely on first query.
const EXPECTED_COLUMNS = [
  'id',
  'received_at',
  'event_time',
  'category',
  'subcategory',
  'severity',
  'name',
  'source_ip',
  'dest_ip',
  'source_port',
  'dest_port',
  'protocol',
  'action',
  'signature',
  'message',
  'device_host',
  'raw',
  'parsed',
];

export function openSinkDb(path: string): SinkDb {
  const conn = new DatabaseSync(path, { readOnly: true });
  return { conn };
}

export function verifySchema(db: SinkDb): { ok: boolean; missingColumns: string[] } {
  const rows = db.conn.prepare('PRAGMA table_info(events)').all() as { name: string }[];
  const present = new Set(rows.map((r) => r.name));
  const missingColumns = EXPECTED_COLUMNS.filter((c) => !present.has(c));
  return { ok: missingColumns.length === 0, missingColumns };
}
