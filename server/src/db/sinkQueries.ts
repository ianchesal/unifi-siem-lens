import type { SinkDb } from './sinkDb.js';

export interface StoredEvent {
  id: number;
  received_at: string;
  category: string;
  severity: number | null;
  source_ip: string | null;
  dest_ip: string | null;
  action: string | null;
  signature: string | null;
  message: string | null;
  raw: string;
}

export function listEvents(db: SinkDb, opts: { since?: string; limit?: number }): StoredEvent[] {
  const clauses: string[] = [];
  const params: (string | number)[] = [];
  if (opts.since) {
    clauses.push('received_at >= ?');
    params.push(opts.since);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const limit = Math.min(opts.limit ?? 100, 500);
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, signature, message, raw
       FROM events ${where} ORDER BY received_at DESC LIMIT ?`
    )
    .all(...params, limit) as unknown as StoredEvent[];
}

// Recent raw events for a given source IP, most-recent first. Used as LLM
// analysis context (spec: "relevant recent raw events pulled from events.db
// as context") — capped low since this is prompt context, not a data dump.
export function eventsForSourceIp(db: SinkDb, sourceIp: string, limit = 20): StoredEvent[] {
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, action, signature, message, raw
       FROM events WHERE source_ip = ? ORDER BY received_at DESC LIMIT ?`
    )
    .all(sourceIp, limit) as unknown as StoredEvent[];
}

// Recent raw events for a given (category, signature) pair, most-recent first.
export function eventsForSignature(
  db: SinkDb,
  category: string,
  signature: string,
  limit = 20
): StoredEvent[] {
  return db.conn
    .prepare(
      `SELECT id, received_at, category, severity, source_ip, dest_ip, action, signature, message, raw
       FROM events WHERE category = ? AND signature = ? ORDER BY received_at DESC LIMIT ?`
    )
    .all(category, signature, limit) as unknown as StoredEvent[];
}

export function eventsOverTime(
  db: SinkDb,
  opts: { sinceDays: number }
): { day: string; category: string; count: number }[] {
  return db.conn
    .prepare(
      `SELECT date(received_at) as day, category, COUNT(*) as count
       FROM events WHERE received_at >= datetime('now', ?)
       GROUP BY day, category ORDER BY day ASC`
    )
    .all(`-${opts.sinceDays} days`) as unknown as {
    day: string;
    category: string;
    count: number;
  }[];
}

export function topSignatures(
  db: SinkDb,
  opts: { sinceDays: number; limit: number }
): { signature: string; count: number }[] {
  return db.conn
    .prepare(
      `SELECT signature, COUNT(*) as count FROM events
       WHERE received_at >= datetime('now', ?) AND signature IS NOT NULL AND signature != ''
       GROUP BY signature ORDER BY count DESC LIMIT ?`
    )
    .all(`-${opts.sinceDays} days`, opts.limit) as unknown as {
    signature: string;
    count: number;
  }[];
}

export function topSourceIps(
  db: SinkDb,
  opts: { sinceDays: number; limit: number }
): { source_ip: string; count: number }[] {
  return db.conn
    .prepare(
      `SELECT source_ip, COUNT(*) as count FROM events
       WHERE received_at >= datetime('now', ?) AND source_ip IS NOT NULL
       GROUP BY source_ip ORDER BY count DESC LIMIT ?`
    )
    .all(`-${opts.sinceDays} days`, opts.limit) as unknown as {
    source_ip: string;
    count: number;
  }[];
}

export function severityDistribution(
  db: SinkDb,
  opts: { sinceDays: number }
): { severity: number | null; count: number }[] {
  return db.conn
    .prepare(
      `SELECT severity, COUNT(*) as count FROM events
       WHERE received_at >= datetime('now', ?)
       GROUP BY severity ORDER BY severity ASC`
    )
    .all(`-${opts.sinceDays} days`) as unknown as { severity: number | null; count: number }[];
}

export interface EntityEventCounts {
  total: number;
  matching: number;
}

// SQL-level completeness check for rule-based triage: counts every event for
// the entity in the window (`total`) alongside only those also satisfying
// `matchingWhereSql` (`matching`). Deliberately does not reuse the LIMIT-20
// fetchers above — those are sized for LLM prompt context, and a burst of
// more than 20 events could otherwise let the most recent 20 stand in for
// "every event" and hide a non-matching event outside the cap.
export function sourceIpEventCounts(
  db: SinkDb,
  sourceIp: string,
  sinceIso: string,
  matchingWhereSql: string,
  matchingParams: (string | number)[] = []
): EntityEventCounts {
  const total = (
    db.conn
      .prepare('SELECT COUNT(*) as n FROM events WHERE source_ip = ? AND received_at >= ?')
      .get(sourceIp, sinceIso) as { n: number }
  ).n;
  const matching = (
    db.conn
      .prepare(
        `SELECT COUNT(*) as n FROM events WHERE source_ip = ? AND received_at >= ? AND (${matchingWhereSql})`
      )
      .get(sourceIp, sinceIso, ...matchingParams) as { n: number }
  ).n;
  return { total, matching };
}

export function signatureEventCounts(
  db: SinkDb,
  category: string,
  signature: string,
  sinceIso: string,
  matchingWhereSql: string,
  matchingParams: (string | number)[] = []
): EntityEventCounts {
  const total = (
    db.conn
      .prepare(
        'SELECT COUNT(*) as n FROM events WHERE category = ? AND signature = ? AND received_at >= ?'
      )
      .get(category, signature, sinceIso) as { n: number }
  ).n;
  const matching = (
    db.conn
      .prepare(
        `SELECT COUNT(*) as n FROM events WHERE category = ? AND signature = ? AND received_at >= ? AND (${matchingWhereSql})`
      )
      .get(category, signature, sinceIso, ...matchingParams) as { n: number }
  ).n;
  return { total, matching };
}

// Unbounded (no LIMIT) category+message rows for a source IP in the window.
// Used only by the admin-audit-login triage rule, whose match condition
// (regex over free text) can't be expressed as a SQL predicate the way the
// other rules' counts above are — audit-category volume per entity per
// window is inherently small, so fetching all of it is cheap and, unlike a
// capped fetch, doesn't risk missing a non-matching event.
export function auditCandidateEvents(
  db: SinkDb,
  sourceIp: string,
  sinceIso: string
): { category: string; message: string | null }[] {
  return db.conn
    .prepare('SELECT category, message FROM events WHERE source_ip = ? AND received_at >= ?')
    .all(sourceIp, sinceIso) as unknown as { category: string; message: string | null }[];
}
