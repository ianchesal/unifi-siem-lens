import type { LensDb } from './lensDb.js';

export interface AnalysisRequestRow {
  id: number;
  finding_id: number;
  status: 'pending' | 'answered';
  context: string;
  recommendation: string | null;
  risk_level: string | null;
  created_at: string;
  answered_at: string | null;
}

export function createAnalysisRequest(
  db: LensDb,
  findingId: number,
  context: object,
  now: string
): AnalysisRequestRow {
  const existingPending = db.conn
    .prepare("SELECT * FROM analysis_requests WHERE finding_id = ? AND status = 'pending'")
    .get(findingId) as AnalysisRequestRow | undefined;
  if (existingPending) return existingPending;

  const result = db.conn
    .prepare(
      `INSERT INTO analysis_requests (finding_id, status, context, created_at)
       VALUES (?, 'pending', ?, ?)`
    )
    .run(findingId, JSON.stringify(context), now);
  return getAnalysisRequest(db, Number(result.lastInsertRowid)) as AnalysisRequestRow;
}

export function getAnalysisRequest(db: LensDb, id: number): AnalysisRequestRow | null {
  const row = db.conn.prepare('SELECT * FROM analysis_requests WHERE id = ?').get(id) as
    | AnalysisRequestRow
    | undefined;
  return row ?? null;
}

export function getPendingAnalysisRequests(db: LensDb): AnalysisRequestRow[] {
  return db.conn
    .prepare("SELECT * FROM analysis_requests WHERE status = 'pending' ORDER BY created_at ASC")
    .all() as unknown as AnalysisRequestRow[];
}

export function submitAnalysis(
  db: LensDb,
  id: number,
  recommendation: string,
  riskLevel: string,
  now: string
): AnalysisRequestRow {
  const existing = getAnalysisRequest(db, id);
  if (!existing) throw new Error(`Analysis request ${id} not found`);
  if (existing.status === 'answered') {
    throw new Error(`Analysis request ${id} was already answered`);
  }
  db.conn
    .prepare(
      `UPDATE analysis_requests SET status = 'answered', recommendation = ?, risk_level = ?, answered_at = ?
       WHERE id = ?`
    )
    .run(recommendation, riskLevel, now, id);
  return getAnalysisRequest(db, id) as AnalysisRequestRow;
}
