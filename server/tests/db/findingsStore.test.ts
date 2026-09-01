import { describe, expect, it } from 'vitest';
import { openLensDb } from '../../src/db/lensDb.js';
import { applyTrigger } from '../../src/analysis/findings.js';
import {
  getFinding,
  hasSeenSourceIp,
  listFindings,
  markSeenSourceIp,
  setFindingStatus,
  upsertFinding,
} from '../../src/db/findingsStore.js';

describe('findingsStore', () => {
  it('round-trips a finding through upsert/get, preserving triggers', () => {
    const db = openLensDb(':memory:');
    const finding = applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4');
    const saved = upsertFinding(db, finding);
    expect(saved.id).toBeDefined();

    const fetched = getFinding(db, 'source_ip', '1.2.3.4');
    expect(fetched?.triggers).toEqual(finding.triggers);
    expect(fetched?.status).toBe('new');
    db.close();
  });

  it('upsert on the same entity updates the same row (no duplicate)', () => {
    const db = openLensDb(':memory:');
    const f1 = upsertFinding(db, applyTrigger(null, 'internal_source', 't0', 'source_ip', '9.9.9.9'));
    const f2 = upsertFinding(db, applyTrigger(f1, 'repeat_offender', 't1', 'source_ip', '9.9.9.9'));
    expect(f2.id).toBe(f1.id);
    expect(listFindings(db).length).toBe(1);
    db.close();
  });

  it('tracks seen source IPs', () => {
    const db = openLensDb(':memory:');
    expect(hasSeenSourceIp(db, '1.1.1.1')).toBe(false);
    markSeenSourceIp(db, '1.1.1.1', 't0');
    expect(hasSeenSourceIp(db, '1.1.1.1')).toBe(true);
    db.close();
  });

  it('setFindingStatus updates status and returns the updated finding', () => {
    const db = openLensDb(':memory:');
    const finding = upsertFinding(db, applyTrigger(null, 'internal_source', 't0', 'source_ip', '9.9.9.9'));
    const updated = setFindingStatus(db, finding.id as number, 'dismissed');
    expect(updated?.status).toBe('dismissed');
    expect(getFinding(db, 'source_ip', '9.9.9.9')?.status).toBe('dismissed');
  });

  it('setFindingStatus returns null for a nonexistent finding id', () => {
    const db = openLensDb(':memory:');
    expect(setFindingStatus(db, 999, 'dismissed')).toBeNull();
  });
});
