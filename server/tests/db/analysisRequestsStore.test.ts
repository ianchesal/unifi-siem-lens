import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import {
  createAnalysisRequest,
  getPendingAnalysisRequests,
  submitAnalysis,
} from '../../src/db/analysisRequestsStore.js';

describe('analysisRequestsStore', () => {
  it('creates a pending request and lists it as pending', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const result = createAnalysisRequest(lensDb, finding.id as number, { note: 'ctx' }, 't1');
    expect('deduped' in result).toBe(false);
    expect(getPendingAnalysisRequests(lensDb)).toHaveLength(1);
  });

  it('dedupes a second request while one is still pending', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const first = createAnalysisRequest(lensDb, finding.id as number, {}, 't1');
    const second = createAnalysisRequest(lensDb, finding.id as number, {}, 't2');
    expect(second.id).toBe(first.id);
    expect(getPendingAnalysisRequests(lensDb)).toHaveLength(1);
  });

  it('allows a fresh request once the prior one is answered', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const first = createAnalysisRequest(lensDb, finding.id as number, {}, 't1');
    submitAnalysis(lensDb, first.id, 'looks benign', 'low', 't2');
    const second = createAnalysisRequest(lensDb, finding.id as number, {}, 't3');
    expect(second.id).not.toBe(first.id);
  });

  it('throws submitting to an already-answered request', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const req = createAnalysisRequest(lensDb, finding.id as number, {}, 't1');
    submitAnalysis(lensDb, req.id, 'first answer', 'low', 't2');
    expect(() => submitAnalysis(lensDb, req.id, 'second answer', 'low', 't3')).toThrow();
  });
});
