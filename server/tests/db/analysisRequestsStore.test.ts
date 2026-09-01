import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';
import {
  createAnalysisRequest,
  createAnsweredRuleAnalysis,
  getAnalysisRequestsForFinding,
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

  it('getAnalysisRequestsForFinding returns all requests for a finding, including answered ones', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const other = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '5.6.7.8'));
    const first = createAnalysisRequest(lensDb, finding.id as number, {}, 't1');
    submitAnalysis(lensDb, first.id, 'looks benign', 'low', 't2');
    const second = createAnalysisRequest(lensDb, finding.id as number, {}, 't3');
    createAnalysisRequest(lensDb, other.id as number, {}, 't4');

    const results = getAnalysisRequestsForFinding(lensDb, finding.id as number);
    expect(results).toHaveLength(2);
    expect(results.map((r) => r.id)).toEqual([first.id, second.id]);
    expect(results[0].status).toBe('answered');
    expect(results[0].recommendation).toBe('looks benign');
    expect(results[1].status).toBe('pending');
  });

  it('createAnsweredRuleAnalysis inserts an already-answered, rule-sourced request', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const request = createAnsweredRuleAnalysis(
      lensDb,
      finding.id as number,
      { finding },
      'auto-dismissed: routine blocklist scan',
      'low',
      't1'
    );
    expect(request.status).toBe('answered');
    expect(request.source).toBe('rule');
    expect(request.recommendation).toBe('auto-dismissed: routine blocklist scan');
    expect(request.risk_level).toBe('low');
    expect(request.answered_at).toBe('t1');
  });

  it('createAnalysisRequest (AI path) still defaults source to ai', () => {
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'internal_source', 't0', 'source_ip', '1.2.3.4'));
    const request = createAnalysisRequest(lensDb, finding.id as number, {}, 't1');
    expect(request.source).toBe('ai');
  });
});
