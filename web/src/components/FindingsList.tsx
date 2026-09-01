import { useEffect, useState } from 'react';
import { fetchJson } from '../api';
import { GlobeIcon, SeverityIcon, SignatureIcon, STANDING_TRIGGER_TYPES, TRIGGER_ICONS, TRIGGER_LABELS } from '../icons';
import { severityBand } from '../severity';

interface Trigger {
  type: string;
  active: boolean;
}

interface Finding {
  id: number;
  entity_type: string;
  entity_key: string;
  triggers: Trigger[];
  severity_score: number;
  status: string;
  first_seen: string;
}

interface AnalysisRequest {
  id: number;
  finding_id: number;
  status: 'pending' | 'answered';
  recommendation: string | null;
  risk_level: string | null;
  source: 'ai' | 'rule';
  answered_at?: string | null;
}

const RISK_STYLE: Record<string, { bg: string; color: string }> = {
  low: { bg: 'var(--good-soft)', color: 'var(--good)' },
  medium: { bg: 'var(--warning-soft)', color: '#f7c860' },
  high: { bg: 'var(--critical-soft)', color: '#f28c88' },
};

function entityIcon(entityType: string) {
  return entityType === 'signature' ? <SignatureIcon /> : <GlobeIcon />;
}

function relativeTime(iso: string | undefined): string | null {
  if (!iso) return null;
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return null;
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${Math.max(mins, 0)}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const STATUS_TABS = [
  { key: 'active', label: 'Active' },
  { key: 'new', label: 'New' },
  { key: 'acknowledged', label: 'Acknowledged' },
  { key: 'dismissed', label: 'Dismissed' },
  { key: 'resolved', label: 'Resolved' },
  { key: 'all', label: 'All' },
] as const;

type StatusTab = (typeof STATUS_TABS)[number]['key'];

export function FindingsList({ refreshKey }: { refreshKey: number }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [requests, setRequests] = useState<Record<number, AnalysisRequest[]>>({});
  const [error, setError] = useState<string | null>(null);
  const [statusTab, setStatusTab] = useState<StatusTab>('active');

  const load = () => {
    const query = statusTab === 'active' ? '' : `?status=${statusTab}`;
    fetchJson<Finding[]>(`/api/findings${query}`)
      .then(async (fs) => {
        setFindings(fs);
        const entries = await Promise.all(
          fs.map(async (f) => [f.id, await fetchJson<AnalysisRequest[]>(`/api/analysis-requests?findingId=${f.id}`)] as const)
        );
        setRequests(Object.fromEntries(entries));
      })
      .catch((e) => setError(String(e)));
  };

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey drives a manual reload, not a data dependency
  useEffect(load, [refreshKey, statusTab]);

  const setStatus = async (id: number, status: 'acknowledged' | 'dismissed') => {
    await fetch(`/api/findings/${id}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    load();
  };

  const requestAnalysis = (id: number) => fetch(`/api/findings/${id}/analyze`, { method: 'POST' });

  const analyze = async (id: number) => {
    await requestAnalysis(id);
    load();
  };

  const sorted = [...findings].sort((a, b) => b.severity_score - a.severity_score);
  const analyzable = sorted.filter((f) => !(requests[f.id] ?? []).some((r) => r.status === 'pending'));

  const analyzeAll = async () => {
    await Promise.all(analyzable.map((f) => requestAnalysis(f.id)));
    load();
  };

  return (
    <div className="section">
      <div className="section-head">
        <h2 className="section-title">Findings</h2>
        <div className="section-head-right">
          <span className="section-count">
            {sorted.length} shown{sorted.length > 0 ? ' · sorted by priority' : ''}
          </span>
          <button className="btn btn-ghost" type="button" disabled={analyzable.length === 0} onClick={analyzeAll}>
            Analyze all{analyzable.length > 0 ? ` (${analyzable.length})` : ''}
          </button>
        </div>
      </div>

      <div className="status-tabs">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className={`status-tab${statusTab === tab.key ? ' is-active' : ''}`}
            onClick={() => setStatusTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {error && <p style={{ color: 'var(--critical)' }}>{error}</p>}
      {!error && sorted.length === 0 && <p style={{ color: 'var(--text-secondary)' }}>No findings in this view.</p>}

      <div className="findings-list">
        {sorted.map((f) => {
          const band = severityBand(f.severity_score);
          const finReqs = requests[f.id] ?? [];
          const pending = finReqs.find((r) => r.status === 'pending');
          const answered = finReqs.filter((r) => r.status === 'answered').at(-1);
          const canActOn = f.status !== 'dismissed' && f.status !== 'acknowledged';
          const seenAgo = relativeTime(f.first_seen);

          return (
            <div key={f.id} className={`finding-card${band === 'crit' ? ' is-critical' : ''}`}>
              <div className="finding-top">
                <div className="finding-id-row">
                  <div className="entity-type-icon">{entityIcon(f.entity_type)}</div>
                  <div>
                    <div className="entity-key">{f.entity_key}</div>
                    <div className="entity-type">{f.entity_type.replace('_', ' ')}</div>
                  </div>
                  <span className={`status-badge ${f.status}`}>{f.status}</span>
                </div>
                <span className={`severity-chip ${band}`}>
                  {band !== 'low' && <SeverityIcon />}
                  Priority {f.severity_score}
                </span>
              </div>

              <div className="trigger-row">
                {f.triggers.map((t) => {
                  const Icon = TRIGGER_ICONS[t.type];
                  const isStanding = STANDING_TRIGGER_TYPES.has(t.type);
                  const classes = ['trigger-chip'];
                  if (t.active && isStanding) classes.push('active-standing');
                  if (!t.active) classes.push('inactive');
                  return (
                    <div key={t.type} className={classes.join(' ')}>
                      {Icon && <Icon />}
                      <span className="chip-status">{TRIGGER_LABELS[t.type] ?? t.type}</span>
                    </div>
                  );
                })}
              </div>

              <div className="finding-actions">
                {canActOn && (
                  <>
                    <button className="btn btn-ghost" type="button" onClick={() => setStatus(f.id, 'acknowledged')}>
                      Acknowledge
                    </button>
                    <button className="btn btn-danger-ghost" type="button" onClick={() => setStatus(f.id, 'dismissed')}>
                      Dismiss
                    </button>
                  </>
                )}
                <span className="spacer" />
                {seenAgo && <span className="timestamp">first seen {seenAgo}</span>}
                <button className="btn btn-primary" type="button" disabled={!!pending} onClick={() => analyze(f.id)}>
                  {pending ? 'Analysis pending…' : answered ? 'Re-analyze' : 'Analyze this'}
                </button>
              </div>

              {answered && (
                <div className="analysis-panel">
                  <div className="analysis-head">
                    <span
                      className="analysis-badge"
                      style={
                        answered.risk_level && RISK_STYLE[answered.risk_level]
                          ? { background: RISK_STYLE[answered.risk_level].bg, color: RISK_STYLE[answered.risk_level].color }
                          : undefined
                      }
                    >
                      Risk: {answered.risk_level ?? 'unknown'}
                    </span>
                    {relativeTime(answered.answered_at ?? undefined) && (
                      <span className="analysis-source">
                        {answered.source === 'rule' ? 'auto-triaged by rule' : 'via Claude Code'} · submitted{' '}
                        {relativeTime(answered.answered_at ?? undefined)}
                      </span>
                    )}
                  </div>
                  <p className="analysis-body">{answered.recommendation}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
