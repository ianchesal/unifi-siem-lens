import { useEffect, useState } from 'react';
import { fetchJson } from '../api';

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
}

interface AnalysisRequest {
  id: number;
  finding_id: number;
  status: 'pending' | 'answered';
  recommendation: string | null;
  risk_level: string | null;
}

export function FindingsList() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [requests, setRequests] = useState<Record<number, AnalysisRequest[]>>({});
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    fetchJson<Finding[]>('/api/findings')
      .then(async (fs) => {
        setFindings(fs);
        const entries = await Promise.all(
          fs.map(async (f) => [f.id, await fetchJson<AnalysisRequest[]>(`/api/analysis-requests?findingId=${f.id}`)] as const)
        );
        setRequests(Object.fromEntries(entries));
      })
      .catch((e) => setError(String(e)));
  };

  useEffect(load, []);

  const setStatus = async (id: number, status: 'acknowledged' | 'dismissed') => {
    await fetch(`/api/findings/${id}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    load();
  };

  const analyze = async (id: number) => {
    await fetch(`/api/findings/${id}/analyze`, { method: 'POST' });
    load();
  };

  if (error) return <p style={{ color: 'red' }}>{error}</p>;

  return (
    <section>
      <h2>Findings</h2>
      {findings.length === 0 && <p>No open findings.</p>}
      <ul>
        {findings.map((f) => {
          const finReqs = requests[f.id] ?? [];
          const pending = finReqs.find((r) => r.status === 'pending');
          const answered = finReqs.filter((r) => r.status === 'answered').at(-1);
          return (
            <li key={f.id}>
              <strong>{f.entity_key}</strong> ({f.entity_type}) — severity {f.severity_score} — {f.status}
              <div>
                {f.triggers.map((t) => (
                  <span key={t.type} style={{ marginRight: '0.5rem', opacity: t.active ? 1 : 0.5 }}>
                    [{t.type}{t.active ? '' : ' (inactive)'}]
                  </span>
                ))}
              </div>
              {f.status !== 'dismissed' && f.status !== 'acknowledged' && (
                <>
                  <button type="button" onClick={() => setStatus(f.id, 'acknowledged')}>
                    Acknowledge
                  </button>
                  <button type="button" onClick={() => setStatus(f.id, 'dismissed')}>
                    Dismiss
                  </button>
                </>
              )}
              <button type="button" disabled={!!pending} onClick={() => analyze(f.id)}>
                {pending ? 'Analysis pending...' : 'Analyze this'}
              </button>
              {answered && (
                <div style={{ border: '1px solid #ccc', padding: '0.5rem', marginTop: '0.5rem' }}>
                  <strong>Risk: {answered.risk_level}</strong>
                  <p>{answered.recommendation}</p>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
