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

export function FindingsList() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    fetchJson<Finding[]>('/api/findings')
      .then(setFindings)
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

  if (error) return <p style={{ color: 'red' }}>{error}</p>;

  return (
    <section>
      <h2>Findings</h2>
      {findings.length === 0 && <p>No open findings.</p>}
      <ul>
        {findings.map((f) => (
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
          </li>
        ))}
      </ul>
    </section>
  );
}
