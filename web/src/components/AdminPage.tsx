import { useState } from 'react';

interface BackfillResult {
  checked: number;
  dismissed: number;
  byRule: {
    admin_login: number;
    operational_noise: number;
    reputation_blocklist: number;
  };
}

const RULE_LABELS: Record<keyof BackfillResult['byRule'], string> = {
  admin_login: 'admin-audit-login rule',
  operational_noise: 'operational-noise rule',
  reputation_blocklist: 'reputation-blocklist rule',
};

export function AdminPage() {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<BackfillResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runBackfill = async () => {
    setRunning(true);
    setError(null);
    try {
      const res = await fetch('/api/admin/backfill-rule-triage', { method: 'POST' });
      if (!res.ok) throw new Error(`Request failed: ${res.status}`);
      setResult(await res.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="main">
      <div className="page-head">
        <div>
          <h1 className="page-title">Admin</h1>
          <p className="page-subtitle">Maintenance actions for unifi-siem-lens</p>
        </div>
      </div>

      <div className="section">
        <div className="section-head">
          <h2 className="section-title">Rule-triage backfill</h2>
        </div>
        <p style={{ color: 'var(--text-secondary)' }}>
          Re-checks existing new/acknowledged findings against the auto-triage rules (admin
          logins, WAN noise, blocklist scans). Findings created before rule-based triage existed
          — or before it was configured — never got a rule pass; this catches them up.
        </p>
        <button className="btn btn-primary" type="button" disabled={running} onClick={runBackfill}>
          {running ? 'Running…' : 'Run backfill'}
        </button>

        {error && <p style={{ color: 'var(--critical)' }}>{error}</p>}

        {result && (
          <div className="analysis-panel">
            <p className="analysis-body">
              Checked {result.checked} finding{result.checked === 1 ? '' : 's'} · {result.dismissed} auto-dismissed
            </p>
            {result.dismissed > 0 && (
              <ul>
                {(Object.entries(result.byRule) as [keyof BackfillResult['byRule'], number][])
                  .filter(([, count]) => count > 0)
                  .map(([rule, count]) => (
                    <li key={rule}>
                      {count} via {RULE_LABELS[rule]}
                    </li>
                  ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
