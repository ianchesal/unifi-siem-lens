import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';
import { SEVERITY_COLORS, severityBand } from '../severity';

interface Row {
  severity: number | null;
  count: number;
}

export function SeverityChart({ sinceDays }: { sinceDays: number }) {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>(`/api/stats/severity-distribution?sinceDays=${sinceDays}`)
      .then((r) => setRows(r.map((x) => ({ ...x, severity: x.severity ?? -1 }))))
      .catch(() => setRows([]));
  }, [sinceDays]);

  return (
    <div className="chart-card">
      <div className="chart-head">
        <span className="chart-title">Severity distribution</span>
        <span className="chart-window">{sinceDays}d</span>
      </div>
      {rows.length === 0 ? (
        <div className="chart-empty">No findings in this range.</div>
      ) : (
        <ResponsiveContainer width="100%" height={272}>
          <BarChart data={rows} margin={{ left: -20 }}>
            <CartesianGrid stroke="#262b36" strokeDasharray="0" vertical={false} />
            <XAxis dataKey="severity" stroke="#383f4d" tick={{ fill: '#626b7d', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }} />
            <YAxis stroke="#383f4d" tick={{ fill: '#626b7d', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#1a1e29', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#f4f6fa' }}
              itemStyle={{ color: '#99a2b3' }}
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]}>
              {rows.map((r) => (
                <Cell key={r.severity} fill={SEVERITY_COLORS[severityBand(r.severity ?? -1)]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
