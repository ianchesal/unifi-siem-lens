import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';

interface Row {
  source_ip: string;
  count: number;
}

const LIMIT = 8;

export function TopSourceIpsChart({ sinceDays }: { sinceDays: number }) {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>(`/api/stats/top-source-ips?sinceDays=${sinceDays}&limit=${LIMIT}`)
      .then(setRows)
      .catch(() => setRows([]));
  }, [sinceDays]);

  return (
    <div className="chart-card">
      <div className="chart-head">
        <span className="chart-title">Top source IPs</span>
        <span className="chart-window">{sinceDays}d</span>
      </div>
      {rows.length === 0 ? (
        <div className="chart-empty">No source IPs in this range.</div>
      ) : (
        <ResponsiveContainer width="100%" height={LIMIT * 34}>
          <BarChart data={rows} layout="vertical" margin={{ left: 8 }}>
            <CartesianGrid stroke="#262b36" strokeDasharray="0" horizontal={false} />
            <XAxis type="number" stroke="#383f4d" tick={{ fill: '#626b7d', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }} allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="source_ip"
              width={110}
              stroke="#383f4d"
              tick={{ fill: '#99a2b3', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }}
            />
            <Tooltip
              contentStyle={{ background: '#1a1e29', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#f4f6fa' }}
              itemStyle={{ color: '#99a2b3' }}
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
            />
            <Bar dataKey="count" fill="#d95926" radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
