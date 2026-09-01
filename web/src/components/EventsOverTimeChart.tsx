import { useEffect, useState } from 'react';
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';

interface Row {
  day: string;
  category: string;
  count: number;
}

const CATEGORY_COLORS = ['#3987e5', '#d95926', '#199e70', '#9085e9', '#eda100', '#e34948'];

export function EventsOverTimeChart({ sinceDays }: { sinceDays: number }) {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>(`/api/stats/events-over-time?sinceDays=${sinceDays}`)
      .then(setRows)
      .catch(() => setRows([]));
  }, [sinceDays]);

  const days = [...new Set(rows.map((r) => r.day))].sort();
  const categories = [...new Set(rows.map((r) => r.category))];
  const data = days.map((day) => {
    const point: Record<string, number | string> = { day };
    for (const cat of categories) {
      point[cat] = rows.find((r) => r.day === day && r.category === cat)?.count ?? 0;
    }
    return point;
  });

  return (
    <div className="chart-card">
      <div className="chart-head">
        <span className="chart-title">Events over time</span>
        <span className="chart-window">by category</span>
      </div>
      {data.length === 0 ? (
        <div className="chart-empty">No events in this range.</div>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={data} margin={{ left: -12 }}>
            <CartesianGrid stroke="#262b36" strokeDasharray="0" vertical={false} />
            <XAxis dataKey="day" stroke="#383f4d" tick={{ fill: '#626b7d', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }} />
            <YAxis stroke="#383f4d" tick={{ fill: '#626b7d', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#1a1e29', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#f4f6fa' }}
              itemStyle={{ color: '#99a2b3' }}
            />
            <Legend wrapperStyle={{ fontSize: 12, color: '#99a2b3' }} />
            {categories.map((cat, i) => (
              <Line
                key={cat}
                type="monotone"
                dataKey={cat}
                stroke={CATEGORY_COLORS[i % CATEGORY_COLORS.length]}
                strokeWidth={2.5}
                dot={false}
                activeDot={{ r: 4 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
