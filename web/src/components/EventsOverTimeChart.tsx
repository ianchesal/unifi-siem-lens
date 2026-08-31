import { useEffect, useState } from 'react';
import { CartesianGrid, Legend, Line, LineChart, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';

interface Row {
  day: string;
  category: string;
  count: number;
}

export function EventsOverTimeChart() {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>('/api/stats/events-over-time?sinceDays=30').then(setRows).catch(() => setRows([]));
  }, []);

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
    <div>
      <h2>Events over time</h2>
      <LineChart width={700} height={300} data={data}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="day" />
        <YAxis />
        <Tooltip />
        <Legend />
        {categories.map((cat, i) => (
          <Line key={cat} type="monotone" dataKey={cat} stroke={`hsl(${(i * 67) % 360}, 65%, 45%)`} />
        ))}
      </LineChart>
    </div>
  );
}
