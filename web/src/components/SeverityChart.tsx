import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';

interface Row {
  severity: number | null;
  count: number;
}

export function SeverityChart() {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>('/api/stats/severity-distribution?sinceDays=7')
      .then((r) => setRows(r.map((x) => ({ ...x, severity: x.severity ?? -1 }))))
      .catch(() => setRows([]));
  }, []);

  return (
    <div>
      <h2>Severity distribution (7d)</h2>
      <BarChart width={700} height={300} data={rows}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="severity" />
        <YAxis />
        <Tooltip />
        <Bar dataKey="count" fill="#7a3bd6" />
      </BarChart>
    </div>
  );
}
