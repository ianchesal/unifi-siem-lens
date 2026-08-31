import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';

interface Row {
  signature: string;
  count: number;
}

export function TopSignaturesChart() {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>('/api/stats/top-signatures?sinceDays=7&limit=10').then(setRows).catch(() => setRows([]));
  }, []);

  return (
    <div>
      <h2>Top signatures (7d)</h2>
      <BarChart width={700} height={300} data={rows} layout="vertical">
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis type="number" />
        <YAxis type="category" dataKey="signature" width={200} />
        <Tooltip />
        <Bar dataKey="count" fill="#3b6fd6" />
      </BarChart>
    </div>
  );
}
