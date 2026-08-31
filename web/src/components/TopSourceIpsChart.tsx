import { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis } from 'recharts';
import { fetchJson } from '../api';

interface Row {
  source_ip: string;
  count: number;
}

export function TopSourceIpsChart() {
  const [rows, setRows] = useState<Row[]>([]);

  useEffect(() => {
    fetchJson<Row[]>('/api/stats/top-source-ips?sinceDays=7&limit=10').then(setRows).catch(() => setRows([]));
  }, []);

  return (
    <div>
      <h2>Top source IPs (7d)</h2>
      <BarChart width={700} height={300} data={rows} layout="vertical">
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis type="number" />
        <YAxis type="category" dataKey="source_ip" width={150} />
        <Tooltip />
        <Bar dataKey="count" fill="#d6603b" />
      </BarChart>
    </div>
  );
}
