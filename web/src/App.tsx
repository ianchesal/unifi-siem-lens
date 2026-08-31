import { useEffect, useState } from 'react';
import { fetchJson } from './api';

interface SignatureCount {
  signature: string;
  count: number;
}

export default function App() {
  const [signatures, setSignatures] = useState<SignatureCount[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchJson<SignatureCount[]>('/api/stats/top-signatures')
      .then(setSignatures)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <div style={{ fontFamily: 'sans-serif', padding: '2rem' }}>
      <h1>unifi-siem-lens</h1>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {!error && !signatures && <p>Loading...</p>}
      {signatures && (
        <ul>
          {signatures.map((s) => (
            <li key={s.signature}>
              {s.signature}: {s.count}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
