import { useEffect, useState } from 'react';
import { fetchJson } from './api';
import { EventsOverTimeChart } from './components/EventsOverTimeChart';
import { FindingsList } from './components/FindingsList';
import { KpiStats } from './components/KpiStats';
import { SeverityChart } from './components/SeverityChart';
import { TopSignaturesChart } from './components/TopSignaturesChart';
import { TopSourceIpsChart } from './components/TopSourceIpsChart';
import { RefreshIcon, ShieldIcon } from './icons';

interface Health {
  status: 'ok' | 'degraded';
  sinkDb: 'available' | 'unavailable';
}

const RANGES = [
  { label: '24h', days: 1 },
  { label: '7d', days: 7 },
  { label: '30d', days: 30 },
];

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [sinceDays, setSinceDays] = useState(7);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    fetchJson<Health>('/health').then(setHealth).catch(() => setHealth(null));
  }, [refreshKey]);

  const sinkAvailable = health?.sinkDb === 'available';

  return (
    <>
      <div className="topbar">
        <div className="brand">
          <ShieldIcon size={28} />
          <div className="brand-text">
            <span className="brand-name">UniFi SIEM Lens</span>
            <span className="brand-sub">Security dashboard</span>
          </div>
        </div>
        <div className="topbar-right">
          <div className={`status-pill${sinkAvailable ? '' : ' offline'}`}>
            <span className="status-dot" />
            {health === null ? 'Checking sink…' : sinkAvailable ? 'Sink connected' : 'Sink unavailable'}
          </div>
          <button className="icon-btn" type="button" aria-label="Refresh" onClick={() => setRefreshKey((k) => k + 1)}>
            <RefreshIcon />
          </button>
        </div>
      </div>

      <div className="main">
        <div className="page-head">
          <div>
            <h1 className="page-title">Security overview</h1>
            <p className="page-subtitle">Heuristic findings and event trends across your UniFi network</p>
          </div>
          <div className="range-toggle">
            {RANGES.map((r) => (
              <button
                key={r.label}
                type="button"
                className={`range-opt${sinceDays === r.days ? ' active' : ''}`}
                onClick={() => setSinceDays(r.days)}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>

        <KpiStats refreshKey={refreshKey} />

        <div className="section">
          <div className="section-head">
            <h2 className="section-title">Trends</h2>
            <span className="section-count">last {sinceDays}d</span>
          </div>
          <div className="charts-grid-top">
            <EventsOverTimeChart sinceDays={sinceDays} />
          </div>
          <div className="charts-grid">
            <TopSignaturesChart sinceDays={sinceDays} />
            <TopSourceIpsChart sinceDays={sinceDays} />
            <SeverityChart sinceDays={sinceDays} />
          </div>
        </div>

        <FindingsList refreshKey={refreshKey} />
      </div>

      <footer>
        <span className="footer-text">unifi-siem-lens · read-only analysis layer over unifi-siem-sink</span>
      </footer>
    </>
  );
}
