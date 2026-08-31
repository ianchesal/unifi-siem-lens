import { EventsOverTimeChart } from './components/EventsOverTimeChart';
import { FindingsList } from './components/FindingsList';
import { SeverityChart } from './components/SeverityChart';
import { TopSignaturesChart } from './components/TopSignaturesChart';
import { TopSourceIpsChart } from './components/TopSourceIpsChart';

export default function App() {
  return (
    <div style={{ fontFamily: 'sans-serif', padding: '2rem' }}>
      <h1>unifi-siem-lens</h1>
      <FindingsList />
      <EventsOverTimeChart />
      <TopSignaturesChart />
      <TopSourceIpsChart />
      <SeverityChart />
    </div>
  );
}
