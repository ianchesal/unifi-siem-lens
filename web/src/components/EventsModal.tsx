import { useEffect, useState } from 'react';
import { fetchJson } from '../api';

interface StoredEvent {
  id: number;
  received_at: string;
  category: string;
  severity: number | null;
  source_ip: string | null;
  dest_ip: string | null;
  action: string | null;
  signature: string | null;
  message: string | null;
  raw: string;
}

const UNIFI_REFERENCE_RE = /(?:^|\s)UNIFIreference=(\S+)/;

function extractUnifiReference(raw: string): string | null {
  return raw.match(UNIFI_REFERENCE_RE)?.[1] ?? null;
}

export function EventsModal({ findingId, onClose }: { findingId: number; onClose: () => void }) {
  const [events, setEvents] = useState<StoredEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchJson<StoredEvent[]>(`/api/findings/${findingId}/events`)
      .then(setEvents)
      .catch((e) => setError(String(e)));
  }, [findingId]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    // biome-ignore lint/a11y/useKeyWithClickEvents: Escape is handled globally above; this is a backdrop dismiss
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3 className="modal-title">Raw events</h3>
          <button className="icon-btn" type="button" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="modal-body">
          {error && <p style={{ color: 'var(--critical)' }}>{error}</p>}
          {!error && events === null && <p style={{ color: 'var(--text-secondary)' }}>Loading…</p>}
          {!error && events?.length === 0 && (
            <p style={{ color: 'var(--text-secondary)' }}>No raw events found.</p>
          )}
          {events?.map((e) => {
            const reference = extractUnifiReference(e.raw);
            return (
              <div key={e.id} className="event-card">
                <div className="event-head">
                  <span className="timestamp">{new Date(e.received_at).toLocaleString()}</span>
                  {e.action && <span className={`event-action ${e.action}`}>{e.action}</span>}
                </div>
                {(e.source_ip || e.dest_ip) && (
                  <div className="event-flow">
                    {e.source_ip ?? '—'} → {e.dest_ip ?? '—'}
                  </div>
                )}
                {e.signature && <div className="event-signature">{e.signature}</div>}
                {e.message && <p className="event-message">{e.message}</p>}
                {reference && (
                  <a
                    className="event-reference"
                    href={reference}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Read reference ↗
                  </a>
                )}
                <details className="event-raw">
                  <summary>raw CEF</summary>
                  <pre>{e.raw}</pre>
                </details>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
