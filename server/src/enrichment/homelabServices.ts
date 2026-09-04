import { existsSync, readFileSync } from 'node:fs';

// Private, per-deployment knowledge of what's actually running on a LAN
// host (e.g. a homelab server hosting a stack of Docker containers) — never
// committed to the repo. See homelab-services.example.json for the shape.
// Loading is tolerant of a missing file, same pattern as openSinkDb/config:
// this enrichment is optional and must never block startup or analysis.

export interface HomelabService {
  port: number;
  name: string;
  description?: string;
}

export interface HomelabHost {
  label: string;
  // Standing, host-wide context that doesn't map to a single port (e.g.
  // "Plex remote access is in use on tranquility") — surfaced on every
  // event matching this host, regardless of which service/port it hit.
  notes?: string[];
  services: HomelabService[];
}

export type HomelabRegistry = Record<string, HomelabHost>;

export function loadHomelabServices(path: string): HomelabRegistry {
  if (!existsSync(path)) return {};
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8'));
    return parsed as HomelabRegistry;
  } catch {
    // Malformed local config must not crash the server — enrichment is optional.
    return {};
  }
}

export function lookupHomelabService(
  registry: HomelabRegistry,
  ip: string,
  port: number | null
): { host: string; notes: string[]; service: HomelabService | null } | null {
  const host = registry[ip];
  if (!host) return null;
  const service = port === null ? null : (host.services.find((s) => s.port === port) ?? null);
  return { host: host.label, notes: host.notes ?? [], service };
}

// Attaches a homelab match to each event's dest_ip/dest_port, for events
// aimed at a known local host — additive prompt context for the Claude Code
// analysis handoff, never a triage verdict on its own.
export function annotateHomelabDestinations<
  T extends { dest_ip: string | null; dest_port: number | null },
>(
  events: T[],
  registry: HomelabRegistry
): (T & { homelab: ReturnType<typeof lookupHomelabService> })[] {
  return events.map((event) => ({
    ...event,
    homelab: event.dest_ip ? lookupHomelabService(registry, event.dest_ip, event.dest_port) : null,
  }));
}
