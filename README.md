# UniFi SIEM Lens

Visualization dashboard and code-driven analysis layer for UniFi IDS/IPS
security events — trend charts, anomaly/repeat-offender detection, and a
"queue for Claude" handoff so a Claude Code session can turn a flagged
finding into an actual recommendation, without this service needing any
API key of its own.

![UniFi SIEM Lens dashboard: KPI cards for open findings, critical severity, 24h events, and repeat offenders; trend charts for events over time, top signatures, top source IPs, and severity distribution; and a findings list with acknowledge/dismiss/analyze actions.](docs/images/dashboard.png)

## Why this exists

This is the third of three companion projects for running an LLM against a
UDM Pro:

- [`unifi-mcp-server`](https://github.com/ianchesal/unifi-mcp-server) —
  exposes the UniFi Network API (firewall rules, networks, clients, traffic
  rules, port forwarding, monitoring) as MCP tools.
- [`unifi-siem-sink`](https://github.com/ianchesal/unifi-siem-sink) —
  listens for UniFi's SIEM/syslog export and stores IPS/IDS and
  Security-category events (the one thing the Network API doesn't expose)
  in SQLite, queryable over MCP.
- **`unifi-siem-lens`** (this project) — sits on top of `unifi-siem-sink`'s
  event store. Where the other two projects hand raw data to an LLM one
  query at a time, lens does the first pass itself: it runs scheduled,
  code-driven heuristics (new signature/source-IP detection, internal-source
  flagging, repeat-offender tracking, statistical anomaly detection) against
  the sink's event history, turns anything interesting into a *finding*, and
  renders trends and findings on a dashboard. When a finding is worth a
  closer look, one click queues it for analysis — a Claude Code session
  (running on your Claude subscription, no separate API key) checks in over
  MCP, reasons about the finding with the real events as context, and posts
  a recommendation back into the app.
  A second, purely code-driven layer goes further for the common case: a
  handful of rules (a trusted admin's own console login, WAN/operational
  noise, a blocked hit from a known reputation/blocklist IDS signature)
  auto-dismiss a finding the moment it's detected, with no Claude Code
  session involved at all — see [Rule-based auto-triage](#rule-based-auto-triage) below.

Run all three and an LLM gets full visibility into the network (via
`unifi-mcp-server`), full visibility into the security event stream (via
`unifi-siem-sink`), and a standing analyst that's already triaged the noise
before you ever open a chat (via `unifi-siem-lens`).

## Quick Start (Docker)

Requires `unifi-siem-sink` already running as a container — lens reads its
event database read-only via `--volumes-from`.

### 1. Create a `.env` file

```bash
SINK_DB_PATH=/data/events.db
LAN_CIDRS=10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
MCP_SECRET=<choose-a-strong-secret>
```

`SINK_DB_PATH=/data/events.db` matches the mount point `unifi-siem-sink`
uses internally — see step 2.

### 2. Run the container

```bash
docker run -d \
  --name unifi-siem-lens \
  --env-file .env \
  -p 3002:3002 \
  -v unifi-siem-lens-data:/lens-data \
  --volumes-from unifi-siem-sink:ro \
  ghcr.io/ianchesal/unifi-siem-lens:latest
```

`--volumes-from unifi-siem-sink:ro` mounts the sink container's `/data`
volume (containing `events.db`) into this container read-only, at the same
path. If your sink container has a different name (check with
`docker ps`), or you're running it via `docker compose` under a different
project name, adjust `unifi-siem-sink` above to match.

### 3. Open the dashboard

`http://<homelab-ip>:3002`

### 4. Add to Claude Code for the analysis handoff

```json
{
  "mcpServers": {
    "unifi-siem-lens": {
      "type": "http",
      "url": "http://<homelab-ip>:3002/mcp",
      "headers": { "Authorization": "Bearer <your-MCP_SECRET>" }
    }
  }
}
```

Then, in a Claude Code session with this configured, ask it to check for
pending analyses. It'll fetch any findings you've queued from the
dashboard, reason about them with the actual event context, and post
recommendations back — which then show up next to the finding.

## Dashboard & MCP tools

| Surface | What it gives you |
|---|---|
| Dashboard (`/`) | Events-over-time, top signatures, top source IPs, and severity-distribution charts; a findings list with status tabs (Active/New/Acknowledged/Dismissed/Resolved/All), an "Analyze all" button, and per-finding Acknowledge/Dismiss/Analyze actions. Each answered finding shows whether its recommendation came "via Claude Code" or was "auto-triaged by rule". |
| Admin (`/admin`) | One-off maintenance actions — currently just the rule-triage backfill (see below). |
| `GET /health` | Liveness + sink DB / schema-contract status. |
| `POST /api/admin/backfill-rule-triage` | Re-checks every existing `new`/`acknowledged` finding against the auto-triage rules; returns `{ checked, dismissed, byRule }`. |
| `get_pending_analyses` (MCP) | List analysis requests queued from the dashboard, awaiting a recommendation. |
| `get_analysis_context` (MCP) | Full context for one request: the finding, its trigger/baseline history, and the relevant raw events. |
| `submit_analysis` (MCP) | Post a recommendation + risk level back for a pending request. |

## Rule-based auto-triage

Most findings a live network throws off don't need an LLM at all: your own
console logins, the gateway's WAN-health blips, and routine reputation-list
scans that UniFi already auto-blocked. Rather than queuing every one of
these for a Claude Code session, lens checks each new `new_signature`/
`new_source_ip` finding against three rules the moment it's detected, and
auto-dismisses it — with a canned, code-generated recommendation, no
Claude Code session involved — if every event behind it is fully explained
by one of them:

1. **Trusted admin login** — a console login from an admin name in
   `TRUSTED_ADMIN_NAMES` (see [Environment Variables](#environment-variables) below; empty by default, so this rule never fires unconfigured).
2. **Operational noise** — WAN/device-health telemetry, not a security
   signal.
3. **Reputation/blocklist scan** — a blocked hit from a known
   reputation-feed IDS signature family (`SAFE_SIGNATURE_PREFIXES`).

A finding that isn't *fully* explained by a rule (mixed events, an
unrecognized signature, an untrusted admin name) is left alone exactly as
before — it still needs a manual "Analyze this" and a Claude Code session.

Because this only runs at the moment a finding is first created, findings
already sitting in the database before you configure `TRUSTED_ADMIN_NAMES`
(or before you upgrade to a lens version that has this feature) never get a
rule pass on their own. Visit **`/admin`** and click **Run backfill** to
sweep the auto-triage rules over your existing `new`/`acknowledged`
findings — safe to run repeatedly, it only ever touches findings still
sitting at those two statuses.

## Homelab/local-service enrichment

An IDS finding pointing at `192.168.1.26:8989` means nothing to a Claude
Code session unless it also knows `192.168.1.26:8989` is your own Sonarr
instance, not a mystery host. `HOMELAB_SERVICES_PATH` points lens at a
local JSON file mapping LAN IPs to the services running on them (typically
the containers on a homelab/NAS box), so that context is attached
automatically whenever a finding involving that IP is queued for analysis.

This is deliberately **not** something you configure by pointing lens at
your Docker Compose files or infrastructure repo directly — the file is a
static, hand-maintained snapshot that lives outside git, so your homelab's
layout never ends up in this (public) repo's history or a published Docker
image.

**Setup:**

1. Copy the template: `cp server/homelab-services.example.json server/data/homelab-services.json`
   (the default `HOMELAB_SERVICES_PATH`; set the env var if you'd rather
   keep it elsewhere).
2. Fill in your own hosts and ports:

   ```json
   {
     "192.168.1.26": {
       "label": "tranquility (homelab)",
       "services": [
         { "port": 8989, "name": "sonarr", "description": "TV show PVR" },
         { "port": 8080, "name": "qbittorrent", "description": "torrent client WebUI" }
       ]
     }
   }
   ```

   Keys are the destination IPs as they appear in `events.db`; `services`
   is matched against each event's `dest_port`. An IP present with no
   matching port still returns the host `label`, so you get partial credit
   ("this is at least *a* known host") even for ports you haven't listed.
3. Restart lens. The file is loaded once at startup — like `SINK_DB_PATH`,
   a missing or malformed file is a silent no-op, never a startup failure.

**What it affects:** only the context bundle built when a finding is
queued via **Analyze** (`POST /findings/:id/analyze`) — each recent event
in that bundle gets a `homelab: { host, service }` field the analyzing
Claude Code session sees alongside the raw event. It has no effect on the
dashboard, the rule-based auto-triage layer, or findings already queued
before the file existed — re-run **Analyze** on a finding to pick up a
newer version of the file.

`server/homelab-services.example.json` (checked in) documents the shape
with placeholder values; `server/data/homelab-services.json` (gitignored,
matching the `data/` pattern used for `lens.db`) is where your real
mapping goes — see [Environment Variables](#environment-variables) below
for `HOMELAB_SERVICES_PATH`.

## Claude Code skill: analyzing findings

If you're working in this repo with Claude Code, `server/.claude/skills/analyzing-findings/`
ships a skill (scoped to the `server` workspace, since it drives the MCP
analysis handoff) that automates the ad hoc "check for pending analyses"
workflow beyond what a plain request to Claude Code does on its own:

- Drains the entire `get_pending_analyses` queue, not just one request.
- Enriches each finding by resolving source/destination IPs to hostnames
  via `unifi-mcp-server`'s client list, when that server is configured and
  reachable (falls back to IP-only otherwise).
- Cross-references findings in the same batch that share a root cause
  (same source IP or signature) so their recommendations note the
  connection instead of being analyzed in isolation.
- After answering each finding, flags any that look like good candidates
  for a new [rule-based auto-triage](#rule-based-auto-triage) rule —
  a low-risk, fully-explained pattern that has recurred and isn't already
  covered by an existing rule — without writing the rule code itself; that
  stays a deliberate, reviewed change to `ruleTriage.ts`.

Ask a Claude Code session working in this repo to "reanalyze findings" or
invoke it directly as `/server:analyzing-findings`.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SINK_DB_PATH` | yes | — | Path to `unifi-siem-sink`'s `events.db`, opened read-only |
| `MCP_SECRET` | yes | — | Bearer token clients must send as `Authorization: Bearer <MCP_SECRET>` to call `/mcp` |
| `PORT` | no | `3002` | Port the dashboard/API/MCP server listens on |
| `HOST` | no | `127.0.0.1` | Bind address. Defaults to localhost-only — the dashboard/REST API have no authentication of their own (only `/mcp` does, via `MCP_SECRET`), so widen this deliberately (e.g. to your LAN interface IP, or `0.0.0.0`) only if you want the dashboard reachable from other devices |
| `LENS_DB_PATH` | no | `./data/lens.db` (`/lens-data/lens.db` in Docker) | Lens's own SQLite store — findings, baselines, seen-entity tracking, analysis-request queue |
| `LAN_CIDRS` | no | *(none)* | Comma-separated CIDRs treated as internal/LAN for the internal-source heuristic, e.g. `10.0.0.0/8,192.168.0.0/16` |
| `TRUSTED_ADMIN_NAMES` | no | *(none)* | Comma-separated admin display names (as they appear in UniFi's own audit log, e.g. `Ian C.`) that auto-dismiss `new_source_ip` findings which are entirely explained by that admin logging into the UniFi console. Empty by default — this rule never fires until configured |
| `SAFE_SIGNATURE_PREFIXES` | no | `ET DROP,ET CINS,ET TOR,ET COMPROMISED,ET DSHIELD` | Comma-separated IDS/IPS signature prefixes (Emerging Threats' reputation/blocklist rule-family naming convention) that auto-dismiss a finding when every backing event is a blocked hit from one of these signature families. Prefixes are matched via SQL `LIKE` (case-insensitive; a configured prefix containing `%` or `_` acts as a wildcard) — keep entries specific |
| `UNIFI_MCP_SERVER_URL` | no | *(unset)* | Optional `unifi-mcp-server` MCP endpoint, e.g. `http://localhost:3000/mcp`. When set, lens resolves source IPs to known client names and pulls a firewall-rule summary into analysis context. Left unset, this enrichment is skipped entirely — never required |
| `UNIFI_MCP_SERVER_TOKEN` | no | *(unset)* | Bearer token sent as `Authorization: Bearer <token>` when calling `UNIFI_MCP_SERVER_URL`, for `unifi-mcp-server` instances that require auth. Ignored if `UNIFI_MCP_SERVER_URL` is unset |
| `HOMELAB_SERVICES_PATH` | no | `./data/homelab-services.json` | Path to a local, never-committed JSON file mapping LAN host IPs to the services running on them (e.g. a homelab server's Docker containers — see `server/homelab-services.example.json` for the shape). Analysis context labels event destinations that match an entry (e.g. `192.168.1.26:8989` → `sonarr`) instead of leaving them as bare IP:port. Missing file is a no-op — this enrichment is entirely optional |
| `LOG_LEVEL` | no | `info` | `error` \| `warn` \| `info` \| `debug` |

---

## Development (Running from a Repo Clone)

### Setup

```bash
git clone https://github.com/ianchesal/unifi-siem-lens
cd unifi-siem-lens
npm install
cp server/.env.example server/.env
# edit server/.env: set SINK_DB_PATH to your unifi-siem-sink events.db, and MCP_SECRET to a strong secret
# (docker cp unifi-siem-sink-unifi-siem-sink-1:/data/events.db ./server/data/events.db)
```

### Run with Docker Compose

```bash
docker compose up -d --build
```

Exposes `3002/tcp` for the dashboard/API/MCP endpoint. Requires
`unifi-siem-sink` running as a container named `unifi-siem-sink` (adjust
`docker-compose.yml`'s `volumes_from` if yours is named differently) —
lens's own state persists in the `lens-data` named volume.

### Run locally

```bash
npm run dev
```

Starts the server (`http://localhost:3002`) and the Vite dev server
(`http://localhost:5173`, proxying `/api` to the server) together. The
server's `/mcp` endpoint is served directly on port 3002 and is not
proxied through Vite.

> **Note:** If `npm run dev -w server` fails to boot (a known issue on
> Node 24.x/25.x — see `unifi-siem-sink`'s CLAUDE.md for details), use
> `npm run build -w server && npm run start -w server` instead, alongside
> `npm run dev -w web` for the frontend.

### Production build

```bash
npm run build
npm start
```

Builds both packages and serves the built dashboard + API + MCP endpoint
from a single process on `PORT` (default `3002`).

### Tests

```bash
npm test          # server test suite (vitest)
npm run lint       # biome (server) + oxlint (web)
```

## Cutting a release

Releases are tag-driven. Pushing a `v*` tag to GitHub triggers
`.github/workflows/release.yml`, which:
- Builds and pushes a Docker image to `ghcr.io/ianchesal/unifi-siem-lens`
  (tagged `latest`, `{major}.{minor}`, and `{version}`)
- Creates a GitHub Release with auto-generated notes

**Steps to release:**

1. Ensure all changes are merged to `main` and CI is green.
2. Decide the new version (follows semver: `MAJOR.MINOR.PATCH`).
3. Update `"version"` in `package.json` (root) to the new version.
4. Commit: `git commit -m "chore: release v{version}" package.json`
5. Tag: `git tag v{version}`
6. Push both: `git push origin main && git push origin v{version}`

The release workflow fires automatically on the tag push. No manual Docker
build or GitHub Release creation needed.

## License

[MIT](LICENSE)
