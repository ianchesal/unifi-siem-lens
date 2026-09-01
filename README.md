# UniFi SIEM Lens

Visualization dashboard and code-driven analysis layer for UniFi IDS/IPS
security events — trend charts, anomaly/repeat-offender detection, and a
"queue for Claude" handoff so a Claude Code session can turn a flagged
finding into an actual recommendation, without this service needing any
API key of its own.

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
  -p 3100:3100 \
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

`http://<homelab-ip>:3100`

### 4. Add to Claude Code for the analysis handoff

```json
{
  "mcpServers": {
    "unifi-siem-lens": {
      "type": "http",
      "url": "http://<homelab-ip>:3100/mcp",
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
| Dashboard (`/`) | Events-over-time, top signatures, top source IPs, and severity-distribution charts; a findings list with acknowledge/dismiss actions and an "Analyze this" button per finding. |
| `GET /health` | Liveness + sink DB / schema-contract status. |
| `get_pending_analyses` (MCP) | List analysis requests queued from the dashboard, awaiting a recommendation. |
| `get_analysis_context` (MCP) | Full context for one request: the finding, its trigger/baseline history, and the relevant raw events. |
| `submit_analysis` (MCP) | Post a recommendation + risk level back for a pending request. |

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SINK_DB_PATH` | yes | — | Path to `unifi-siem-sink`'s `events.db`, opened read-only |
| `MCP_SECRET` | yes | — | Bearer token clients must send as `Authorization: Bearer <MCP_SECRET>` to call `/mcp` |
| `PORT` | no | `3100` | Port the dashboard/API/MCP server listens on |
| `HOST` | no | `127.0.0.1` | Bind address. Defaults to localhost-only — the dashboard/REST API have no authentication of their own (only `/mcp` does, via `MCP_SECRET`), so widen this deliberately (e.g. to your LAN interface IP, or `0.0.0.0`) only if you want the dashboard reachable from other devices |
| `LENS_DB_PATH` | no | `./data/lens.db` (`/lens-data/lens.db` in Docker) | Lens's own SQLite store — findings, baselines, seen-entity tracking, analysis-request queue |
| `LAN_CIDRS` | no | *(none)* | Comma-separated CIDRs treated as internal/LAN for the internal-source heuristic, e.g. `10.0.0.0/8,192.168.0.0/16` |
| `UNIFI_MCP_SERVER_URL` | no | *(unset)* | Optional `unifi-mcp-server` MCP endpoint, e.g. `http://localhost:3000/mcp`. When set, lens resolves source IPs to known client names and pulls a firewall-rule summary into analysis context. Left unset, this enrichment is skipped entirely — never required |
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

Exposes `3100/tcp` for the dashboard/API/MCP endpoint. Requires
`unifi-siem-sink` running as a container named `unifi-siem-sink` (adjust
`docker-compose.yml`'s `volumes_from` if yours is named differently) —
lens's own state persists in the `lens-data` named volume.

### Run locally

```bash
npm run dev
```

Starts the server (`http://localhost:3100`) and the Vite dev server
(`http://localhost:5173`, proxying `/api` to the server) together. The
server's `/mcp` endpoint is served directly on port 3100 and is not
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
from a single process on `PORT` (default `3100`).

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
