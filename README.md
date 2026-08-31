# unifi-siem-lens

Visualization and code-driven analysis layer for `unifi-siem-sink`. See
`docs/superpowers/specs/2026-08-31-lens-design.md` for the full design.

## Run locally

```bash
npm install
cp server/.env.example server/.env
# edit server/.env: set SINK_DB_PATH to your unifi-siem-sink events.db
# (docker cp unifi-siem-sink-unifi-siem-sink-1:/data/events.db ./server/data/events.db)
npm run dev
```

> **Note:** If `npm run dev` fails to boot (a known issue on Node 24.x/25.x — see
> `unifi-siem-sink`'s CLAUDE.md for details), use `npm run build -w server && npm run start -w server`
> instead, alongside `npm run dev -w web` for the frontend.

This starts the server (`http://localhost:3100`) and the Vite dev server
(`http://localhost:5173`, proxying `/api` to the server) together. The
server's `/mcp` endpoint (see below) is served directly on port 3100 and is
not proxied through Vite.

## Configure Claude Code for the analysis handoff

Copy `.mcp.json.example` to `.mcp.json` (or merge into your existing one) and
ask a Claude Code session in this repo to check for pending analyses.

## Production build

```bash
npm run build
npm start
```

Serves the built dashboard and API from a single process on `PORT`
(default 3100). By default the server binds to `127.0.0.1` only (localhost),
so it's not reachable from other devices on your network. To expose it more
widely, set `HOST` in `server/.env` to your LAN interface IP (or `0.0.0.0`
to bind all interfaces) — do this deliberately, since the dashboard has no
authentication.
