# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A visualization dashboard and code-driven (no-LLM) analysis layer on top of
the sibling project `unifi-siem-sink`'s event store. It reads
`unifi-siem-sink`'s `events.db` read-only, runs scheduled heuristics
(new-signature/new-source-IP detection, internal-source flagging,
repeat-offender tracking, z-score anomaly detection) to produce *findings*,
and serves both a React dashboard and an MCP server. The MCP server is the
key mechanism: this project has no LLM access of its own (no API key), so
"Analyze this" on a finding just queues a request — a Claude Code session
(subscription-authenticated, configured with this project's `/mcp`
endpoint) fetches pending requests, reasons about them with real event
context, and posts a recommendation back via `submit_analysis`. It pairs
with `unifi-mcp-server` (rest of the UniFi Network API) and
`unifi-siem-sink` (the event source); this project adds no new UniFi API
coverage, only analysis on top of what the sink already collects.

See `docs/superpowers/specs/2026-08-31-lens-design.md` for the full design
spec (architecture rationale, trigger/finding lifecycle rules, and the
decisions behind the analysis heuristics) — it is not gitignored from the
published repo the way `docs/superpowers/` normally would be, since it's
the primary architecture reference for this project going forward.

## Commands

```bash
npm install                 # installs both workspaces (npm workspaces: server, web)
npm run dev                  # concurrently: server dev + web (Vite) dev, proxied together
npm run build                 # builds web then server
npm start                     # runs the built server (serves API + MCP + built dashboard)
npm test                      # server test suite (vitest)
npm run lint                  # biome (server) + oxlint (web)
```

Run a single server test file: `cd server && npx vitest run tests/analysis/findings.test.ts`
Run tests matching a name: `cd server && npx vitest run -t "some test name"`

`npm run dev -w server` (`node --watch --experimental-strip-types src/index.ts`)
is currently broken on Node 24.x/25.x — the same known issue documented in
`unifi-siem-sink`'s CLAUDE.md (`--experimental-strip-types` doesn't resolve
`.js`-suffixed relative imports against sibling `.ts` files). Use
`npm run build -w server && npm run start -w server` instead, alongside
`npm run dev -w web` for the frontend.

Node >= 22.5.0 is required (uses `node:sqlite`, built in — no
better-sqlite3 or other native SQLite dependency).

## Architecture

Two npm workspaces: `server/` (Node/TS, Express, MCP SDK) and `web/`
(React/Vite/Recharts). In production the server serves the built dashboard
(`web/dist`) statically alongside its own API and MCP endpoint — one
process, `server/src/server.ts`'s static/SPA-fallback middleware is
registered *after* the `/api`, `/mcp`, and `/health` routes so it can never
shadow them.

### Two SQLite databases

- **`events.db`** (path via `SINK_DB_PATH`) — the sink's database, opened
  strictly **read-only** (`server/src/db/sinkDb.ts`). Never written to.
  Tolerates being empty; a missing file is caught at startup and the server
  boots in a degraded mode (schema check skipped, scheduled jobs skipped,
  API routes return empty results / 503) rather than crashing — see
  `index.ts`'s try/catch around `openSinkDb`. A schema-contract check
  (`verifySchema`, `PRAGMA table_info`) runs at startup and is reflected in
  `/health`, so a sink schema change surfaces loudly instead of causing
  silent wrong-data queries.
- **`lens.db`** (path via `LENS_DB_PATH`) — this project's own store,
  migrated the same numbered-`MIGRATIONS`-array way the sink migrates its
  own DB (`server/src/db/lensDb.ts`). Holds `baselines` (rolling per-
  signature daily counts for anomaly detection), `seen_signatures` /
  `seen_source_ips` (first-seen tracking), `findings`, and
  `analysis_requests` (the Claude Code handoff queue).

### Analysis engine (`server/src/analysis/`)

Pure-function heuristic modules (`cidr.ts`, `newEntity.ts`,
`repeatOffender.ts`, `baseline.ts`) with zero I/O, orchestrated by
`runner.ts`'s `runHourlyChecks`/`runDailyAnomalyCheck`, scheduled from
`index.ts`. Each check runs in its own try/catch (`runCheck` helper in
`runner.ts`) — one broken heuristic must never block the others for that
run, mirroring the sink's "never stop listening" philosophy.

`isAnomalous` (in `baseline.ts`) is deliberately one-sided: only a spike
above the trailing baseline registers, never a drop. A drop in alert volume
is more likely a collection/operational problem than a security one for an
IDS/IPS use case.

**Findings lifecycle** (`server/src/analysis/findings.ts`) is the most
spec-critical module — read it before touching it. A finding accumulates
`triggers`; only `anomaly` and `repeat_offender` are "standing" conditions
that can auto-resolve when they lift (`reevaluateTrigger`); `new_signature`,
`new_source_ip`, and `internal_source` are one-off/permanent facts that
never auto-resolve and always require manual dismissal. Adding a *new*
trigger type to an existing finding always reopens it to `status: 'new'`,
even from `dismissed` — an escalation must never sit silently hidden behind
an old dismissal. A `resolved` finding also reopens to `new` if a
previously-inactive standing trigger reactivates (a status recomputed by
the system, not a human decision, so it doesn't get the same "leave it
alone" treatment `acknowledged`/`dismissed` do).

### MCP handoff (`server/src/mcp/tools.ts`, `server/src/db/analysisRequestsStore.ts`)

`POST /findings/:id/analyze` queues an `analysis_requests` row (deduped —
at most one `pending` request per finding at a time) with a context bundle
of the finding, recent matching raw events from `events.db`, baseline
history, and (if `UNIFI_MCP_SERVER_URL` is configured) an enrichment
lookup via `unifi-mcp-server`. `get_pending_analyses` / `get_analysis_context`
/ `submit_analysis` are the three MCP tools a Claude Code session drives;
`submit_analysis` throws on an already-answered or nonexistent request
rather than silently overwriting.

### Optional enrichment (`server/src/enrichment/unifiMcpClient.ts`)

`createUnifiMcpClient(url)` is a genuine no-op when `url` is `null`
(no `Client`/transport constructed at all) and resolves to `null` on any
connection failure rather than throwing — enrichment must never block the
core analysis-request flow. Not required for anything else in this
project; it's purely additive context for the Claude Code handoff.

## Config

All runtime config is env-driven, loaded once in `server/src/config.ts`
(`loadConfig`) — fails fast if `SINK_DB_PATH` or `MCP_SECRET` is unset or
`LOG_LEVEL` is invalid. `HOST` defaults to `127.0.0.1` (not `0.0.0.0`)
since the dashboard/REST API have no authentication of their own by design
(a single-user LAN tool) — widen it deliberately, never as an accident.
The `/mcp` endpoint is the one exception: it requires
`Authorization: Bearer <MCP_SECRET>` (checked in `server/src/server.ts`'s
`mcpAuthMiddleware`, applied only to the `/mcp` route), mirroring
`unifi-mcp-server`'s auth so a Claude Code session configured against a
LAN-exposed lens instance still needs the shared secret. See the README's
Environment Variables table for the full list and defaults.
