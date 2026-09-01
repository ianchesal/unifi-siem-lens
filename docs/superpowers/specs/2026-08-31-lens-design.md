# unifi-siem-lens design

Date: 2026-08-31

## Why

`unifi-siem-sink` collects UniFi IPS/IDS and Security-category events into a
SQLite database and exposes them to an LLM via MCP tools, but has no
visualization or trend analysis of its own — every question ("is this
getting worse?", "have I seen this signature before?", "is this worth
worrying about?") currently requires manually querying `list_events` /
`get_event_stats` through an MCP client and reasoning about the raw numbers
by hand.

`unifi-siem-lens` adds a companion visualization and analysis layer on top
of the sink's data: a dashboard for trends, a code-driven (no-LLM) heuristics
engine that flags what's worth attention, and a lightweight handoff
mechanism so deeper reasoning about a specific flagged finding can be
delegated to a Claude Code session running on the user's Claude subscription
(no API key available/desired).

## Non-goals

- Not a replacement for the sink — lens never writes to the sink's data and
  has no opinion on ingestion, retention, or parsing.
- Not a general SIEM — no alerting/paging, no case management workflow
  beyond the single request→answer analysis loop described below.
- No autonomous/scheduled LLM calls — lens has no API key and makes none of
  its own. The Claude Code handoff only advances when a human explicitly
  runs a Claude Code session against it.

## Architecture

Two-package repo, one deployed process:

```
unifi-siem-lens/
├── server/          Node/TS — Express REST API + MCP server (Streamable HTTP)
│   ├── db/          read-only node:sqlite connection to the sink's events.db
│   ├── analysis/    heuristics engine (baselines, z-scores, new-signature/IP
│   │                detection, internal-source flag, repeat-offender tracking)
│   ├── store/       lens's own SQLite db (lens.db): baselines, seen-entity
│   │                history, findings, analysis_requests
│   ├── api/         REST endpoints consumed by the dashboard
│   └── mcp/         MCP tools for the Claude Code analysis handoff
└── web/             React/Vite SPA dashboard (Chart.js or Recharts)
```

Same stack and conventions as the sibling `unifi-siem-sink` project
(Node >= 22.5, TypeScript, `node:sqlite`, Express, zod, `@modelcontextprotocol/sdk`,
Vitest, Biome) so patterns for config loading, migrations, and graceful
shutdown can be lifted directly rather than reinvented.

In production, `server` serves `web`'s built static output (`web/dist`), so
the whole thing ships and runs as a single process/container, matching the
sink's deployment model (Docker image, env-driven config).

### Two SQLite databases

- **`events.db`** — the sink's database, opened **read-only**. Lens never
  writes to it and must tolerate it being empty, missing, or momentarily
  locked by the sink's writer without erroring the dashboard.
- **`lens.db`** — lens's own database, holding everything lens needs to
  remember across restarts:
  - `baselines` — rolling per-(category, signature) daily-count statistics
    used for anomaly detection.
  - `seen_signatures`, `seen_source_ips` — first-seen tracking.
  - `findings` — output of the analysis engine (see below).
  - `analysis_requests` — the Claude Code handoff queue.

Keeping these separate means lens never risks a write conflict with the
sink's own WAL writer, and lens's own state survives independently of the
sink's `RETENTION_DAYS` purge.

### Enrichment via `unifi-mcp-server` (lens as an MCP client)

`unifi-mcp-server` (the sibling project covering the rest of the UniFi
Network API — clients, networks, firewall rules, port forwarding, traffic
rules) is available to lens as an MCP client dependency, used as needed for
enrichment:

- Resolving a bare `source_ip`/`dest_ip` on a finding to a known LAN client
  (device name, network/VLAN) via its client-lookup tools, so the dashboard
  can show "printer (10.0.10.42)" instead of just an IP.
- Pulling current firewall rules / port-forward config when building an
  `analysis_request`'s context bundle, so a Claude Code session reasoning
  about a finding has the actual current mitigations available to it
  (e.g. "is there already a port-forward exposing this?") rather than
  guessing from IPS data alone.

This is enrichment only — lens never uses `unifi-mcp-server` for anything
core to the analysis engine's heuristics (baseline/anomaly/new-entity/
repeat-offender all run purely off `events.db` + `lens.db`), so lens must
degrade gracefully (unresolved IPs stay bare IPs, context bundles omit
firewall/client detail) if `unifi-mcp-server` is unreachable or not
configured.

## Analysis engine (code-driven, no LLM)

New-entity, internal-source, and repeat-offender checks run hourly
(`setInterval`-driven, like the sink's purge job) and can be re-run on
demand when the dashboard loads. The anomaly check runs once per day,
just after day-close (e.g. 00:05), evaluating the just-completed day —
see rationale below.

- **Baseline & anomaly detection** — for each `(category, signature)` pair,
  maintain a rolling baseline (trailing 14-day mean/stddev of *full-day*
  counts, stored in `baselines`) and z-score the prior day's total count
  against it. This check deliberately does **not** run hourly against a
  partial "today": comparing a few hours of events to a baseline built
  from full 24-hour days would make today look anomalously low almost
  all day, never high, until very late in the day. Finalizing once/day
  against a complete day avoids that skew; it costs up to ~24h of
  detection latency, which is an acceptable trade for correctness here.
- **New-entity detection** — `seen_signatures` / `seen_source_ips` tables;
  anything present in `events.db` that isn't yet recorded there is flagged
  "first seen" and then recorded, so it's only flagged once. Events with a
  null or empty `signature` (the sink's `signature` column is nullable) are
  excluded from new-signature detection entirely — they'd otherwise collapse
  into one spurious shared "entity." They still count toward category-level
  volume in the anomaly check above.
- **Internal-source flag** — a config-supplied list of LAN CIDRs; any event
  whose `source_ip` falls inside them is flagged as "internal source"
  (possible compromised host talking out), reusing CIDR-matching logic
  equivalent to the sink's `storage/cidr.ts`. IPv4-only, matching the
  sink's own scope: an IPv6 `source_ip` silently never matches (not an
  error) so this flag simply never fires for it — accepted known
  limitation, not something to debug later.
- **Repeat-offender detection** — source IPs or signatures with events on
  ≥N distinct days within a trailing window are flagged "sustained,"
  distinguishing persistent probing from one-off noise.

Each entity gets **one** `findings` row, not one row per heuristic — a
single source IP that is simultaneously internal and sustained produces
one row with two entries under `triggers`, so the dashboard shows one card
with multiple badges rather than duplicate cards for the same underlying
situation. `triggers` is an array of `{type, first_seen, last_seen, active}`
records, not a flat list of type strings — `active` is what auto-resolve
(below) evaluates per trigger.

`findings` schema: type/entity, first_seen, last_seen, `triggers` (array,
see above), `severity_score`, `status` (`new` / `acknowledged` /
`dismissed` / `resolved`). `severity_score` is computed from *which*
triggers fired (a weighted sum per trigger type) — it is not a passthrough
of the sink's `severity` column, which is nullable and unreliable as a
sole signal; the sink's `severity`, when present, is used only as an
optional tie-breaker input, handled null-safe.

**Auto-resolve** applies only to the two triggers with a genuine standing
condition to revert from — `anomaly` (reverts when the z-score returns to
baseline) and `repeat_offender` (reverts when the entity goes quiet past
the window). `new_signature`, `new_source_ip`, and `internal_source` are
one-off or static: a first-seen event doesn't "un-happen," and an IP's
internal-ness doesn't change, so there is nothing for these to revert
from — they always require manual dismissal by design. Each analysis run
re-evaluates every trigger on `new`/`acknowledged` findings and marks
standing-condition triggers `active: false` once their condition lifts; a
finding auto-transitions to `resolved` only when **every** trigger it
carries is a standing-condition type and all are currently inactive. A
finding carrying even one event-based trigger never auto-resolves.

**Escalation**: adding a new trigger type to an already-existing finding
(e.g. a source IP dismissed for `internal_source` alone later crosses the
repeat-offender threshold) unconditionally resets `status` back to `new`,
regardless of its prior `acknowledged`/`dismissed` state — a genuine
escalation must resurface on the dashboard, never sit silently hidden
behind an old dismissal of a narrower situation.

## Data flow — the Claude Code analysis handoff

1. Dashboard shows a finding (e.g. "new signature X seen 40x today,
   z-score 4.2"). User clicks **Analyze this**.
2. Backend writes a row to `analysis_requests` (`status: pending`) with a
   snapshot of the finding plus relevant recent raw events pulled from
   `events.db` as context, and returns immediately. No LLM call happens
   here — lens has no model access. At most one `pending` request may
   exist per finding: clicking "Analyze this" while one is already
   pending is a no-op (the button reflects pending state rather than
   queuing a duplicate). Once a request is `answered`, clicking again
   creates a fresh request with a new snapshot — the finding may have
   changed since the last answer.
3. Later, in a Claude Code session with this repo's MCP server configured
   (`.mcp.json`), the user asks it to check for pending analyses. Claude
   Code calls `get_pending_analyses`, then `get_analysis_context(id)` for
   full detail, reasons about it using its own judgment (subscription-
   authenticated, no API key involved), and calls
   `submit_analysis(id, recommendation_markdown, risk_level)`.
4. Backend marks the `analysis_requests` row `status: answered` and stores
   the response; the dashboard shows it inline under that finding.

No polling, no scheduled cloud agent. The loop only advances when a human
runs a Claude Code session against it.

### MCP tools (server/mcp)

| Tool | Description |
|---|---|
| `get_pending_analyses` | List `analysis_requests` with `status: pending`. |
| `get_analysis_context` | Full detail for one request: the finding, its baseline/history, and the relevant raw events. |
| `submit_analysis` | Attach a recommendation (markdown) and risk level to a request, marking it `answered`. Errors on an already-answered or nonexistent id — never silently overwrites. |

## Error handling

- `events.db` opened read-only; if the sink hasn't written any events yet
  or the file doesn't exist, API responses are empty result sets, not
  errors — lens must not crash or 500 just because the sink is quiet.
- Each analysis-engine check runs in isolation; one broken heuristic
  (bad baseline math, missing data) must not block the others — mirrors
  the sink's "never stop listening" philosophy.
- MCP tools validate input with zod and return structured tool errors
  rather than throwing, matching the sink's tool implementations.
- **Schema contract with the sink**: at startup, lens runs `PRAGMA
  table_info(events)` against `events.db` and verifies the columns it
  depends on are present, documenting itself as pinned to the sink's
  schema `version 1` (the sink's own `MIGRATIONS` versioning). A mismatch
  is logged loudly and surfaced as degraded in `/health`, rather than
  failing silently on the first query that happens to touch a missing
  column.
- **Access control is a deliberate partial non-goal for v1**: lens's REST
  API/dashboard have no auth by default — this is scoped as a single-user
  LAN tool, and the bind address should default to LAN-only, not
  `0.0.0.0`-exposed-to-the-internet. The `/mcp` endpoint is the exception,
  mirroring the sink's hard-required `MCP_SECRET` bearer-token check, since
  it's the one surface a remote Claude Code session calls directly.
  Revisit the REST API/dashboard assumption if the single-user scoping
  changes.
- **Concurrent Claude Code sessions are an accepted, unhandled edge case**:
  `submit_analysis` errors on an already-answered id, but there is no
  claim/lock step, so two sessions could both fetch the same `pending`
  request and duplicate the reasoning work before either submits. Given
  the single-operator model this is low-priority and left as-is rather
  than solved.

## Testing

- Vitest, `tests/` mirroring `server/src/`, matching the sink's layout.
- Analysis engine gets the heaviest coverage: baseline/z-score math,
  new-entity detection, CIDR-based internal-source flag, repeat-offender
  windowing — pure functions over fixture data, no real DB required.
- **Fixture data**: seed from a sanitized copy of the real, currently-running
  sink's SQLite file (`docker cp unifi-siem-sink-unifi-siem-sink-1:/data/events.db
  ./tests/fixtures/events.db`) rather than fully synthetic rows — it's small
  and already exercises real-world CEF parsing quirks. Review/scrub it for
  anything sensitive (real external IPs are fine to keep; nothing else in
  the schema is identifying) before committing it as a fixture.
- API/MCP route tests run against a temp copy of that fixture DB (read-only
  open) plus a temp `lens.db`.
- Frontend: manual verification against a real or fixture DB, per this
  project's UI-testing convention; component tests optional/light.

## Open questions for the implementation plan

- Exact chart set for v1 (likely: events-over-time by category, top
  signatures, top source IPs, severity distribution, findings list) —
  left to the plan/implementation stage rather than pinned here.
- Config for LAN CIDRs (env var vs. config file) — small detail, decide
  during implementation following the sink's `config.ts` pattern.
