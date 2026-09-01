# Rule-based finding triage design

Date: 2026-09-01

## Why

The Claude Code analysis handoff (see `2026-08-31-lens-design.md`) works,
but a live network generates a steady stream of findings that don't need
reasoning at all: the operator's own console logins, the gateway's WAN-health
noise, and routine reputation-blocklist scans that get auto-blocked before
they touch anything. Queuing every one of these for a human-run Claude Code
session to pick up (`get_pending_analyses` → reason → `submit_analysis`)
wastes that session's attention on findings whose verdict is mechanical.

This adds a small rule-based triage step that runs automatically inside the
existing heuristics runner: when a newly-created or reopened `new_signature`
/ `new_source_ip` finding is *entirely* explained by one of a handful of
known-safe patterns, it is answered and dismissed immediately, in code, with
no queued request and no human or AI in the loop. Findings that aren't fully
explained by a rule are untouched — they still need a click of "Analyze
this" (or `Analyze all`) and, from there, a Claude Code session, exactly as
today.

This does not change the project's "no autonomous/scheduled LLM calls"
non-goal from the original design doc — it reduces how often that path is
needed at all, rather than adding any new automated call to Claude.

## Scope

Rule-based triage applies only to findings created via the `new_signature`
or `new_source_ip` triggers in `runHourlyChecks` — the two trigger types
that represent a single newly-seen entity, where "is this explained by a
known-safe pattern" is a meaningful question. `anomaly`, `repeat_offender`,
and `internal_source` findings are standing conditions evaluated across a
window, not single-shot facts, and are out of scope for this change.

## Rules

A finding qualifies for auto-triage only if **every** event backing it
(fetched the same way `POST /findings/:id/analyze` already does, via
`eventsForSignature`/`eventsForSourceIp`) matches the *same* rule below. A
finding whose events are mixed, or match no rule, is left alone — same
behavior as today.

1. **Admin audit login** — every event has `category='audit'` and its
   `message` parses to an admin name (`"<name> accessed UniFi Network..."`)
   that appears in the `TRUSTED_ADMIN_NAMES` config (comma-separated env
   var, empty by default — this rule never fires until configured).
2. **Operational noise** — every event's `category` is in a fixed,
   non-security set (`internet_and_wan` today). These categories describe
   device/WAN health, not intrusion activity, so a `new_source_ip` finding
   triggered by (for example) the gateway's own IP appearing on a
   high-latency log line has nothing security-relevant to say.
3. **Reputation/blocklist scan** — every event has `category='ips_alert'`,
   `action='blocked'`, and a `signature` starting with one of
   `SAFE_SIGNATURE_PREFIXES` (env-configurable; defaults to `ET DROP`,
   `ET CINS`, `ET TOR`, `ET COMPROMISED`, `ET DSHIELD` — Emerging Threats'
   own naming convention for reputation-feed rules, as opposed to
   `ET MALWARE`/`ET TROJAN`/`ET EXPLOIT`/`ET SCAN`/`ET CNC`-family rules,
   which never match this rule and always fall through to manual/AI
   review).

Each rule produces a short canned `recommendation` string identifying which
rule fired and why, and a fixed `risk_level: 'low'`.

## Data flow

`tryRuleTriage(finding, events): { recommendation, riskLevel } | null` is a
pure function in a new `server/src/analysis/ruleTriage.ts`, matching the
existing zero-I/O heuristic module pattern (`cidr.ts`, `newEntity.ts`,
`baseline.ts`).

In `runner.ts`'s `runHourlyChecks`, immediately after each `upsertFinding`
call inside the `new-signature` and `new-source-ip` checks, the runner:

1. Fetches that finding's backing events (same helpers `analysisRequests.ts`
   already uses for the manual-analyze path).
2. Calls `tryRuleTriage`.
3. On a match, writes an already-answered `analysis_requests` row
   (`createAnsweredRuleAnalysis`, new store function alongside the existing
   `createAnalysisRequest`/`submitAnalysis`) and sets the finding's `status`
   to `dismissed` directly (reusing the same `UPDATE findings SET status`
   path `POST /findings/:id/status` uses).

This runs once per finding per runner pass, right when the finding is
created/reopened — before it is ever visible to the dashboard in `new`
status, for findings that qualify. A finding that doesn't fully match a rule
is created exactly as it is today (`status: 'new'`, no analysis_requests row
until someone clicks Analyze).

Because `applyTrigger` already reopens a `dismissed` finding to `new` when a
genuinely new trigger type fires or a standing trigger reactivates, an
auto-dismissed finding is not permanently silenced: if this same entity
later trips a *different* trigger (e.g. a `repeat_offender` escalation on an
IP that was auto-dismissed for `new_source_ip`), it reopens and surfaces
normally, and rule-triage only re-evaluates it if `new_signature`/
`new_source_ip` fires again — it does not retroactively re-examine
findings reopened by other trigger types.

## Data model

New column on `analysis_requests`: `source TEXT NOT NULL DEFAULT 'ai'`,
values `'ai'` (the existing `submit_analysis` MCP path) or `'rule'` (this
new path). Added via a new numbered entry in `lensDb.ts`'s `MIGRATIONS`
array, following the sink's/lens's existing migration pattern.

`sinkQueries.ts`'s `eventsForSignature`/`eventsForSourceIp` and the
`StoredEvent` type gain the `action` column — already present in the sink's
schema and in lens's `EXPECTED_COLUMNS` contract, just not selected today.

## API / UI

No new endpoints. `GET /api/analysis-requests` rows now carry `source`;
`FindingsList.tsx`'s analysis panel branches its existing "via Claude Code ·
submitted…" line on `source`: `"via Claude Code"` for `'ai'`, `"auto-triaged
by rule"` for `'rule'`. Auto-dismissed findings behave exactly like any
other dismissed finding in the status-tab UI added earlier — visible under
the Dismissed tab, with the canned analysis attached as an audit trail.

## Config

Two new env vars in `config.ts`, both optional with safe defaults:

- `TRUSTED_ADMIN_NAMES` — comma-separated admin display names; empty by
  default (rule 1 never fires unconfigured).
- `SAFE_SIGNATURE_PREFIXES` — comma-separated signature prefixes; defaults
  to `ET DROP,ET CINS,ET TOR,ET COMPROMISED,ET DSHIELD` if unset.

## Testing

`ruleTriage.ts` is a pure function — unit tests cover: each rule matching
in isolation, mixed-category events failing to match any rule, an
`ET MALWARE`/`ET TROJAN`/etc. signature never matching rule 3 regardless of
`action`, and an audit login from a name outside `TRUSTED_ADMIN_NAMES` not
matching rule 1. `runner.ts` integration tests cover: a qualifying finding
ending up `dismissed` with an answered, `source: 'rule'` analysis request
attached, and a non-qualifying (or mixed-event) finding created exactly as
today with no analysis_requests row at all.
