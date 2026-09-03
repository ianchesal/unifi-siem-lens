---
name: analyzing-findings
description: Use when asked to analyze, reanalyze, or triage pending findings in unifi-siem-lens — drains the MCP analysis_requests queue, enriches with UniFi client/hostname data, submits risk-rated recommendations, and flags recurring low-risk findings that look like candidates for a new auto-triage rule.
---

# Analyzing Findings

Drives the `unifi-siem-lens` MCP analysis handoff loop end to end: pulls
every pending analysis request, reasons about each with full context and
UniFi enrichment, submits a recommendation, and separately calls out any
findings that look like they belong in the code-driven auto-triage layer
(`server/src/analysis/ruleTriage.ts`) instead of needing an LLM every time.

Read `server/src/analysis/findings.ts` and `server/src/analysis/ruleTriage.ts`
first if you haven't seen this codebase's finding lifecycle before — the
trigger-type distinctions below (standing vs. one-off) come from there.

## Scope

This skill only drains the **pending MCP queue**
(`get_pending_analyses`). It does not:
- re-check findings that were already answered (no ad hoc "analyze
  finding #N" outside the queue),
- trigger or replace `runRuleTriageBackfill`,
- write or edit `ruleTriage.ts` / `runner.ts` — noise candidates are
  reported, never auto-implemented.

## Steps

1. **Fetch the queue.** Call `mcp__unifi-siem-lens__get_pending_analyses`.
   If it returns empty, tell the user there's nothing to reanalyze and stop.

2. **Get full context per request.** For each pending item, call
   `mcp__unifi-siem-lens__get_analysis_context` with its `id` and parse the
   embedded JSON `context` string: `finding` (entity, triggers, severity,
   status), `recentEvents`, `baselineHistory`, `knownClient`.

3. **Enrich with hostnames.** Collect the distinct source/dest IPs across
   `recentEvents`. Try `mcp__unifi__list_clients` (`include_offline: true`)
   and match by IP to get a hostname/name for context in the writeup. If
   the call fails (unreachable controller/server) or an IP has no match,
   proceed IP-only — enrichment must never block analysis. Don't call
   `mcp__unifi__get_client` speculatively; it needs a MAC address, which
   you only have after a `list_clients` match.

4. **Reason about the finding.** Weigh:
   - **Trigger type** — `repeat_offender` and `anomaly` are standing
     conditions (the finding reflects an ongoing state); `new_signature`,
     `new_source_ip`, and `internal_source` are one-off facts that never
     auto-resolve. A finding already `acknowledged`/`dismissed` that
     reopened to `new` means a new trigger fired or a standing condition
     reactivated — treat that recurrence itself as signal, not noise.
   - **Severity and action** (`blocked` vs not, IDS/IPS severity score).
   - **Recurrence** — does `baselineHistory` or the event timestamps show
     this happening more than once, or is it a single blip?
   - **Enrichment** — a known/trusted hostname changes the read on
     otherwise-suspicious traffic; an unknown or unexpected device doesn't.

5. **Cross-reference other pending findings.** If two or more pending
   findings clearly share a root cause (same source IP, same signature,
   overlapping events), say so explicitly in each one's recommendation
   rather than analyzing them as unrelated.

6. **Submit.** Call `mcp__unifi-siem-lens__submit_analysis` with `id`,
   `risk_level` (`low`/`medium`/`high`), and a `recommendation` covering:
   what was observed, why it matters (or doesn't), and concrete next
   steps. Be specific — cite the actual signature names, IPs/hostnames,
   and dates involved.

7. **Check for noise-rule candidates.** After forming a verdict, a finding
   qualifies as a candidate to flag (not implement) only if **all** of:
   - every event behind it fits one clear, mechanical explanation (same
     signature/action/source-category pattern across *all* matching
     events, not just the ones in `recentEvents` — the same completeness
     bar `ruleTriage.ts`'s `isComplete` helper enforces: total count must
     equal matching count, not just "the sample looks clean"),
   - the verdict from step 6 was `risk_level: low`,
   - the pattern has recurred (this finding or a clear lookalike has
     shown up more than once — not a first-time one-off), and
   - it doesn't already fit one of the three existing rules in
     `ruleTriage.ts` (`tryAdminAuditLoginRule` — trusted admin console
     logins, `tryOperationalNoiseRule` — WAN/device/software-update
     telemetry, `tryReputationBlocklistRule` — blocked reputation-
     blocklist IDS hits). Skim `ruleTriage.ts` to confirm before flagging.

   Because `get_analysis_context`'s `recentEvents` is capped (LIMIT 20,
   sized for LLM context), you can't verify true completeness from it
   alone — treat step 7 as a heuristic flag for the user to verify with a
   real completeness query, the way `ruleTriage.ts` itself does, not as a
   claim that the pattern is proven complete.

8. **Summarize.** Report per finding: id, risk level, one-line rationale.
   Separately list any noise-rule candidates from step 7, each with the
   recurring pattern observed and a one-line sketch of what a new
   `tryXRule` condition would check (e.g. "all events are
   `category=ips_alert`, `action=blocked`, signature matches ET SCAN
   family, source_ip always outside RFC1918") — left for the user to
   decide whether to implement in `ruleTriage.ts`/`runner.ts`.
