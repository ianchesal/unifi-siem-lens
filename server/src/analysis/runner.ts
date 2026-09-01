import { createAnsweredRuleAnalysis } from '../db/analysisRequestsStore.js';
import {
  getFinding,
  hasSeenSignature,
  hasSeenSourceIp,
  listFindings,
  markSeenSignature,
  markSeenSourceIp,
  setFindingStatus,
  upsertFinding,
} from '../db/findingsStore.js';
import type { LensDb } from '../db/lensDb.js';
import type { SinkDb } from '../db/sinkDb.js';
import {
  auditCandidateEvents,
  signatureEventCounts,
  sourceIpEventCounts,
} from '../db/sinkQueries.js';
import { computeBaseline, isAnomalous } from './baseline.js';
import { isInternalSource } from './cidr.js';
import { applyTrigger, type Finding, reevaluateTrigger } from './findings.js';
import {
  detectNewSignatures,
  detectNewSourceIps,
  signatureKey,
  splitSignatureKey,
} from './newEntity.js';
import { isSustained, REPEAT_OFFENDER_WINDOW_DAYS } from './repeatOffender.js';
import {
  NON_SECURITY_OPERATIONAL_CATEGORIES,
  tryAdminAuditLoginRule,
  tryOperationalNoiseRule,
  tryReputationBlocklistRule,
} from './ruleTriage.js';

export interface RunnerDeps {
  sinkDb: SinkDb;
  lensDb: LensDb;
  lanCidrs: string[];
  trustedAdminNames: string[];
  safeSignaturePrefixes: string[];
}

const NEW_ENTITY_WINDOW_HOURS = 24;

interface RecentEventRow {
  category: string;
  signature: string | null;
  source_ip: string | null;
}

function recentEvents(sinkDb: SinkDb, sinceIso: string): RecentEventRow[] {
  return sinkDb.conn
    .prepare('SELECT category, signature, source_ip FROM events WHERE received_at >= ?')
    .all(sinceIso) as unknown as RecentEventRow[];
}

// Runs a single named check in isolation: a failure here is logged and contributes
// zero to the total, but must not prevent the other checks in the run from executing
// (Global Constraint: "All heuristics run in isolation from each other — one broken
// heuristic must not block the others").
function runCheck(name: string, fn: () => number): number {
  try {
    return fn();
  } catch (err) {
    console.error(`Analysis check "${name}" failed:`, err);
    return 0;
  }
}

// Attempts rule-based auto-triage for a just-created/updated new_signature or
// new_source_ip finding. Fires at most one rule (admin login, then
// operational noise, then reputation blocklist — first match wins) and, on a
// match, writes an already-answered analysis_requests row and dismisses the
// finding directly. No-op (returns without touching the finding) if no rule
// fully explains every event behind it.
function tryRuleTriage(deps: RunnerDeps, finding: Finding, sinceIso: string, nowIso: string): void {
  const prefixClause = deps.safeSignaturePrefixes.map(() => 'signature LIKE ?').join(' OR ');
  const prefixParams = deps.safeSignaturePrefixes.map((p) => `${p}%`);

  let verdict: ReturnType<typeof tryAdminAuditLoginRule> = null;

  if (finding.entity_type === 'source_ip') {
    if (deps.trustedAdminNames.length > 0) {
      const auditEvents = auditCandidateEvents(deps.sinkDb, finding.entity_key, sinceIso);
      verdict = tryAdminAuditLoginRule(auditEvents, deps.trustedAdminNames);
    }

    if (!verdict) {
      const opCounts = sourceIpEventCounts(
        deps.sinkDb,
        finding.entity_key,
        sinceIso,
        `category IN (${NON_SECURITY_OPERATIONAL_CATEGORIES.map(() => '?').join(',')})`,
        NON_SECURITY_OPERATIONAL_CATEGORIES
      );
      verdict = tryOperationalNoiseRule(opCounts);
    }

    if (!verdict && prefixClause) {
      const blockCounts = sourceIpEventCounts(
        deps.sinkDb,
        finding.entity_key,
        sinceIso,
        `category = 'ips_alert' AND action = 'blocked' AND (${prefixClause})`,
        prefixParams
      );
      verdict = tryReputationBlocklistRule(blockCounts);
    }
  } else {
    const { category, signature } = splitSignatureKey(finding.entity_key);
    if (category === 'ips_alert' && prefixClause) {
      const blockCounts = signatureEventCounts(
        deps.sinkDb,
        category,
        signature,
        sinceIso,
        `action = 'blocked' AND (${prefixClause})`,
        prefixParams
      );
      verdict = tryReputationBlocklistRule(blockCounts);
    }
  }

  if (!verdict) return;

  createAnsweredRuleAnalysis(
    deps.lensDb,
    finding.id as number,
    { finding },
    verdict.recommendation,
    verdict.riskLevel,
    nowIso
  );
  setFindingStatus(deps.lensDb, finding.id as number, 'dismissed');
}

export function runHourlyChecks(
  deps: RunnerDeps,
  now: Date = new Date()
): { findingsTouched: number } {
  const nowIso = now.toISOString();
  const sinceIso = new Date(now.getTime() - NEW_ENTITY_WINDOW_HOURS * 3600 * 1000).toISOString();
  const events = recentEvents(deps.sinkDb, sinceIso);
  let touched = 0;

  // New-signature / new-source-ip
  touched += runCheck('new-signature', () => {
    let count = 0;
    const seenSigSet = new Set(
      events
        .filter((e) => e.signature && hasSeenSignature(deps.lensDb, e.category, e.signature))
        .map((e) => signatureKey(e.category, e.signature as string))
    );
    for (const { category, signature } of detectNewSignatures(events, seenSigSet)) {
      const existing = getFinding(deps.lensDb, 'signature', signatureKey(category, signature));
      const finding = upsertFinding(
        deps.lensDb,
        applyTrigger(
          existing,
          'new_signature',
          nowIso,
          'signature',
          signatureKey(category, signature)
        )
      );
      markSeenSignature(deps.lensDb, category, signature, nowIso);
      tryRuleTriage(deps, finding, sinceIso, nowIso);
      count++;
    }
    return count;
  });

  touched += runCheck('new-source-ip', () => {
    let count = 0;
    const seenIpSet = new Set(
      events
        .filter((e) => e.source_ip && hasSeenSourceIp(deps.lensDb, e.source_ip))
        .map((e) => e.source_ip as string)
    );
    for (const ip of detectNewSourceIps(events, seenIpSet)) {
      const existing = getFinding(deps.lensDb, 'source_ip', ip);
      const finding = upsertFinding(
        deps.lensDb,
        applyTrigger(existing, 'new_source_ip', nowIso, 'source_ip', ip)
      );
      markSeenSourceIp(deps.lensDb, ip, nowIso);
      tryRuleTriage(deps, finding, sinceIso, nowIso);
      count++;
    }
    return count;
  });

  // Internal-source
  touched += runCheck('internal-source', () => {
    let count = 0;
    const distinctIps = new Set(
      events.filter((e) => e.source_ip).map((e) => e.source_ip as string)
    );
    for (const ip of distinctIps) {
      if (!isInternalSource(ip, deps.lanCidrs)) continue;
      const existing = getFinding(deps.lensDb, 'source_ip', ip);
      upsertFinding(
        deps.lensDb,
        applyTrigger(existing, 'internal_source', nowIso, 'source_ip', ip)
      );
      count++;
    }
    return count;
  });

  // Repeat-offender: recompute distinct-day activity over the trailing window directly
  // from events.db each run (homelab data volumes make this cheap; avoids incremental-
  // cursor bookkeeping — see spec's "runner queries the window directly" note).
  touched += runCheck('repeat-offender', () => {
    let count = 0;
    const windowStart = new Date(
      now.getTime() - REPEAT_OFFENDER_WINDOW_DAYS * 24 * 3600 * 1000
    ).toISOString();
    const ipDayCounts = deps.sinkDb.conn
      .prepare(
        `SELECT source_ip, COUNT(DISTINCT date(received_at)) as days FROM events
         WHERE received_at >= ? AND source_ip IS NOT NULL GROUP BY source_ip`
      )
      .all(windowStart) as { source_ip: string; days: number }[];

    const activeSustainedIps = new Set(
      ipDayCounts.filter((r) => isSustained(r.days)).map((r) => r.source_ip)
    );

    for (const row of ipDayCounts) {
      const existing = getFinding(deps.lensDb, 'source_ip', row.source_ip);
      if (isSustained(row.days)) {
        upsertFinding(
          deps.lensDb,
          applyTrigger(existing, 'repeat_offender', nowIso, 'source_ip', row.source_ip)
        );
        count++;
      } else if (existing?.triggers.some((t) => t.type === 'repeat_offender' && t.active)) {
        upsertFinding(deps.lensDb, reevaluateTrigger(existing, 'repeat_offender', false, nowIso));
        count++;
      }
    }
    // Any previously-sustained IP that dropped out of the window entirely (no rows at all)
    for (const finding of listFindings(deps.lensDb)) {
      if (finding.entity_type !== 'source_ip') continue;
      if (activeSustainedIps.has(finding.entity_key)) continue;
      if (!finding.triggers.some((t) => t.type === 'repeat_offender' && t.active)) continue;
      upsertFinding(deps.lensDb, reevaluateTrigger(finding, 'repeat_offender', false, nowIso));
      count++;
    }
    return count;
  });

  return { findingsTouched: touched };
}

const BASELINE_HISTORY_LOOKBACK_DAYS = 30;

export function runDailyAnomalyCheck(
  deps: RunnerDeps,
  day: string = new Date(Date.now() - 86400000).toISOString().slice(0, 10)
): { findingsTouched: number } {
  const nowIso = new Date().toISOString();

  const touched = runCheck('daily-anomaly', () => {
    let count = 0;

    // Backfill baselines for prior days directly from the sink DB. In steady-state
    // production this is a no-op (each prior day's row was already written by that
    // day's own run), but it means a fresh lens.db — or a gap from missed runs —
    // still has real history to judge today's count against, instead of silently
    // skipping the anomaly check for lack of `baselines` rows.
    const lookbackStart = new Date(
      new Date(`${day}T00:00:00Z`).getTime() - BASELINE_HISTORY_LOOKBACK_DAYS * 24 * 3600 * 1000
    )
      .toISOString()
      .slice(0, 10);
    const historicalCounts = deps.sinkDb.conn
      .prepare(
        `SELECT date(received_at) as day, category, signature, COUNT(*) as count FROM events
       WHERE date(received_at) >= ? AND date(received_at) < ? AND signature IS NOT NULL AND signature != ''
       GROUP BY day, category, signature`
      )
      .all(lookbackStart, day) as {
      day: string;
      category: string;
      signature: string;
      count: number;
    }[];
    for (const row of historicalCounts) {
      deps.lensDb.conn
        .prepare(
          `INSERT OR IGNORE INTO baselines (category, signature, day, count) VALUES (?, ?, ?, ?)`
        )
        .run(row.category, row.signature, row.day, row.count);
    }

    const dayCounts = deps.sinkDb.conn
      .prepare(
        `SELECT category, signature, COUNT(*) as count FROM events
       WHERE date(received_at) = ? AND signature IS NOT NULL AND signature != ''
       GROUP BY category, signature`
      )
      .all(day) as { category: string; signature: string; count: number }[];

    for (const row of dayCounts) {
      deps.lensDb.conn
        .prepare(
          `INSERT OR IGNORE INTO baselines (category, signature, day, count) VALUES (?, ?, ?, ?)`
        )
        .run(row.category, row.signature, day, row.count);
    }

    const activeAnomalies = new Set<string>();
    for (const row of dayCounts) {
      const history = deps.lensDb.conn
        .prepare(
          `SELECT count FROM baselines WHERE category = ? AND signature = ? AND day < ?
         ORDER BY day DESC LIMIT 14`
        )
        .all(row.category, row.signature, day) as { count: number }[];
      if (history.length < 3) continue; // not enough history to judge yet
      const stats = computeBaseline(history.map((h) => h.count));
      if (!isAnomalous(row.count, stats)) continue;

      const key = signatureKey(row.category, row.signature);
      activeAnomalies.add(key);
      const existing = getFinding(deps.lensDb, 'signature', key);
      upsertFinding(deps.lensDb, applyTrigger(existing, 'anomaly', nowIso, 'signature', key));
      count++;
    }

    for (const finding of listFindings(deps.lensDb)) {
      if (finding.entity_type !== 'signature') continue;
      if (activeAnomalies.has(finding.entity_key)) continue;
      if (!finding.triggers.some((t) => t.type === 'anomaly' && t.active)) continue;
      upsertFinding(deps.lensDb, reevaluateTrigger(finding, 'anomaly', false, nowIso));
      count++;
    }

    return count;
  });

  return { findingsTouched: touched };
}
