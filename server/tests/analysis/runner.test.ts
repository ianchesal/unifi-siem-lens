import { describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { openLensDb } from '../../src/db/lensDb.js';
import { listFindings, upsertFinding } from '../../src/db/findingsStore.js';
import {
  createAnalysisRequest,
  getAnalysisRequestsForFinding,
  submitAnalysis,
} from '../../src/db/analysisRequestsStore.js';
import { applyTrigger } from '../../src/analysis/findings.js';
import { runDailyAnomalyCheck, runHourlyChecks, runRuleTriageBackfill } from '../../src/analysis/runner.js';

function seededSinkDb(
  rows: {
    received_at: string;
    category: string;
    signature: string | null;
    source_ip: string | null;
    action?: string | null;
    message?: string | null;
    dest_ip?: string | null;
    dest_port?: number | null;
  }[]
) {
  const conn = new DatabaseSync(':memory:');
  conn.exec(
    `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT,
     signature TEXT, source_ip TEXT, severity INTEGER, action TEXT, message TEXT,
     dest_ip TEXT, dest_port INTEGER)`
  );
  const stmt = conn.prepare(
    `INSERT INTO events (received_at, category, signature, source_ip, action, message, dest_ip, dest_port)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  for (const r of rows) {
    stmt.run(
      r.received_at,
      r.category,
      r.signature,
      r.source_ip,
      r.action ?? null,
      r.message ?? null,
      r.dest_ip ?? null,
      r.dest_port ?? null
    );
  }
  return { conn };
}

describe('runHourlyChecks', () => {
  it('flags a brand-new signature and a brand-new source IP', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, now);

    const findings = listFindings(lensDb);
    const types = findings.flatMap((f) => f.triggers.map((t) => t.type));
    expect(types).toContain('new_signature');
    expect(types).toContain('new_source_ip');
  });

  it('flags an internal-source event', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '10.0.30.5' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: ['10.0.0.0/8'], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, now);

    const finding = listFindings(lensDb).find((f) => f.entity_key === '10.0.30.5');
    expect(finding?.triggers.some((t) => t.type === 'internal_source')).toBe(true);
  });

  it('flags a repeat offender once it crosses the distinct-day threshold', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const days = ['2026-08-29', '2026-08-30', '2026-08-31'];
    const sinkDb = seededSinkDb(
      days.map((d) => ({ received_at: `${d}T01:00:00Z`, category: 'ips_alert', signature: 'ET SCAN Nmap', source_ip: '203.0.113.9' }))
    );
    const lensDb = openLensDb(':memory:');
    runHourlyChecks({ sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, now);

    const finding = listFindings(lensDb).find((f) => f.entity_key === '203.0.113.9');
    expect(finding?.triggers.some((t) => t.type === 'repeat_offender' && t.active)).toBe(true);
  });
});

describe('runDailyAnomalyCheck', () => {
  it('flags a signature whose count is far above its 14-day baseline', () => {
    const conn = new DatabaseSync(':memory:');
    conn.exec(
      `CREATE TABLE events (id INTEGER PRIMARY KEY, received_at TEXT, category TEXT,
       signature TEXT, source_ip TEXT, severity INTEGER)`
    );
    const stmt = conn.prepare(
      'INSERT INTO events (received_at, category, signature, source_ip) VALUES (?, ?, ?, ?)'
    );
    // 13 quiet days at count 1, then a spike day at count 50
    for (let i = 13; i >= 1; i--) {
      const day = new Date(Date.UTC(2026, 7, 31 - i)).toISOString().slice(0, 10);
      stmt.run(`${day}T01:00:00Z`, 'ips_alert', 'ET TROJAN Foo', '203.0.113.1');
    }
    const spikeDay = '2026-08-30';
    for (let i = 0; i < 50; i++) {
      stmt.run(`${spikeDay}T01:00:00Z`, 'ips_alert', 'ET TROJAN Foo', '203.0.113.1');
    }
    const sinkDb = { conn };
    const lensDb = openLensDb(':memory:');
    runDailyAnomalyCheck({ sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] }, spikeDay);

    const finding = listFindings(lensDb).find((f) => f.entity_key === 'ips_alert|ET TROJAN Foo');
    expect(finding?.triggers.some((t) => t.type === 'anomaly' && t.active)).toBe(true);
  });
});

describe('rule-based triage', () => {
  it('auto-dismisses a reputation-blocklist new_source_ip finding with a rule-sourced analysis', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET DROP Dshield Block Listed Source group 1',
        source_ip: '203.0.113.5',
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '203.0.113.5');
    expect(finding).toBeDefined();
    const requests = getAnalysisRequestsForFinding(lensDb, finding?.id as number);
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe('rule');
    expect(requests[0].status).toBe('answered');
    expect(requests[0].risk_level).toBe('low');

    const sigFinding = listFindings(lensDb, { status: 'dismissed' }).find(
      (f) => f.entity_key === 'ips_alert|ET DROP Dshield Block Listed Source group 1'
    );
    expect(sigFinding).toBeDefined();
    const sigRequests = getAnalysisRequestsForFinding(lensDb, sigFinding?.id as number);
    expect(sigRequests).toHaveLength(1);
    expect(sigRequests[0].source).toBe('rule');
  });

  it('does not auto-dismiss a signature outside the safe-prefix list', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic',
        source_ip: '203.0.113.6',
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb).find((f) => f.entity_key === '203.0.113.6');
    expect(finding?.status).toBe('new');
    expect(getAnalysisRequestsForFinding(lensDb, finding?.id as number)).toHaveLength(0);
  });

  it('auto-dismisses a trusted admin audit-login new_source_ip finding', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'audit',
        signature: null,
        source_ip: '192.168.1.134',
        message: 'Ian C. accessed UniFi Network using the web. Source IP: 192.168.1.134',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: ['Ian C.'], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '192.168.1.134');
    expect(finding).toBeDefined();
  });

  it('leaves an untrusted admin audit login for manual/AI review', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'audit',
        signature: null,
        source_ip: '192.168.1.200',
        message: 'Mallory accessed UniFi Network using the web. Source IP: 192.168.1.200',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: ['Ian C.'], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb).find((f) => f.entity_key === '192.168.1.200');
    expect(finding?.status).toBe('new');
  });

  it('auto-dismisses an operational-noise new_source_ip finding', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'internet_and_wan', signature: null, source_ip: '192.168.1.1' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '192.168.1.1');
    expect(finding).toBeDefined();
  });

  it('auto-dismisses an operational-noise new_signature finding (device telemetry event code)', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'unifi_devices', signature: '512', source_ip: '192.168.1.43' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find(
      (f) => f.entity_key === 'unifi_devices|512'
    );
    expect(finding).toBeDefined();
    const requests = getAnalysisRequestsForFinding(lensDb, finding?.id as number);
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe('rule');
  });

  it('auto-dismisses an operational-noise new_signature finding (software update event code)', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      { received_at: now.toISOString(), category: 'software_updates', signature: '510', source_ip: '192.168.1.207' },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      { sinkDb, lensDb, lanCidrs: [], trustedAdminNames: [], safeSignaturePrefixes: ['ET DROP'] },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find(
      (f) => f.entity_key === 'software_updates|510'
    );
    expect(finding).toBeDefined();
  });

  it('same-pass reopen: a rule-dismissed source IP that also trips internal-source ends the pass as new', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET DROP Dshield Block Listed Source group 1',
        source_ip: '10.0.30.5',
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      {
        sinkDb,
        lensDb,
        lanCidrs: ['10.0.0.0/8'],
        trustedAdminNames: [],
        safeSignaturePrefixes: ['ET DROP'],
      },
      now
    );

    const finding = listFindings(lensDb).find((f) => f.entity_key === '10.0.30.5');
    expect(finding?.status).toBe('new');
    expect(finding?.triggers.some((t) => t.type === 'internal_source' && t.active)).toBe(true);
    expect(finding?.triggers.some((t) => t.type === 'new_source_ip' && t.active)).toBe(true);

    const ruleRequests = getAnalysisRequestsForFinding(lensDb, finding?.id as number).filter((r) => r.source === 'rule');
    expect(ruleRequests).toHaveLength(1);
    expect(ruleRequests[0].status).toBe('answered');
  });

  it('auto-dismisses a new_signature finding whose events all match a known homelab service egress port', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic',
        source_ip: '192.168.1.26',
        dest_ip: '71.1.236.121',
        dest_port: 50300,
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      {
        sinkDb,
        lensDb,
        lanCidrs: [],
        trustedAdminNames: [],
        safeSignaturePrefixes: ['ET DROP'],
        homelabServices: {
          '192.168.1.26': {
            label: 'tranquility',
            services: [{ port: 50300, name: 'slskd', description: 'Soulseek P2P listen port' }],
          },
        },
      },
      now
    );

    const finding = listFindings(lensDb, { status: 'dismissed' }).find(
      (f) => f.entity_key === 'ips_alert|ET MALWARE Backdoor family PCRat/Gh0st CnC traffic'
    );
    expect(finding).toBeDefined();
    const requests = getAnalysisRequestsForFinding(lensDb, finding?.id as number);
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe('rule');
    expect(requests[0].risk_level).toBe('low');
    expect(requests[0].recommendation).toContain('slskd');
  });

  it('does not auto-dismiss via the homelab-service rule when an event falls outside the known port', () => {
    const now = new Date('2026-08-31T12:00:00Z');
    const sinkDb = seededSinkDb([
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic',
        source_ip: '192.168.1.26',
        dest_ip: '71.1.236.121',
        dest_port: 50300,
        action: 'blocked',
      },
      {
        received_at: now.toISOString(),
        category: 'ips_alert',
        signature: 'ET MALWARE Backdoor family PCRat/Gh0st CnC traffic',
        source_ip: '192.168.1.26',
        dest_ip: '198.51.100.9',
        dest_port: 4444,
        action: 'blocked',
      },
    ]);
    const lensDb = openLensDb(':memory:');
    runHourlyChecks(
      {
        sinkDb,
        lensDb,
        lanCidrs: [],
        trustedAdminNames: [],
        safeSignaturePrefixes: ['ET DROP'],
        homelabServices: {
          '192.168.1.26': {
            label: 'tranquility',
            services: [{ port: 50300, name: 'slskd', description: 'Soulseek P2P listen port' }],
          },
        },
      },
      now
    );

    const finding = listFindings(lensDb).find(
      (f) => f.entity_key === 'ips_alert|ET MALWARE Backdoor family PCRat/Gh0st CnC traffic'
    );
    expect(finding?.status).toBe('new');
    expect(getAnalysisRequestsForFinding(lensDb, finding?.id as number)).toHaveLength(0);
  });
});

describe('runRuleTriageBackfill', () => {
  const deps = (sinkDb: ReturnType<typeof seededSinkDb>, lensDb: ReturnType<typeof openLensDb>) => ({
    sinkDb,
    lensDb,
    lanCidrs: [],
    trustedAdminNames: [],
    safeSignaturePrefixes: ['ET DROP'],
  });

  it('dismisses an existing new finding whose window-scoped events all match a rule, and reports counts', () => {
    const firstSeen = '2026-08-20T12:00:00Z';
    const sinkDb = seededSinkDb([
      // Before first_seen, inside [first_seen - 24h, first_seen) — first_seen is stamped
      // with the detection *run* time, at the end of the trailing window, not the start.
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.5', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.5'));

    const result = runRuleTriageBackfill(deps(sinkDb, lensDb));

    expect(result.checked).toBe(1);
    expect(result.dismissed).toBe(1);
    expect(result.byRule.reputation_blocklist).toBe(1);

    const finding = listFindings(lensDb, { status: 'dismissed' }).find((f) => f.entity_key === '203.0.113.5');
    expect(finding).toBeDefined();
    const requests = getAnalysisRequestsForFinding(lensDb, finding?.id as number);
    expect(requests).toHaveLength(1);
    expect(requests[0].source).toBe('rule');
  });

  it('skips findings that are already dismissed or resolved', () => {
    const sinkDb = seededSinkDb([]);
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, {
      entity_type: 'source_ip',
      entity_key: '9.9.9.9',
      first_seen: '2026-08-20T00:00:00Z',
      last_seen: '2026-08-20T00:00:00Z',
      triggers: [{ type: 'new_source_ip', first_seen: '2026-08-20T00:00:00Z', last_seen: '2026-08-20T00:00:00Z', active: true }],
      severity_score: 1,
      status: 'dismissed',
    });

    const result = runRuleTriageBackfill(deps(sinkDb, lensDb));

    expect(result.checked).toBe(0);
    expect(result.dismissed).toBe(0);
  });

  it('re-processes a finding that already has an AI-answered analysis request', () => {
    const firstSeen = '2026-08-20T12:00:00Z';
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.7', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    const finding = upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.7'));
    const aiRequest = createAnalysisRequest(lensDb, finding.id as number, {}, '2026-08-20T13:00:00Z');
    submitAnalysis(lensDb, aiRequest.id, 'looked benign to Claude', 'low', '2026-08-20T13:05:00Z');

    const result = runRuleTriageBackfill(deps(sinkDb, lensDb));

    expect(result.dismissed).toBe(1);
    const requests = getAnalysisRequestsForFinding(lensDb, finding.id as number);
    expect(requests).toHaveLength(2);
    expect(requests.some((r) => r.source === 'ai')).toBe(true);
    expect(requests.some((r) => r.source === 'rule')).toBe(true);
  });

  it('anchors the completeness window to [first_seen - 24h, first_seen), not to now', () => {
    const firstSeen = '2026-08-20T12:00:00Z';
    const sinkDb = seededSinkDb([
      { received_at: '2026-08-20T01:00:00Z', category: 'ips_alert', signature: 'ET DROP Foo', source_ip: '203.0.113.9', action: 'blocked' },
      // Outside the [first_seen - 24h, first_seen) window (it's after first_seen) and
      // non-matching — must not count toward `total`, or completeness would wrongly fail.
      { received_at: '2026-09-01T00:00:00Z', category: 'ips_alert', signature: 'ET MALWARE Bar', source_ip: '203.0.113.9', action: 'blocked' },
    ]);
    const lensDb = openLensDb(':memory:');
    upsertFinding(lensDb, applyTrigger(null, 'new_source_ip', firstSeen, 'source_ip', '203.0.113.9'));

    const result = runRuleTriageBackfill(deps(sinkDb, lensDb));

    expect(result.dismissed).toBe(1);
  });
});
