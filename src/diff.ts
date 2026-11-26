import { readFile, writeFile } from 'node:fs/promises';
import type { DnsAuditReport } from './dns-audit.js';
import type { TlsAuditResult } from './tls-audit.js';

export interface DomainSnapshot {
  schemaVersion: 1;
  domain: string;
  capturedAt: string;
  dns: {
    mx: Array<{ priority: number; exchange: string }>;
    spfRecord: string | null;
    spfLookupCount: number;
    dmarcRecord: string | null;
    dmarcPolicy: string | null;
    dkim: Array<{ selector: string; record: string | null; keyBits: number | null; revoked: boolean }>;
    mtaStsRecord: string | null;
    tlsRptRecord: string | null;
    caaRecords: Array<{ critical: number; issue?: string; issuewild?: string; iodef?: string }>;
  };
  tls: {
    host: string;
    port: number;
    authorized?: boolean;
    authorizationError?: string | null;
    fingerprint256: string | null;
    validTo: string | null;
    daysRemaining: number | null;
    status: string;
  } | null;
}

export interface DriftChange {
  field: string;
  severity: 'warn' | 'error';
  before: string;
  after: string;
  message: string;
}

export interface DriftReport {
  domain: string;
  comparedAt: string;
  hasDrift: boolean;
  changes: DriftChange[];
}

export function createSnapshot(dnsReport: DnsAuditReport, tlsResult: TlsAuditResult | null = null): DomainSnapshot {
  return {
    schemaVersion: 1,
    domain: dnsReport.domain,
    capturedAt: new Date().toISOString(),
    dns: {
      mx: [...dnsReport.mx]
        .map((m) => ({ priority: m.priority, exchange: m.exchange.toLowerCase() }))
        .sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange)),
      spfRecord: dnsReport.spf.record,
      spfLookupCount: dnsReport.spf.lookupCount,
      dmarcRecord: dnsReport.dmarc.record,
      dmarcPolicy: dnsReport.dmarc.policy,
      dkim: [...dnsReport.dkim]
        .filter((d) => d.present)
        .map((d) => ({
          selector: d.selector,
          record: d.record,
          keyBits: d.keyBits,
          revoked: d.revoked
        }))
        .sort((a, b) => a.selector.localeCompare(b.selector)),
      mtaStsRecord: dnsReport.mtaSts.record,
      tlsRptRecord: dnsReport.tlsRpt.record,
      caaRecords: [...dnsReport.caa.records].sort((a, b) =>
        JSON.stringify(a).localeCompare(JSON.stringify(b))
      )
    },
    tls: tlsResult
      ? {
          host: tlsResult.host,
          port: tlsResult.port,
          authorized: tlsResult.authorized,
          authorizationError: tlsResult.authorizationError,
          fingerprint256: tlsResult.fingerprint256,
          validTo: tlsResult.validTo,
          daysRemaining: tlsResult.daysRemaining,
          status: tlsResult.status
        }
      : null
  };
}

export async function saveSnapshot(filePath: string, snapshot: DomainSnapshot): Promise<void> {
  await writeFile(filePath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
}

export async function loadSnapshot(filePath: string): Promise<DomainSnapshot> {
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw) as DomainSnapshot;
  if (!parsed || parsed.schemaVersion !== 1 || !parsed.domain || !parsed.dns) {
    throw new Error(`Invalid DMARCZero snapshot file: ${filePath}`);
  }
  return parsed;
}

export function diffSnapshots(baseline: DomainSnapshot, current: DomainSnapshot): DriftReport {
  const changes: DriftChange[] = [];

  // SPF drift
  if (baseline.dns.spfRecord !== current.dns.spfRecord) {
    changes.push({
      field: 'dns.spfRecord',
      severity: 'error',
      before: baseline.dns.spfRecord ?? '(none)',
      after: current.dns.spfRecord ?? '(none)',
      message: 'SPF TXT record changed'
    });
  }
  if (baseline.dns.spfLookupCount !== current.dns.spfLookupCount) {
    changes.push({
      field: 'dns.spfLookupCount',
      severity: current.dns.spfLookupCount > 10 ? 'error' : 'warn',
      before: String(baseline.dns.spfLookupCount),
      after: String(current.dns.spfLookupCount),
      message: `SPF DNS lookup count changed (${baseline.dns.spfLookupCount} -> ${current.dns.spfLookupCount})`
    });
  }

  // DMARC drift
  if (baseline.dns.dmarcRecord !== current.dns.dmarcRecord) {
    changes.push({
      field: 'dns.dmarcRecord',
      severity: 'error',
      before: baseline.dns.dmarcRecord ?? '(none)',
      after: current.dns.dmarcRecord ?? '(none)',
      message: 'DMARC TXT record changed'
    });
  }

  // MX drift
  const baseMx = JSON.stringify(baseline.dns.mx);
  const currMx = JSON.stringify(current.dns.mx);
  if (baseMx !== currMx) {
    changes.push({
      field: 'dns.mx',
      severity: 'error',
      before: baseMx,
      after: currMx,
      message: 'MX records changed'
    });
  }

  // DKIM drift
  const baseDkim = JSON.stringify(baseline.dns.dkim);
  const currDkim = JSON.stringify(current.dns.dkim);
  if (baseDkim !== currDkim) {
    changes.push({
      field: 'dns.dkim',
      severity: 'error',
      before: baseDkim,
      after: currDkim,
      message: 'DKIM selector keys changed'
    });
  }

  // MTA-STS / TLS-RPT / CAA drift
  if (baseline.dns.mtaStsRecord !== current.dns.mtaStsRecord) {
    changes.push({
      field: 'dns.mtaStsRecord',
      severity: 'warn',
      before: baseline.dns.mtaStsRecord ?? '(none)',
      after: current.dns.mtaStsRecord ?? '(none)',
      message: 'MTA-STS TXT record changed'
    });
  }
  if (baseline.dns.tlsRptRecord !== current.dns.tlsRptRecord) {
    changes.push({
      field: 'dns.tlsRptRecord',
      severity: 'warn',
      before: baseline.dns.tlsRptRecord ?? '(none)',
      after: current.dns.tlsRptRecord ?? '(none)',
      message: 'TLS-RPT TXT record changed'
    });
  }
  const baseCaa = JSON.stringify(baseline.dns.caaRecords);
  const currCaa = JSON.stringify(current.dns.caaRecords);
  if (baseCaa !== currCaa) {
    changes.push({
      field: 'dns.caaRecords',
      severity: 'warn',
      before: baseCaa,
      after: currCaa,
      message: 'CAA records changed'
    });
  }

  // TLS drift
  if (baseline.tls && current.tls) {
    if (baseline.tls.fingerprint256 !== current.tls.fingerprint256) {
      changes.push({
        field: 'tls.fingerprint256',
        severity: 'warn',
        before: baseline.tls.fingerprint256 ?? '(none)',
        after: current.tls.fingerprint256 ?? '(none)',
        message: 'TLS certificate fingerprint changed'
      });
    }
    if (
      baseline.tls.authorized !== undefined &&
      current.tls.authorized !== undefined &&
      baseline.tls.authorized !== current.tls.authorized
    ) {
      changes.push({
        field: 'tls.authorized',
        severity: current.tls.authorized ? 'warn' : 'error',
        before: String(baseline.tls.authorized),
        after: String(current.tls.authorized),
        message: current.tls.authorized
          ? 'TLS certificate trust restored'
          : `TLS certificate became untrusted (${current.tls.authorizationError ?? 'verification failed'})`
      });
    }
    if (current.tls.status === 'critical' || current.tls.status === 'expired' || current.tls.status === 'error') {
      if (baseline.tls.status !== current.tls.status) {
        changes.push({
          field: 'tls.status',
          severity: 'error',
          before: baseline.tls.status,
          after: current.tls.status,
          message: `TLS certificate status degraded (${baseline.tls.status} -> ${current.tls.status})`
        });
      }
    }
  } else if (Boolean(baseline.tls) !== Boolean(current.tls)) {
    changes.push({
      field: 'tls',
      severity: 'warn',
      before: baseline.tls ? `${baseline.tls.host}:${baseline.tls.port}` : '(none)',
      after: current.tls ? `${current.tls.host}:${current.tls.port}` : '(none)',
      message: 'TLS snapshot presence changed'
    });
  }

  return {
    domain: current.domain,
    comparedAt: new Date().toISOString(),
    hasDrift: changes.length > 0,
    changes
  };
}
