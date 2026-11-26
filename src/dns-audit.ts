import { promises as dns } from 'node:dns';
import { createPublicKey } from 'node:crypto';

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface CaaRecord {
  critical: number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
}

export interface DnsResolver {
  resolveTxt(hostname: string): Promise<string[][]>;
  resolveMx(hostname: string): Promise<MxRecord[]>;
  resolveCaa(hostname: string): Promise<CaaRecord[]>;
}

export type Severity = 'ok' | 'warn' | 'error';

export interface AuditFinding {
  code: string;
  severity: Severity;
  message: string;
}

export interface SpfLookupNode {
  domain: string;
  mechanism: string;
  record: string | null;
  children: SpfLookupNode[];
  loop?: boolean;
  error?: string;
}

export interface SpfAuditResult {
  present: boolean;
  record: string | null;
  multipleRecords: boolean;
  lookupCount: number;
  maxLookups: number;
  status: Severity;
  allQualifier: string | null;
  loops: string[];
  tree: SpfLookupNode | null;
  findings: AuditFinding[];
}

export interface DmarcAuditResult {
  present: boolean;
  record: string | null;
  validVersion: boolean;
  policy: 'none' | 'quarantine' | 'reject' | null;
  subdomainPolicy: 'none' | 'quarantine' | 'reject' | null;
  pct: number;
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  rua: string[];
  ruf: string[];
  status: Severity;
  findings: AuditFinding[];
}

export interface DkimSelectorResult {
  selector: string;
  host: string;
  present: boolean;
  record: string | null;
  keyType: string | null;
  keyBits: number | null;
  revoked: boolean;
  status: Severity;
  findings: AuditFinding[];
}

export interface MtaStsResult {
  present: boolean;
  record: string | null;
  id: string | null;
  status: Severity;
}

export interface TlsRptResult {
  present: boolean;
  record: string | null;
  rua: string[];
  status: Severity;
}

export interface CaaAuditResult {
  present: boolean;
  records: CaaRecord[];
  status: Severity;
}

export interface DnsAuditReport {
  domain: string;
  auditedAt: string;
  mx: MxRecord[];
  spf: SpfAuditResult;
  dmarc: DmarcAuditResult;
  dkim: DkimSelectorResult[];
  mtaSts: MtaStsResult;
  tlsRpt: TlsRptResult;
  caa: CaaAuditResult;
  score: number;
  findings: AuditFinding[];
}

export interface DnsAuditOptions {
  selectors?: string[];
  resolver?: DnsResolver;
  timeoutMs?: number;
  maxSpfDepth?: number;
}

export const DEFAULT_DKIM_SELECTORS = [
  'google',
  'selector1',
  'selector2',
  's1',
  's2',
  'default',
  'k1'
];

function createDefaultResolver(): DnsResolver {
  return {
    resolveTxt: (hostname: string) => dns.resolveTxt(hostname),
    resolveMx: (hostname: string) => dns.resolveMx(hostname),
    resolveCaa: (hostname: string) => dns.resolveCaa(hostname) as Promise<CaaRecord[]>
  };
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`DNS timeout after ${timeoutMs}ms (${label})`)), timeoutMs);
      })
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function safeResolveTxt(resolver: DnsResolver, host: string, timeoutMs: number): Promise<string[]> {
  try {
    const chunks = await withTimeout(resolver.resolveTxt(host), timeoutMs, `TXT ${host}`);
    return chunks.map((parts) => parts.join(''));
  } catch (err: unknown) {
    const code = (err as { code?: string })?.code;
    if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'NXDOMAIN') {
      return [];
    }
    throw err;
  }
}

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, '');
}

export async function auditSpf(
  domain: string,
  resolver: DnsResolver,
  timeoutMs = 5000,
  maxDepth = 15
): Promise<SpfAuditResult> {
  const normalized = normalizeDomain(domain);
  const findings: AuditFinding[] = [];
  const loops: string[] = [];
  let lookupCount = 0;

  let rootTxt: string[] = [];
  try {
    rootTxt = await safeResolveTxt(resolver, normalized, timeoutMs);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    findings.push({ code: 'SPF_DNS_ERROR', severity: 'error', message: `Failed to query SPF TXT for ${normalized}: ${msg}` });
    return {
      present: false,
      record: null,
      multipleRecords: false,
      lookupCount: 0,
      maxLookups: 10,
      status: 'error',
      allQualifier: null,
      loops,
      tree: null,
      findings
    };
  }

  const spfRecords = rootTxt.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (spfRecords.length === 0) {
    findings.push({ code: 'SPF_MISSING', severity: 'error', message: `No SPF (v=spf1) TXT record found for ${normalized}` });
    return {
      present: false,
      record: null,
      multipleRecords: false,
      lookupCount: 0,
      maxLookups: 10,
      status: 'error',
      allQualifier: null,
      loops,
      tree: null,
      findings
    };
  }

  const multipleRecords = spfRecords.length > 1;
  if (multipleRecords) {
    findings.push({
      code: 'SPF_MULTIPLE',
      severity: 'error',
      message: `Found ${spfRecords.length} SPF records on ${normalized} (RFC 7208 allows only 1)`
    });
  }

  const rootRecord = spfRecords[0] ?? null;
  let allQualifier: string | null = null;

  const walk = async (
    targetDomain: string,
    mechanismLabel: string,
    ancestors: Set<string>,
    depth: number,
    knownRecord?: string
  ): Promise<SpfLookupNode> => {
    const normTarget = normalizeDomain(targetDomain);
    if (ancestors.has(normTarget)) {
      loops.push(normTarget);
      findings.push({
        code: 'SPF_LOOP',
        severity: 'error',
        message: `Circular SPF reference detected involving ${normTarget}`
      });
      return { domain: normTarget, mechanism: mechanismLabel, record: null, children: [], loop: true };
    }

    if (depth > maxDepth) {
      findings.push({
        code: 'SPF_MAX_DEPTH',
        severity: 'error',
        message: `SPF recursion exceeded maximum depth (${maxDepth}) at ${normTarget}`
      });
      return { domain: normTarget, mechanism: mechanismLabel, record: null, children: [], error: 'Max depth exceeded' };
    }

    let record = knownRecord ?? null;
    if (record === null) {
      try {
        const txts = await safeResolveTxt(resolver, normTarget, timeoutMs);
        const matches = txts.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
        if (matches.length > 1) {
          findings.push({
            code: 'SPF_CHILD_MULTIPLE',
            severity: 'error',
            message: `Included SPF domain ${normTarget} has ${matches.length} SPF records`
          });
        }
        record = matches[0] ?? null;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        findings.push({ code: 'SPF_LOOKUP_ERROR', severity: 'error', message: `SPF lookup error on ${normTarget}: ${msg}` });
        return { domain: normTarget, mechanism: mechanismLabel, record: null, children: [], error: msg };
      }
    }

    const node: SpfLookupNode = { domain: normTarget, mechanism: mechanismLabel, record, children: [] };
    if (!record) {
      findings.push({
        code: 'SPF_INCLUDE_MISSING',
        severity: 'warn',
        message: `No SPF record found at referenced domain ${normTarget}`
      });
      return node;
    }

    const nextAncestors = new Set(ancestors);
    nextAncestors.add(normTarget);

    const tokens = record.trim().split(/\s+/).slice(1);
    const hasAllMechanism = tokens.some((t) => /^[+\-~?]?all$/i.test(t));
    for (const rawToken of tokens) {
      if (!rawToken) continue;
      const qualifierMatch = /^([+\-~?])?(.*)$/.exec(rawToken);
      const qualifier = qualifierMatch?.[1] ?? '+';
      const body = (qualifierMatch?.[2] ?? rawToken).toLowerCase();

      if (body === 'all') {
        if (depth === 0) {
          allQualifier = `${qualifier}all`;
          if (qualifier === '+') {
            findings.push({
              code: 'SPF_PLUS_ALL',
              severity: 'error',
              message: `SPF ends with +all on ${normTarget}, allowing any IP to send mail`
            });
          } else if (qualifier === '?') {
            findings.push({
              code: 'SPF_NEUTRAL_ALL',
              severity: 'warn',
              message: `SPF ends with ?all (neutral) on ${normTarget}; prefer ~all or -all`
            });
          }
        }
        continue;
      }

      if (body.startsWith('ip4:') || body.startsWith('ip6:') || body.startsWith('exp=')) {
        continue;
      }

      if (body.startsWith('include:')) {
        const incDomain = body.slice('include:'.length);
        lookupCount += 1;
        if (incDomain) {
          const child = await walk(incDomain, rawToken, nextAncestors, depth + 1);
          node.children.push(child);
        }
      } else if (body.startsWith('redirect=')) {
        if (hasAllMechanism) {
          // RFC 7208 Section 6.1: redirect modifier MUST be ignored if an "all" mechanism is present
          continue;
        }
        const redirDomain = body.slice('redirect='.length);
        lookupCount += 1;
        if (redirDomain) {
          const child = await walk(redirDomain, rawToken, nextAncestors, depth + 1);
          node.children.push(child);
        }
      } else if (
        body === 'a' || body.startsWith('a:') || body.startsWith('a/') ||
        body === 'mx' || body.startsWith('mx:') || body.startsWith('mx/') ||
        body === 'ptr' || body.startsWith('ptr:') ||
        body.startsWith('exists:')
      ) {
        lookupCount += 1;
        if (body === 'ptr' || body.startsWith('ptr:')) {
          findings.push({
            code: 'SPF_PTR_DEPRECATED',
            severity: 'warn',
            message: `SPF uses deprecated ptr mechanism on ${normTarget}`
          });
        }
      }
    }

    return node;
  };

  const tree = await walk(normalized, 'root', new Set<string>(), 0, rootRecord ?? undefined);

  if (lookupCount > 10) {
    findings.push({
      code: 'SPF_LOOKUP_EXCEEDED',
      severity: 'error',
      message: `SPF requires ${lookupCount}/10 DNS lookups (exceeds RFC 7208 limit of 10 — PermError risk)`
    });
  } else if (lookupCount >= 9) {
    findings.push({
      code: 'SPF_LOOKUP_NEAR_LIMIT',
      severity: 'warn',
      message: `SPF uses ${lookupCount}/10 DNS lookups (at 9–10 ceiling — high risk of exceeding limit)`
    });
  }

  const status: Severity = findings.some((f) => f.severity === 'error')
    ? 'error'
    : findings.some((f) => f.severity === 'warn')
      ? 'warn'
      : 'ok';

  return {
    present: true,
    record: rootRecord,
    multipleRecords,
    lookupCount,
    maxLookups: 10,
    status,
    allQualifier,
    loops,
    tree,
    findings
  };
}

export async function auditDmarc(
  domain: string,
  resolver: DnsResolver,
  timeoutMs = 5000
): Promise<DmarcAuditResult> {
  const normalized = normalizeDomain(domain);
  const host = `_dmarc.${normalized}`;
  const findings: AuditFinding[] = [];

  let txts: string[] = [];
  try {
    txts = await safeResolveTxt(resolver, host, timeoutMs);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    findings.push({ code: 'DMARC_DNS_ERROR', severity: 'error', message: `Failed to query DMARC TXT for ${host}: ${msg}` });
    return {
      present: false,
      record: null,
      validVersion: false,
      policy: null,
      subdomainPolicy: null,
      pct: 100,
      adkim: 'r',
      aspf: 'r',
      rua: [],
      ruf: [],
      status: 'error',
      findings
    };
  }

  const dmarcRecords = txts.filter((r) => /^v=DMARC1(\s*;|$)/i.test(r.trim()));
  if (dmarcRecords.length === 0) {
    findings.push({ code: 'DMARC_MISSING', severity: 'error', message: `No DMARC record (v=DMARC1) found at ${host}` });
    return {
      present: false,
      record: null,
      validVersion: false,
      policy: null,
      subdomainPolicy: null,
      pct: 100,
      adkim: 'r',
      aspf: 'r',
      rua: [],
      ruf: [],
      status: 'error',
      findings
    };
  }

  if (dmarcRecords.length > 1) {
    findings.push({
      code: 'DMARC_MULTIPLE',
      severity: 'error',
      message: `Found ${dmarcRecords.length} DMARC records at ${host} (only 1 is permitted)`
    });
  }

  const record = dmarcRecords[0] ?? '';
  const tags = new Map<string, string>();
  for (const part of record.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim().toLowerCase();
    const val = trimmed.slice(eqIdx + 1).trim();
    tags.set(key, val);
  }

  const validVersion = tags.get('v') === 'DMARC1';
  if (!validVersion) {
    findings.push({ code: 'DMARC_INVALID_VERSION', severity: 'error', message: `Invalid DMARC version tag at ${host}` });
  }

  const rawP = tags.get('p')?.toLowerCase();
  const policy = rawP === 'none' || rawP === 'quarantine' || rawP === 'reject' ? rawP : null;
  if (!policy) {
    findings.push({ code: 'DMARC_INVALID_POLICY', severity: 'error', message: `Missing or invalid DMARC policy (p=) at ${host}` });
  } else if (policy === 'none') {
    findings.push({
      code: 'DMARC_POLICY_NONE',
      severity: 'warn',
      message: `DMARC policy is p=none (monitoring only); consider moving to quarantine or reject`
    });
  }

  const rawSp = tags.get('sp')?.toLowerCase();
  const subdomainPolicy = rawSp === 'none' || rawSp === 'quarantine' || rawSp === 'reject' ? rawSp : null;

  const rawPct = tags.get('pct');
  const parsedPct = rawPct !== undefined ? Number.parseInt(rawPct, 10) : 100;
  const pct = Number.isFinite(parsedPct) && parsedPct >= 0 && parsedPct <= 100 ? parsedPct : 100;
  if (rawPct !== undefined && (!Number.isFinite(parsedPct) || parsedPct < 0 || parsedPct > 100)) {
    findings.push({ code: 'DMARC_INVALID_PCT', severity: 'warn', message: `Invalid DMARC pct=${rawPct}` });
  } else if (pct < 100) {
    findings.push({ code: 'DMARC_PARTIAL_PCT', severity: 'warn', message: `DMARC pct=${pct}% (not applied to 100% of mail)` });
  }

  const adkim: 'r' | 's' = tags.get('adkim')?.toLowerCase() === 's' ? 's' : 'r';
  const aspf: 'r' | 's' = tags.get('aspf')?.toLowerCase() === 's' ? 's' : 'r';

  const rua = (tags.get('rua') ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const ruf = (tags.get('ruf') ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (rua.length === 0) {
    findings.push({
      code: 'DMARC_NO_RUA',
      severity: 'warn',
      message: `DMARC record has no rua= aggregate report destination`
    });
  }
  if (ruf.length > 0) {
    findings.push({
      code: 'DMARC_RUF_PRIVACY_NOTE',
      severity: 'warn',
      message: `DMARC record enables ruf= forensic reports (contains PII; DMARCZero strictly rejects RUF ingestion)`
    });
  }

  const status: Severity = findings.some((f) => f.severity === 'error')
    ? 'error'
    : findings.some((f) => f.severity === 'warn')
      ? 'warn'
      : 'ok';

  return {
    present: true,
    record,
    validVersion,
    policy,
    subdomainPolicy,
    pct,
    adkim,
    aspf,
    rua,
    ruf,
    status,
    findings
  };
}

function measureDkimKeyBits(base64PubKey: string, keyType: string): number | null {
  if (!base64PubKey) return null;
  try {
    const clean = base64PubKey.replace(/\s+/g, '');
    const der = Buffer.from(clean, 'base64');
    if (der.length === 0) return null;
    if (keyType.toLowerCase() === 'ed25519') {
      return der.length * 8;
    }
    const pem = `-----BEGIN PUBLIC KEY-----\n${clean.match(/.{1,64}/g)?.join('\n') ?? clean}\n-----END PUBLIC KEY-----`;
    const keyObj = createPublicKey(pem);
    const details = keyObj.asymmetricKeyDetails;
    if (details?.modulusLength) {
      return details.modulusLength;
    }
    return null;
  } catch {
    return null;
  }
}

export async function auditDkim(
  domain: string,
  selectors: string[],
  resolver: DnsResolver,
  timeoutMs = 5000
): Promise<DkimSelectorResult[]> {
  const normalized = normalizeDomain(domain);
  const results: DkimSelectorResult[] = [];

  for (const rawSelector of selectors) {
    const selector = rawSelector.trim();
    if (!selector) continue;
    const host = `${selector}._domainkey.${normalized}`;
    const findings: AuditFinding[] = [];

    let txts: string[] = [];
    try {
      txts = await safeResolveTxt(resolver, host, timeoutMs);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({ code: 'DKIM_DNS_ERROR', severity: 'warn', message: `Failed to query DKIM ${host}: ${msg}` });
      results.push({
        selector,
        host,
        present: false,
        record: null,
        keyType: null,
        keyBits: null,
        revoked: false,
        status: 'warn',
        findings
      });
      continue;
    }

    const dkimRecord = txts.find((t) => /(^|;\s*)p=/i.test(t) || /^v=DKIM1/i.test(t.trim())) ?? null;
    if (!dkimRecord) {
      results.push({
        selector,
        host,
        present: false,
        record: null,
        keyType: null,
        keyBits: null,
        revoked: false,
        status: 'ok',
        findings
      });
      continue;
    }

    const tags = new Map<string, string>();
    for (const part of dkimRecord.split(';')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      tags.set(trimmed.slice(0, eqIdx).trim().toLowerCase(), trimmed.slice(eqIdx + 1).trim());
    }

    const keyType = (tags.get('k') ?? 'rsa').toLowerCase();
    const pubKey = tags.get('p') ?? '';
    const revoked = tags.has('p') && pubKey === '';

    if (revoked) {
      findings.push({
        code: 'DKIM_KEY_REVOKED',
        severity: 'warn',
        message: `DKIM selector "${selector}" has an empty p= tag (key revoked)`
      });
    }

    const keyBits = revoked ? 0 : measureDkimKeyBits(pubKey, keyType);
    if (!revoked && keyType === 'rsa' && keyBits !== null && keyBits < 2048) {
      findings.push({
        code: 'DKIM_WEAK_RSA_KEY',
        severity: 'warn',
        message: `DKIM selector "${selector}" uses a weak ${keyBits}-bit RSA key (< 2048 bits)`
      });
    }

    const status: Severity = findings.some((f) => f.severity === 'error')
      ? 'error'
      : findings.some((f) => f.severity === 'warn')
        ? 'warn'
        : 'ok';

    results.push({
      selector,
      host,
      present: true,
      record: dkimRecord,
      keyType,
      keyBits,
      revoked,
      status,
      findings
    });
  }

  return results;
}

export async function auditDns(domain: string, options: DnsAuditOptions = {}): Promise<DnsAuditReport> {
  const normalized = normalizeDomain(domain);
  const resolver = options.resolver ?? createDefaultResolver();
  const timeoutMs = options.timeoutMs ?? 5000;
  const selectors = options.selectors && options.selectors.length > 0 ? options.selectors : DEFAULT_DKIM_SELECTORS;

  const [spf, dmarc, dkim, mx, mtaStsTxts, tlsRptTxts, caaRecords] = await Promise.all([
    auditSpf(normalized, resolver, timeoutMs, options.maxSpfDepth ?? 15),
    auditDmarc(normalized, resolver, timeoutMs),
    auditDkim(normalized, selectors, resolver, timeoutMs),
    withTimeout(resolver.resolveMx(normalized), timeoutMs, `MX ${normalized}`).catch(() => [] as MxRecord[]),
    safeResolveTxt(resolver, `_mta-sts.${normalized}`, timeoutMs).catch(() => [] as string[]),
    safeResolveTxt(resolver, `_smtp._tls.${normalized}`, timeoutMs).catch(() => [] as string[]),
    withTimeout(resolver.resolveCaa(normalized), timeoutMs, `CAA ${normalized}`).catch(() => [] as CaaRecord[])
  ]);

  const mtaStsRec = mtaStsTxts.find((t) => /^v=STSv1/i.test(t.trim())) ?? null;
  const mtaStsIdMatch = mtaStsRec ? /(?:^|;\s*)id=([^;\s]+)/i.exec(mtaStsRec) : null;
  const mtaSts: MtaStsResult = {
    present: mtaStsRec !== null,
    record: mtaStsRec,
    id: mtaStsIdMatch?.[1] ?? null,
    status: mtaStsRec ? 'ok' : 'warn'
  };

  const tlsRptRec = tlsRptTxts.find((t) => /^v=TLSRPTv1/i.test(t.trim())) ?? null;
  const tlsRptRuaMatch = tlsRptRec ? /(?:^|;\s*)rua=([^;]+)/i.exec(tlsRptRec) : null;
  const tlsRpt: TlsRptResult = {
    present: tlsRptRec !== null,
    record: tlsRptRec,
    rua: tlsRptRuaMatch?.[1] ? tlsRptRuaMatch[1].split(',').map((s) => s.trim()).filter(Boolean) : [],
    status: tlsRptRec ? 'ok' : 'warn'
  };

  const caa: CaaAuditResult = {
    present: caaRecords.length > 0,
    records: caaRecords,
    status: caaRecords.length > 0 ? 'ok' : 'warn'
  };

  const allFindings: AuditFinding[] = [
    ...spf.findings,
    ...dmarc.findings,
    ...dkim.flatMap((d) => d.findings)
  ];

  const activeDkim = dkim.filter((d) => d.present && !d.revoked);
  if (activeDkim.length === 0) {
    allFindings.push({
      code: 'DKIM_NONE_FOUND',
      severity: 'warn',
      message: `No active DKIM keys found for probed selectors (${selectors.join(', ')})`
    });
  }
  if (!mtaSts.present) {
    allFindings.push({ code: 'MTA_STS_MISSING', severity: 'warn', message: `No MTA-STS record found at _mta-sts.${normalized}` });
  }
  if (!tlsRpt.present) {
    allFindings.push({ code: 'TLS_RPT_MISSING', severity: 'warn', message: `No TLS-RPT record found at _smtp._tls.${normalized}` });
  }
  if (!caa.present) {
    allFindings.push({ code: 'CAA_MISSING', severity: 'warn', message: `No CAA records found for ${normalized}` });
  }

  let score = 100;
  for (const f of allFindings) {
    if (f.severity === 'error') score -= 20;
    else if (f.severity === 'warn') score -= 7;
  }
  score = Math.max(0, Math.min(100, score));

  const sortedMx = [...mx].sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange));

  return {
    domain: normalized,
    auditedAt: new Date().toISOString(),
    mx: sortedMx,
    spf,
    dmarc,
    dkim,
    mtaSts,
    tlsRpt,
    caa,
    score,
    findings: allFindings
  };
}
