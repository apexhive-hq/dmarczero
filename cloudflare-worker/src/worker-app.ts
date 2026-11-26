import { createPrivateKey, sign as nodeEd25519Sign } from 'node:crypto';
import {
  parseStrictHexBigInt,
  rpcCallWithFailover,
  sumBaseUsdcTransfers,
  verifySmartWalletOrEoaSignature,
  type RpcReceipt
} from './base-verifier.js';
import { parseIncomingRuaMime, type WorkerRuaSource, type WorkerRuaSummary } from './email-handler.js';
import {
  diffDomainSnapshots,
  fetchDomainDnsSnapshot,
  sendSafeWebhookAlert,
  type DohDnsSnapshot
} from './cron-monitor.js';

export const APEXHIVE_BASE_USDC_RECIPIENT = '0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206';
export const BASE_USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const SCOPE_DMARCZERO = 'storefront:dmarczero';

const TX_HASH_RE = /^0x[a-fA-F0-9]{64}$/;
const SIG_RE = /^0x(?:[0-9a-fA-F]{2}){32,8192}$/;
const MAX_JSON_BYTES = 32 * 1024;
const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base'
];

export interface Env {
  DMARC_STORE: DurableObjectNamespace;
  MONITORED_DOMAINS?: string;
  ALLOWED_ORIGINS?: string;
  ALERT_WEBHOOK_URL?: string;
  WEBHOOK_ALLOWLIST?: string;
  PASS_RATE_ALERT_THRESHOLD?: string;
  BRAND_NAME?: string;
  PRODUCT_ID?: string;
  PAY_TO_EVM_ADDRESS?: string;
  BASE_USDC_CONTRACT?: string;
  BASE_CHAIN_ID?: string;
  BASE_RPC_URL?: string;
  BASE_RPC_URLS?: string;
  TEAM_PRICE_USDC_ATOMIC?: string;
  ENTERPRISE_PRICE_USDC_ATOMIC?: string;
  MIN_CONFIRMATIONS?: string;
  CHALLENGE_TTL_SECONDS?: string;
  LICENSE_SIGNING_PRIVATE_JWK?: string;
  LICENSE_SIGNING_PUBLIC_SPKI_B64?: string;
}

export type CommercialTier = 'team' | 'enterprise';

export interface WalletLicenseRequest {
  tier: CommercialTier;
  txHash: string;
  nonce: string;
  signature: string;
  holder?: string;
  signerAddress?: string;
  recipientAddress?: string;
  walletType?: 'eip191' | 'erc1271' | 'eip6492';
}

interface ChallengeRecord {
  nonce: string;
  txHash: string;
  tier: CommercialTier;
  ts: number;
  message: string;
}

function parseTier(raw: unknown): CommercialTier | null {
  const val = typeof raw === 'string' ? raw.trim() : '';
  if (val === 'team' || val === 'enterprise') return val;
  return null;
}

function getTierPriceAtomic(env: Env, tier: CommercialTier): bigint {
  if (tier === 'enterprise') return BigInt(env.ENTERPRISE_PRICE_USDC_ATOMIC || '499000000');
  return BigInt(env.TEAM_PRICE_USDC_ATOMIC || '99000000');
}

function getBaseRpcUrls(env: Env): string[] {
  if (env.BASE_RPC_URLS && env.BASE_RPC_URLS.trim()) {
    const parsed = env.BASE_RPC_URLS.split(',')
      .map((u) => u.trim())
      .filter(Boolean);
    if (parsed.length > 0) return parsed;
  }
  if (env.BASE_RPC_URL && env.BASE_RPC_URL.trim()) {
    return [env.BASE_RPC_URL.trim()];
  }
  return DEFAULT_BASE_RPC_URLS;
}

function randomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function buildChallengeMessage(params: {
  brand: string;
  product: string;
  tier: CommercialTier;
  txHash: string;
  nonce: string;
  ts: number;
}): string {
  return [
    `${params.brand} DMARCZero Commercial Ownership Proof`,
    `product=${params.product}`,
    `tier=${params.tier}`,
    `tx=${params.txHash.toLowerCase()}`,
    `nonce=${params.nonce}`,
    `ts=${params.ts}`
  ].join('\n');
}

function canonicalizeLicensePayload(payload: {
  product: 'dmarczero';
  tier: CommercialTier;
  holder: string;
  seats: number;
  issuedAt: string;
  txHash: string;
}): string {
  return JSON.stringify({
    product: payload.product,
    tier: payload.tier,
    holder: payload.holder,
    seats: payload.seats,
    issuedAt: payload.issuedAt,
    txHash: payload.txHash
  });
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function signCommercialCertificate(
  env: Env,
  payload: {
    product: 'dmarczero';
    tier: CommercialTier;
    holder: string;
    seats: number;
    issuedAt: string;
    txHash: string;
  }
): Promise<{ payload: typeof payload; signature: string }> {
  const rawKey = env.LICENSE_SIGNING_PRIVATE_JWK!.trim().replace(/^'(.*)'$/, '$1');
  const signingInput = new TextEncoder().encode(canonicalizeLicensePayload(payload));

  if (rawKey.startsWith('-----BEGIN')) {
    const privKey = createPrivateKey({ key: rawKey, format: 'pem' });
    const sigBuf = nodeEd25519Sign(null, Buffer.from(signingInput), privKey);
    return { payload, signature: base64UrlEncode(new Uint8Array(sigBuf)) };
  }

  const jwk = JSON.parse(rawKey) as JsonWebKey;
  try {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
    const sigBuf = await crypto.subtle.sign('Ed25519', key, signingInput);
    return { payload, signature: base64UrlEncode(new Uint8Array(sigBuf)) };
  } catch {
    const privKey = createPrivateKey({ key: jwk as Record<string, unknown>, format: 'jwk' });
    const sigBuf = nodeEd25519Sign(null, Buffer.from(signingInput), privKey);
    return { payload, signature: base64UrlEncode(new Uint8Array(sigBuf)) };
  }
}

async function parseBoundedJsonBody<T = Record<string, unknown>>(
  request: Request,
  maxBytes = MAX_JSON_BYTES
): Promise<{ ok: true; data: T } | { ok: false; status: 400 | 413; error: string; message: string }> {
  const contentLen = request.headers.get('content-length');
  if (contentLen && /^\d+$/.test(contentLen) && Number(contentLen) > maxBytes) {
    return { ok: false, status: 413, error: 'PAYLOAD_TOO_LARGE', message: `JSON payload exceeds ${maxBytes} bytes.` };
  }
  const rawText = await request.text();
  if (new TextEncoder().encode(rawText).byteLength > maxBytes) {
    return { ok: false, status: 413, error: 'PAYLOAD_TOO_LARGE', message: `JSON payload exceeds ${maxBytes} bytes.` };
  }
  try {
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, status: 400, error: 'INVALID_JSON', message: 'Expected JSON object.' };
    }
    return { ok: true, data: parsed as T };
  } catch {
    return { ok: false, status: 400, error: 'INVALID_JSON', message: 'Malformed JSON body.' };
  }
}

/**
 * Validates CORS origin strictly: loopback origins + explicitly configured ALLOWED_ORIGINS only.
 * NEVER returns wildcard Access-Control-Allow-Origin: *.
 */
export function resolveAllowedCorsOrigin(origin: string | null, allowedOriginsEnv?: string): string | null {
  if (!origin) return null;
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return null;
  }

  const isLoopback =
    (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
    (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]');
  if (isLoopback) {
    return parsed.origin;
  }

  const configured = (allowedOriginsEnv ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (configured.includes(parsed.origin)) {
    return parsed.origin;
  }
  return null;
}

function withCorsHeaders(headers: HeadersInit, origin: string | null, allowedOriginsEnv?: string): Headers {
  const out = new Headers(headers);
  const allowed = resolveAllowedCorsOrigin(origin, allowedOriginsEnv);
  if (allowed) {
    out.set('access-control-allow-origin', allowed);
    out.set('vary', 'Origin');
    out.set('access-control-allow-methods', 'GET, POST, OPTIONS');
    out.set('access-control-allow-headers', 'Content-Type');
  }
  return out;
}

/**
 * SQLite-backed Durable Object storing sanitized RUA summaries (with offline provider attribution),
 * DNS/TLS drift baselines, challenge nonces, and an atomic anti-replay transaction claim lock.
 */
export class DmarcStoreDO {
  private readonly sql: SqlStorage;
  private queue: Promise<void> = Promise.resolve();

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS rua_reports (
        report_id TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        org_name TEXT NOT NULL,
        policy TEXT NOT NULL,
        total_messages INTEGER NOT NULL,
        dmarc_pass INTEGER NOT NULL,
        dmarc_fail INTEGER NOT NULL,
        pass_rate REAL NOT NULL,
        suspicious_json TEXT NOT NULL,
        sources_json TEXT NOT NULL DEFAULT '[]',
        received_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS domain_snapshots (
        domain TEXT PRIMARY KEY,
        spf TEXT,
        dmarc TEXT,
        mx_json TEXT NOT NULL,
        tls_status TEXT NOT NULL DEFAULT 'ok',
        tls_detail TEXT NOT NULL DEFAULT '',
        checked_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS license_challenges (
        nonce TEXT PRIMARY KEY,
        tx_hash TEXT NOT NULL,
        tier TEXT NOT NULL,
        ts INTEGER NOT NULL,
        message TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS used_tx_claims (
        claim_key TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        payer TEXT NOT NULL,
        tier TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        paid_atomic TEXT NOT NULL,
        claimed_at INTEGER NOT NULL
      );
    `);
    try {
      this.sql.exec(`ALTER TABLE rua_reports ADD COLUMN sources_json TEXT NOT NULL DEFAULT '[]'`);
    } catch {
      // Column already present on fresh schemas.
    }
  }

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  async fetch(request: Request): Promise<Response> {
    return this.runExclusive(async () => {
      const url = new URL(request.url);

      if (request.method === 'POST' && url.pathname === '/rua') {
        const report = (await request.json()) as WorkerRuaSummary;
        this.sql.exec(
          `INSERT OR REPLACE INTO rua_reports
           (report_id, domain, org_name, policy, total_messages, dmarc_pass, dmarc_fail, pass_rate, suspicious_json, sources_json, received_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          report.reportId,
          report.domain,
          report.orgName,
          report.policy,
          report.totalMessages,
          report.dmarcPass,
          report.dmarcFail,
          report.passRate,
          JSON.stringify(report.suspiciousSources ?? []),
          JSON.stringify(report.sources ?? []),
          report.receivedAt
        );
        return Response.json({ stored: true, reportId: report.reportId });
      }

      if (request.method === 'GET' && url.pathname === '/summary') {
        const rawReports = this.sql
          .exec(`SELECT * FROM rua_reports ORDER BY received_at DESC LIMIT 50`)
          .toArray() as Array<Record<string, unknown>>;
        const reports = rawReports.map((row) => {
          let sources: WorkerRuaSource[] = [];
          try {
            sources = JSON.parse(String(row.sources_json ?? '[]')) as WorkerRuaSource[];
          } catch {
            sources = [];
          }
          const providerBreakdown: Record<string, number> = {};
          for (const s of sources) {
            const label = s.provider || 'Unknown / Unattributed';
            providerBreakdown[label] = (providerBreakdown[label] ?? 0) + (Number(s.totalCount) || 0);
          }
          return {
            ...row,
            sources,
            provider_breakdown: providerBreakdown
          };
        });
        const snapshots = this.sql
          .exec(`SELECT * FROM domain_snapshots ORDER BY domain ASC`)
          .toArray();
        return Response.json({ reports, snapshots });
      }

      if (request.method === 'POST' && url.pathname === '/snapshot') {
        const next = (await request.json()) as DohDnsSnapshot;
        const prevRows = this.sql
          .exec(`SELECT domain, spf, dmarc, mx_json, tls_status, tls_detail, checked_at FROM domain_snapshots WHERE domain = ?`, next.domain)
          .toArray();
        const prevRow = prevRows[0] as Record<string, unknown> | undefined;
        const prev: DohDnsSnapshot | null = prevRow
          ? {
              domain: String(prevRow.domain),
              spf: prevRow.spf === null ? null : String(prevRow.spf),
              dmarc: prevRow.dmarc === null ? null : String(prevRow.dmarc),
              mx: JSON.parse(String(prevRow.mx_json)) as string[],
              tlsStatus: prevRow.tls_status === 'error' ? 'error' : 'ok',
              tlsDetail: String(prevRow.tls_detail ?? ''),
              checkedAt: String(prevRow.checked_at)
            }
          : null;

        const diffs = diffDomainSnapshots(prev, next);
        this.sql.exec(
          `INSERT OR REPLACE INTO domain_snapshots (domain, spf, dmarc, mx_json, tls_status, tls_detail, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          next.domain,
          next.spf,
          next.dmarc,
          JSON.stringify(next.mx),
          next.tlsStatus,
          next.tlsDetail,
          next.checkedAt
        );
        return Response.json({ diffs, previous: prev, current: next });
      }

      if (request.method === 'POST' && url.pathname === '/challenge-create') {
        const ch = (await request.json()) as ChallengeRecord;
        this.sql.exec(
          `INSERT OR REPLACE INTO license_challenges (nonce, tx_hash, tier, ts, message) VALUES (?, ?, ?, ?, ?)`,
          ch.nonce,
          ch.txHash,
          ch.tier,
          ch.ts,
          ch.message
        );
        return Response.json({ ok: true });
      }

      if (request.method === 'POST' && url.pathname === '/challenge-get') {
        const body = (await request.json()) as { nonce?: string };
        const rows = this.sql
          .exec(`SELECT nonce, tx_hash, tier, ts, message FROM license_challenges WHERE nonce = ?`, body.nonce ?? '')
          .toArray() as Array<Record<string, unknown>>;
        if (rows.length === 0) {
          return Response.json({ found: false }, { status: 404 });
        }
        const row = rows[0]!;
        return Response.json({
          found: true,
          challenge: {
            nonce: String(row.nonce),
            txHash: String(row.tx_hash),
            tier: String(row.tier),
            ts: Number(row.ts),
            message: String(row.message)
          }
        });
      }

      if (request.method === 'POST' && url.pathname === '/challenge-delete') {
        const body = (await request.json()) as { nonce?: string };
        this.sql.exec(`DELETE FROM license_challenges WHERE nonce = ?`, body.nonce ?? '');
        return Response.json({ deleted: true });
      }

      if (request.method === 'POST' && url.pathname === '/tx-claim') {
        const body = (await request.json()) as {
          scope: string;
          payer: string;
          tier: CommercialTier;
          txHash: string;
          paidAtomic: string;
        };
        const claimKey = body.txHash.toLowerCase();
        const existing = this.sql
          .exec(`SELECT claim_key, scope, payer, tier FROM used_tx_claims WHERE claim_key = ?`, claimKey)
          .toArray() as Array<Record<string, unknown>>;
        if (existing.length > 0) {
          return Response.json(
            { locked: false, error: 'TX_ALREADY_CLAIMED', reason: 'Replay detected: Base USDC txHash already claimed' },
            { status: 409 }
          );
        }
        this.sql.exec(
          `INSERT INTO used_tx_claims (claim_key, scope, payer, tier, tx_hash, paid_atomic, claimed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          claimKey,
          body.scope,
          body.payer.toLowerCase(),
          body.tier,
          claimKey,
          body.paidAtomic,
          Date.now()
        );
        return Response.json({ locked: true });
      }

      return new Response('Not Found', { status: 404 });
    });
  }
}

/**
 * Zero-CDN, XSS-safe single-page dashboard HTML.
 * Uses strictly document.createElement + textContent and pure escaped-string Blob download
 * (zero innerHTML, zero outerHTML, zero insertAdjacentHTML, zero document.write, zero eval).
 */
export function renderDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DMARCZero Edge Dashboard</title>
  <style>
    :root { --bg: #0b1120; --card: #162033; --text: #f1f5f9; --muted: #94a3b8; --border: #2a3952; --ok: #10b981; --warn: #f59e0b; --err: #ef4444; --accent: #38bdf8; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }
    .wrap { max-width: 1020px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; margin-bottom: 18px; }
    h1 { margin: 0 0 6px 0; font-size: 1.5rem; }
    h2 { margin: 0 0 12px 0; font-size: 1.1rem; }
    .muted { color: var(--muted); font-size: 0.9rem; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); }
    code { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.85em; }
    form.lic-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 12px; }
    input, select, button { background: #0b1120; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-size: 0.88rem; }
    button { background: var(--accent); color: #0b1120; font-weight: 700; cursor: pointer; border: none; }
    button.secondary { background: #1e293b; color: var(--text); border: 1px solid var(--border); }
    #lic-result { margin-top: 10px; font-size: 0.88rem; white-space: pre-wrap; word-break: break-all; }
    footer { color: var(--muted); font-size: 0.82rem; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>DMARCZero Edge Dashboard</h1>
      <div class="muted">Self-Hosted Cloudflare Worker · Offline Mail-Provider Attribution · Zero RUF PII Ingestion</div>
    </div>
    <div class="card">
      <h2>Recent RUA Aggregate Reports &amp; White-Label Export</h2>
      <div class="row">
        <input id="wl-title" value="Client DMARC Security Audit" placeholder="White-label client report title" style="flex:1 1 260px;" />
        <button id="export-report-btn" type="button">Export White-Label Client HTML Report</button>
      </div>
      <div id="rua-status" class="muted">Loading...</div>
      <table>
        <thead><tr><th>Domain</th><th>Org</th><th>Providers</th><th>Total</th><th>Pass</th><th>Fail</th><th>Pass Rate</th></tr></thead>
        <tbody id="rua-body"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>Monitored DNS &amp; TLS Baselines</h2>
      <table>
        <thead><tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>TLS</th><th>Checked At</th></tr></thead>
        <tbody id="dns-body"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>Base USDC Commercial License Verification &amp; Voluntary Support</h2>
      <p class="muted">Solo (1 natural person): <strong>0 USDC</strong> forever (100% features unlocked) · Team (2–99): <strong>Founder Early-Bird 99 USDC</strong> · Enterprise (100+): <strong>Founder Early-Bird 499 USDC</strong></p>
      <p class="muted">Base Mainnet USDC (<code>eip155:8453</code>) Recipient / Voluntary Tip: <code>${APEXHIVE_BASE_USDC_RECIPIENT}</code> · Contact: <code>apexhive.hq@proton.me</code></p>
      <form id="lic-form" class="lic-form">
        <select id="lic-tier"><option value="team">Team (Founder Early-Bird 99 USDC)</option><option value="enterprise">Enterprise (Founder Early-Bird 499 USDC)</option></select>
        <input id="lic-holder" placeholder="Organization / Holder Name" required />
        <input id="lic-tx" placeholder="Base USDC Tx Hash 0x..." required />
        <input id="lic-nonce" placeholder="Challenge Nonce (or click Request Challenge)" />
        <input id="lic-sig" placeholder="Wallet Ownership Signature 0x... (optional if MetaMask connected)" />
        <button id="lic-challenge-btn" type="button" class="secondary">1. Request Challenge</button>
        <button type="submit">2. Verify On-Chain &amp; Issue Cert</button>
      </form>
      <div id="lic-result" class="muted"></div>
    </div>
    <footer>DMARCZero by ApexHive Labs · Base USDC EOA (EIP-191) &amp; Smart Wallet (ERC-1271 / EIP-6492) verifier at <code>POST /api/license/challenge</code> + <code>POST /api/license/verify</code></footer>
  </div>
  <script>
    (async function () {
      const statusEl = document.getElementById('rua-status');
      const ruaBody = document.getElementById('rua-body');
      const dnsBody = document.getElementById('dns-body');
      const exportBtn = document.getElementById('export-report-btn');
      const wlTitleInput = document.getElementById('wl-title');
      const licForm = document.getElementById('lic-form');
      const licChallengeBtn = document.getElementById('lic-challenge-btn');
      const licResult = document.getElementById('lic-result');
      let latestSummary = { reports: [], snapshots: [] };

      function escapeHtmlText(val) {
        return String(val === undefined || val === null ? '' : val)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function appendRow(tbody, cells) {
        const tr = document.createElement('tr');
        for (const val of cells) {
          const td = document.createElement('td');
          td.textContent = String(val ?? '-');
          tr.appendChild(td);
        }
        tbody.appendChild(tr);
      }

      function buildWhiteLabelReportHtml(title, summary) {
        const reports = Array.isArray(summary.reports) ? summary.reports : [];
        const snapshots = Array.isArray(summary.snapshots) ? summary.snapshots : [];
        const reportRows = reports.length > 0
          ? reports.map(function (r) {
              const provs = r.provider_breakdown ? Object.keys(r.provider_breakdown).join(', ') : '-';
              return '<tr><td>' + escapeHtmlText(r.domain) + '</td><td>' + escapeHtmlText(r.org_name) + '</td><td>' + escapeHtmlText(provs || '-') + '</td><td>' + escapeHtmlText(r.total_messages) + '</td><td>' + escapeHtmlText(r.dmarc_pass) + '</td><td>' + escapeHtmlText(r.dmarc_fail) + '</td><td>' + escapeHtmlText(r.pass_rate) + '%</td></tr>';
            }).join('')
          : '<tr><td colspan="7">No RUA reports stored yet.</td></tr>';
        const snapRows = snapshots.length > 0
          ? snapshots.map(function (s) {
              return '<tr><td>' + escapeHtmlText(s.domain) + '</td><td><code>' + escapeHtmlText(s.spf || '(none)') + '</code></td><td><code>' + escapeHtmlText(s.dmarc || '(none)') + '</code></td><td>' + escapeHtmlText(s.tls_status || 'ok') + '</td><td>' + escapeHtmlText(s.checked_at) + '</td></tr>';
            }).join('')
          : '<tr><td colspan="5">No DNS/TLS snapshots recorded yet.</td></tr>';

        return [
          '<!DOCTYPE html>',
          '<html lang="en"><head><meta charset="utf-8" />',
          '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\';" />',
          '<title>' + escapeHtmlText(title) + '</title>',
          '<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#f8fafc;padding:28px;margin:0}h1{margin:0 0 8px}table{width:100%;border-collapse:collapse;margin:12px 0 24px}th,td{text-align:left;padding:8px;border-bottom:1px solid #334155}</style>',
          '</head><body>',
          '<h1>' + escapeHtmlText(title) + '</h1>',
          '<p>Generated offline from DMARCZero Edge Dashboard at ' + escapeHtmlText(new Date().toISOString()) + ' (Zero-CDN Static Export)</p>',
          '<h2>DMARC Aggregate Summary</h2>',
          '<table><thead><tr><th>Domain</th><th>Org</th><th>Providers</th><th>Total</th><th>Pass</th><th>Fail</th><th>Pass Rate</th></tr></thead><tbody>' + reportRows + '</tbody></table>',
          '<h2>DNS &amp; TLS Baselines</h2>',
          '<table><thead><tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>TLS</th><th>Checked At</th></tr></thead><tbody>' + snapRows + '</tbody></table>',
          '</body></html>'
        ].join('\n');
      }

      exportBtn.addEventListener('click', function () {
        const title = (wlTitleInput.value || '').trim() || 'Client DMARC Security Audit';
        const htmlDoc = buildWhiteLabelReportHtml(title, latestSummary);
        const blob = new Blob([htmlDoc], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'dmarczero-client-report.html';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      });

      try {
        const resp = await fetch('/api/summary');
        const data = await resp.json();
        latestSummary = data;
        const reports = Array.isArray(data.reports) ? data.reports : [];
        const snapshots = Array.isArray(data.snapshots) ? data.snapshots : [];
        statusEl.textContent = reports.length + ' report(s) stored in SQLite Durable Object.';
        for (const r of reports) {
          const provText = r.provider_breakdown ? Object.entries(r.provider_breakdown).map(function (kv) { return kv[0] + ' (' + kv[1] + ')'; }).join(', ') : '-';
          appendRow(ruaBody, [r.domain, r.org_name, provText || '-', r.total_messages, r.dmarc_pass, r.dmarc_fail, r.pass_rate + '%']);
        }
        for (const s of snapshots) {
          appendRow(dnsBody, [s.domain, s.spf || '(none)', s.dmarc || '(none)', s.tls_status || 'ok', s.checked_at]);
        }
      } catch (err) {
        statusEl.textContent = 'Failed to load summary.';
      }

      licChallengeBtn.addEventListener('click', async function () {
        licResult.textContent = 'Requesting Base USDC challenge...';
        try {
          const resp = await fetch('/api/license/challenge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              tier: document.getElementById('lic-tier').value,
              txHash: document.getElementById('lic-tx').value.trim()
            })
          });
          const ch = await resp.json();
          if (!resp.ok || !ch.nonce) {
            licResult.textContent = 'Challenge failed: ' + (ch.message || ch.reason || ch.error || resp.status);
            return;
          }
          document.getElementById('lic-nonce').value = ch.nonce;
          if (window.ethereum && window.ethereum.request) {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            const sig = await window.ethereum.request({ method: 'personal_sign', params: [ch.message, accounts[0]] });
            document.getElementById('lic-sig').value = sig;
            licResult.textContent = 'Challenge signed via wallet. Click "2. Verify On-Chain & Issue Cert".';
          } else {
            licResult.textContent = 'Challenge nonce: ' + ch.nonce + '\\nSign message with payer wallet:\\n' + ch.message;
          }
        } catch (err) {
          licResult.textContent = 'Challenge error.';
        }
      });

      licForm.addEventListener('submit', async function (ev) {
        ev.preventDefault();
        licResult.textContent = 'Verifying on Base RPC...';
        try {
          const resp = await fetch('/api/license/verify', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              tier: document.getElementById('lic-tier').value,
              holder: document.getElementById('lic-holder').value,
              recipientAddress: '${APEXHIVE_BASE_USDC_RECIPIENT}',
              txHash: document.getElementById('lic-tx').value.trim(),
              nonce: document.getElementById('lic-nonce').value.trim(),
              signature: document.getElementById('lic-sig').value.trim()
            })
          });
          const out = await resp.json();
          licResult.textContent = out.valid
            ? 'Verified ' + out.tier.toUpperCase() + ' license for ' + out.holder + ':\\n' + JSON.stringify(out.certificate, null, 2)
            : 'Verification failed: ' + (out.message || out.reason || 'unknown error') + ' (Solo features remain 100% unlocked).';
        } catch (err) {
          licResult.textContent = 'Request failed.';
        }
      });
    })();
  </script>
</body>
</html>`;
}

export async function handleWorkerFetch(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const origin = request.headers.get('origin');
  const payTo = env.PAY_TO_EVM_ADDRESS || APEXHIVE_BASE_USDC_RECIPIENT;
  const baseUsdc = env.BASE_USDC_CONTRACT || BASE_USDC_CONTRACT;

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: withCorsHeaders({}, origin, env.ALLOWED_ORIGINS)
    });
  }

  if (request.method === 'GET' && url.pathname === '/api/health') {
    return new Response(
      JSON.stringify({
        status: 'ok',
        service: 'dmarczero-worker',
        version: '1.1.0',
        rufIngestion: 'rejected',
        featuresUnlocked: true,
        smartWalletSupport: ['EOA', 'ERC-1271', 'EIP-6492'],
        durableObjectLockBound: Boolean(env.DMARC_STORE)
      }),
      {
        status: 200,
        headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      }
    );
  }

  if (request.method === 'GET' && url.pathname === '/api/config') {
    return new Response(
      JSON.stringify({
        brand: env.BRAND_NAME || 'ApexHive Labs',
        productId: env.PRODUCT_ID || 'dmarczero',
        supportEmail: 'apexhive.hq@proton.me',
        chainId: Number(env.BASE_CHAIN_ID || '8453'),
        usdcContract: baseUsdc,
        payToEvmAddress: payTo,
        minConfirmations: Number(env.MIN_CONFIRMATIONS || '2'),
        smartWalletSupport: ['EOA', 'ERC-1271', 'EIP-6492'],
        licensePublicKeySpkiB64: env.LICENSE_SIGNING_PUBLIC_SPKI_B64 || null,
        tiers: {
          solo: { priceUsd: '0', featuresUnlocked: true },
          team: { priceAtomic: getTierPriceAtomic(env, 'team').toString(), priceUsd: '99.00', seats: 99 },
          enterprise: { priceAtomic: getTierPriceAtomic(env, 'enterprise').toString(), priceUsd: '499.00', seats: 1000 }
        }
      }),
      {
        status: 200,
        headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      }
    );
  }

  if (request.method === 'GET' && url.pathname === '/api/summary') {
    const id = env.DMARC_STORE.idFromName('global');
    const stub = env.DMARC_STORE.get(id);
    const resp = await stub.fetch('https://dmarc-store/summary');
    const body = await resp.text();
    return new Response(body, {
      status: resp.status,
      headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
    });
  }

  if (request.method === 'POST' && url.pathname === '/api/license/challenge') {
    const parsed = await parseBoundedJsonBody<{ txHash?: string; tier?: string }>(request);
    if (!parsed.ok) {
      return new Response(JSON.stringify({ valid: false, error: parsed.error, reason: parsed.message }), {
        status: parsed.status,
        headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      });
    }

    const txHash = (parsed.data.txHash ?? '').trim();
    const tier = parseTier(parsed.data.tier);
    if (!TX_HASH_RE.test(txHash)) {
      return new Response(
        JSON.stringify({ valid: false, error: 'INVALID_TX_HASH', reason: 'Expected 0x-prefixed 64-hex txHash.' }),
        { status: 400, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }
    if (!tier) {
      return new Response(
        JSON.stringify({ valid: false, error: 'INVALID_TIER', reason: 'Tier must be team or enterprise.' }),
        { status: 400, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const ttl = Math.max(60, Number(env.CHALLENGE_TTL_SECONDS || '300'));
    const nonce = randomHex(16);
    const ts = Math.floor(Date.now() / 1000);
    const message = buildChallengeMessage({
      brand: env.BRAND_NAME || 'ApexHive Labs',
      product: env.PRODUCT_ID || 'dmarczero',
      tier,
      txHash,
      nonce,
      ts
    });

    const id = env.DMARC_STORE.idFromName('global');
    const stub = env.DMARC_STORE.get(id);
    await stub.fetch('https://dmarc-store/challenge-create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce, txHash: txHash.toLowerCase(), tier, ts, message })
    });

    return new Response(
      JSON.stringify({ ok: true, nonce, ts, expiresInSeconds: ttl, message }),
      {
        status: 200,
        headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      }
    );
  }

  if (request.method === 'POST' && url.pathname === '/api/license/verify') {
    if (!env.LICENSE_SIGNING_PRIVATE_JWK || !env.LICENSE_SIGNING_PRIVATE_JWK.trim() || !env.DMARC_STORE) {
      return new Response(
        JSON.stringify({
          valid: false,
          featuresUnlocked: true,
          error: 'SERVER_MISCONFIGURED',
          reason: 'Missing LICENSE_SIGNING_PRIVATE_JWK or DMARC_STORE binding.'
        }),
        {
          status: 500,
          headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
        }
      );
    }

    const parsed = await parseBoundedJsonBody<Partial<WalletLicenseRequest>>(request);
    if (!parsed.ok) {
      return new Response(JSON.stringify({ valid: false, error: parsed.error, reason: parsed.message }), {
        status: parsed.status,
        headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      });
    }

    const body = parsed.data;
    const txHash = (body.txHash ?? '').trim();
    const nonce = (body.nonce ?? '').trim();
    const signature = (body.signature ?? '').trim();
    const tier = parseTier(body.tier);
    const holder = String(body.holder ?? 'Verified Organization').trim().slice(0, 120) || 'Verified Organization';

    if (body.recipientAddress && body.recipientAddress.toLowerCase() !== payTo.toLowerCase()) {
      return new Response(
        JSON.stringify({ valid: false, featuresUnlocked: true, error: 'INVALID_RECIPIENT', reason: `Recipient address must match ${payTo}` }),
        { status: 400, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    if (!TX_HASH_RE.test(txHash) || !nonce || nonce.length < 8 || !SIG_RE.test(signature)) {
      return new Response(
        JSON.stringify({
          valid: false,
          featuresUnlocked: true,
          error: 'INVALID_REQUEST',
          reason: 'Provide valid txHash, nonce (>=8 chars), and EIP-191/ERC-1271/EIP-6492 signature.'
        }),
        { status: 400, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }
    if (!tier) {
      return new Response(
        JSON.stringify({ valid: false, featuresUnlocked: true, error: 'INVALID_TIER', reason: 'Tier must be "team" or "enterprise".' }),
        { status: 400, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const txLower = txHash.toLowerCase();
    const id = env.DMARC_STORE.idFromName('global');
    const stub = env.DMARC_STORE.get(id);

    const chResp = await stub.fetch('https://dmarc-store/challenge-get', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce })
    });
    if (!chResp.ok) {
      return new Response(
        JSON.stringify({
          valid: false,
          featuresUnlocked: true,
          error: 'CHALLENGE_EXPIRED_OR_MISSING',
          reason: 'Challenge nonce missing, expired, or already consumed.'
        }),
        { status: 403, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const chData = (await chResp.json()) as { found: boolean; challenge: ChallengeRecord };
    const challenge = chData.challenge;
    const ttl = Math.max(60, Number(env.CHALLENGE_TTL_SECONDS || '300'));
    const nowSec = Math.floor(Date.now() / 1000);
    if (challenge.txHash !== txLower || challenge.tier !== tier || nowSec - challenge.ts > ttl) {
      await stub.fetch('https://dmarc-store/challenge-delete', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce })
      });
      return new Response(
        JSON.stringify({ valid: false, featuresUnlocked: true, error: 'CHALLENGE_MISMATCH_OR_EXPIRED', reason: 'Challenge mismatch or expired.' }),
        { status: 403, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const rpcUrls = getBaseRpcUrls(env);
    let receipt: RpcReceipt | null;
    let latestBlockHex: string;
    try {
      [receipt, latestBlockHex] = await Promise.all([
        rpcCallWithFailover<RpcReceipt | null>(rpcUrls, 'eth_getTransactionReceipt', [txLower]),
        rpcCallWithFailover<string>(rpcUrls, 'eth_blockNumber', [])
      ]);
    } catch (err) {
      return new Response(
        JSON.stringify({
          valid: false,
          featuresUnlocked: true,
          error: 'RPC_UNAVAILABLE',
          reason: err instanceof Error ? err.message : 'Base RPC error'
        }),
        { status: 502, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    if (!receipt || receipt.status !== '0x1') {
      return new Response(
        JSON.stringify({ valid: false, featuresUnlocked: true, error: 'TX_NOT_CONFIRMED', reason: 'Receipt missing or reverted on Base.' }),
        { status: 403, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const txBlock = parseStrictHexBigInt(receipt.blockNumber);
    const headBlock = parseStrictHexBigInt(latestBlockHex);
    if (txBlock === null || headBlock === null) {
      return new Response(
        JSON.stringify({ valid: false, featuresUnlocked: true, error: 'TX_NOT_CONFIRMED', reason: 'Malformed hex blockNumber from RPC.' }),
        { status: 403, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const minConf = Math.max(1, Number(env.MIN_CONFIRMATIONS || '2'));
    const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock) + 1 : 0;
    if (confirmations < minConf) {
      return new Response(
        JSON.stringify({ valid: false, featuresUnlocked: true, error: 'INSUFFICIENT_CONFIRMATIONS', reason: `Need >= ${minConf} Base confirmations.` }),
        { status: 403, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const requiredAmount = getTierPriceAtomic(env, tier);
    const payerTotals = sumBaseUsdcTransfers(receipt.logs, baseUsdc, payTo);
    const expectedSignerLower = body.signerAddress?.trim().toLowerCase();

    let matchedPayer: string | null = null;
    let paidAtomic = 0n;
    for (const [fromAddr, totalPaid] of payerTotals.entries()) {
      if (totalPaid < requiredAmount) continue;
      if (expectedSignerLower && expectedSignerLower !== fromAddr.toLowerCase()) continue;
      const sigOk = await verifySmartWalletOrEoaSignature({
        rpcUrls,
        address: fromAddr,
        message: challenge.message,
        signature
      });
      if (sigOk) {
        matchedPayer = fromAddr;
        paidAtomic = totalPaid;
        break;
      }
    }

    if (!matchedPayer) {
      return new Response(
        JSON.stringify({
          valid: false,
          featuresUnlocked: true,
          error: 'PAYMENT_OR_SIGNATURE_INVALID',
          reason: 'Base USDC transfer amount or wallet signature (EIP-191 / ERC-1271 / EIP-6492) verification failed.'
        }),
        { status: 403, headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS) }
      );
    }

    const lockResp = await stub.fetch('https://dmarc-store/tx-claim', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        scope: SCOPE_DMARCZERO,
        payer: matchedPayer,
        tier,
        txHash: txLower,
        paidAtomic: paidAtomic.toString()
      })
    });

    if (lockResp.status === 409) {
      return new Response(
        JSON.stringify({
          valid: false,
          featuresUnlocked: true,
          error: 'TX_ALREADY_CLAIMED',
          reason: 'Replay detected: this Base USDC transaction has already been verified.'
        }),
        {
          status: 409,
          headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
        }
      );
    }

    await stub.fetch('https://dmarc-store/challenge-delete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce })
    });

    const certificate = await signCommercialCertificate(env, {
      product: 'dmarczero',
      tier,
      holder,
      seats: tier === 'enterprise' ? 1000 : 99,
      issuedAt: new Date().toISOString(),
      txHash: txLower
    });

    return new Response(
      JSON.stringify({
        valid: true,
        ok: true,
        tier,
        holder,
        payer: matchedPayer,
        txHash: txLower,
        paidAtomic: paidAtomic.toString(),
        recipientAddress: payTo,
        certificate,
        featuresUnlocked: true
      }),
      {
        status: 200,
        headers: withCorsHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      }
    );
  }

  if (request.method === 'GET' && url.pathname === '/') {
    return new Response(renderDashboardHtml(), {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self';",
        'x-content-type-options': 'nosniff'
      }
    });
  }

  return new Response('Not Found', { status: 404 });
}

export async function handleWorkerEmail(
  rawMime: string,
  env: Env,
  fetchFn: typeof fetch = fetch
): Promise<{ accepted: boolean; stored: number; rejectedReason?: string }> {
  const parsed = await parseIncomingRuaMime(rawMime);
  if (!parsed.accepted) {
    return { accepted: false, stored: 0, rejectedReason: parsed.rejectedReason };
  }

  const id = env.DMARC_STORE.idFromName('global');
  const stub = env.DMARC_STORE.get(id);
  const threshold = Number.parseFloat(env.PASS_RATE_ALERT_THRESHOLD ?? '90') || 90;

  for (const rep of parsed.reports) {
    await stub.fetch('https://dmarc-store/rua', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(rep)
    });

    if (env.ALERT_WEBHOOK_URL && rep.totalMessages > 0 && rep.passRate < threshold) {
      const extraHosts = (env.WEBHOOK_ALLOWLIST ?? '').split(',').filter(Boolean);
      await sendSafeWebhookAlert(
        env.ALERT_WEBHOOK_URL,
        `[DMARCZero Alert] ${rep.domain} DMARC pass rate dropped to ${rep.passRate}% (${rep.dmarcFail}/${rep.totalMessages} failed, org: ${rep.orgName})`,
        { extraAllowedHosts: extraHosts, fetchFn }
      );
    }
  }

  return { accepted: true, stored: parsed.reports.length };
}

export async function handleWorkerScheduled(
  env: Env,
  fetchFn: typeof fetch = fetch
): Promise<{ checked: number; alertsSent: number }> {
  const domains = (env.MONITORED_DOMAINS ?? '')
    .split(',')
    .map((d) => d.trim())
    .filter(Boolean);

  const id = env.DMARC_STORE.idFromName('global');
  const stub = env.DMARC_STORE.get(id);
  const extraHosts = (env.WEBHOOK_ALLOWLIST ?? '').split(',').filter(Boolean);

  let alertsSent = 0;
  for (const domain of domains) {
    const snap = await fetchDomainDnsSnapshot(domain, fetchFn);
    const resp = await stub.fetch('https://dmarc-store/snapshot', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(snap)
    });
    const data = (await resp.json()) as { diffs: string[] };
    if (data.diffs.length > 0 && env.ALERT_WEBHOOK_URL) {
      const alertRes = await sendSafeWebhookAlert(
        env.ALERT_WEBHOOK_URL,
        `[DMARCZero Drift] ${domain}:\n${data.diffs.map((d) => `- ${d}`).join('\n')}`,
        { extraAllowedHosts: extraHosts, fetchFn }
      );
      if (alertRes.sent) alertsSent += 1;
    }
  }

  return { checked: domains.length, alertsSent };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleWorkerFetch(request, env);
  },
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    const rawText = await new Response(message.raw).text();
    const res = await handleWorkerEmail(rawText, env);
    if (!res.accepted && res.rejectedReason?.toLowerCase().includes('ruf')) {
      message.setReject('DMARCZero rejects RUF forensic reports to protect email privacy');
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await handleWorkerScheduled(env);
  }
};
