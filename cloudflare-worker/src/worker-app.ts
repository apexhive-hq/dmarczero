import { timingSafeEqual } from 'node:crypto';
import {
  parseIncomingRuaMime,
  type WorkerRuaSource,
  type WorkerRuaSummary
} from './email-handler.js';
import {
  diffDomainSnapshots,
  fetchDomainDnsSnapshot,
  sendSafeWebhookAlert,
  validateMonitoredDomain,
  type DohDnsSnapshot
} from './cron-monitor.js';

export const WORKER_VERSION = '1.0.0';
export const MAX_RATE_LIMIT_ROWS = 10_000;
export const MAX_RUA_REPORT_ROWS = 10_000;
const SESSION_COOKIE_NAME = 'dmarczero_session';
const SESSION_TTL_SECONDS = 3600;
const LOGIN_RATE_LIMIT_MAX = 5;
const LOGIN_RATE_LIMIT_WINDOW_SEC = 60;
const MAX_JSON_BYTES = 16 * 1024;

export interface Env {
  DMARC_STORE: DurableObjectNamespace;
  DASHBOARD_ADMIN_TOKEN?: string;
  MONITORED_DOMAINS?: string;
  ALLOW_UNLISTED_DOMAINS?: string;
  ALLOWED_ORIGINS?: string;
  ALERT_WEBHOOK_URL?: string;
  TELEGRAM_CHAT_ID?: string;
  WEBHOOK_ALLOWLIST?: string;
  PASS_RATE_ALERT_THRESHOLD?: string;
}

async function sha256Bytes(input: string): Promise<Uint8Array> {
  const encoded = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(digest);
}

/**
 * Constant-time token check using fixed-length SHA-256 digests so token length never leaks.
 */
async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [da, db] = await Promise.all([sha256Bytes(a), sha256Bytes(b)]);
  return timingSafeEqual(da, db);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(input: string): Uint8Array | null {
  try {
    const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (input.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
}

async function deriveSessionHmacKey(adminToken: string): Promise<CryptoKey> {
  const keyMaterial = await sha256Bytes(`dmarczero-session-v1:${adminToken}`);
  return crypto.subtle.importKey(
    'raw',
    keyMaterial as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function createSessionCookiePayload(
  adminToken: string,
  nowSec = Math.floor(Date.now() / 1000)
): Promise<{ cookieValue: string; nonce: string; expiresAt: number }> {
  const exp = nowSec + SESSION_TTL_SECONDS;
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = base64UrlEncode(nonceBytes);
  const payload = `${exp}.${nonce}`;
  const key = await deriveSessionHmacKey(adminToken);
  const sig = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload) as unknown as BufferSource)
  );
  return {
    cookieValue: `${payload}.${base64UrlEncode(sig)}`,
    nonce,
    expiresAt: exp
  };
}

function parseCookieHeader(cookieHeader: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const name = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (name) cookies.set(name, val);
  }
  return cookies;
}

async function verifySessionCookieValue(
  cookieHeader: string | null,
  adminToken: string,
  nowSec = Math.floor(Date.now() / 1000)
): Promise<{ valid: boolean; nonce?: string }> {
  const raw = parseCookieHeader(cookieHeader).get(SESSION_COOKIE_NAME);
  if (!raw) return { valid: false };
  const parts = raw.split('.');
  if (parts.length !== 3) return { valid: false };
  const [expStr, nonce, sigB64] = parts;
  if (!expStr || !nonce || !sigB64 || !/^\d+$/.test(expStr)) return { valid: false };
  const exp = Number.parseInt(expStr, 10);
  if (!Number.isFinite(exp) || exp < nowSec) return { valid: false };

  const sigBytes = base64UrlDecode(sigB64);
  if (!sigBytes) return { valid: false };

  const payload = `${expStr}.${nonce}`;
  const key = await deriveSessionHmacKey(adminToken);
  const verified = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes as unknown as BufferSource,
    new TextEncoder().encode(payload) as unknown as BufferSource
  );
  return verified ? { valid: true, nonce } : { valid: false };
}

function getClientKey(request: Request): string {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown'
  );
}

async function callRateCheck(
  stub: DurableObjectStub,
  clientKey: string,
  nowSec: number,
  mode: 'check' | 'hit' | 'reset'
): Promise<{ allowed: boolean; retryAfter?: number }> {
  const resp = await stub.fetch('https://dmarc-store/auth/rate-check', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      clientKey,
      nowSec,
      maxAttempts: LOGIN_RATE_LIMIT_MAX,
      windowSec: LOGIN_RATE_LIMIT_WINDOW_SEC,
      mode
    })
  });
  return (await resp.json()) as { allowed: boolean; retryAfter?: number };
}

async function authenticateAdminRequest(
  request: Request,
  env: Env
): Promise<{ ok: true } | { ok: false; status: 503 | 401 | 429; retryAfter?: number; error: string; message: string }> {
  const adminToken = (env.DASHBOARD_ADMIN_TOKEN ?? '').trim();
  if (!adminToken) {
    return {
      ok: false,
      status: 503,
      error: 'ADMIN_AUTH_UNCONFIGURED',
      message: 'DASHBOARD_ADMIN_TOKEN is not configured; private routes are disabled (fail-closed).'
    };
  }

  const id = env.DMARC_STORE.idFromName('global');
  const stub = env.DMARC_STORE.get(id);
  const nowSec = Math.floor(Date.now() / 1000);

  const authHeader = request.headers.get('authorization');
  if (authHeader) {
    const clientKey = getClientKey(request);
    const rate = await callRateCheck(stub, clientKey, nowSec, 'check');
    if (!rate.allowed) {
      return {
        ok: false,
        status: 429,
        retryAfter: rate.retryAfter ?? LOGIN_RATE_LIMIT_WINDOW_SEC,
        error: 'RATE_LIMITED',
        message: 'Too many authentication attempts; please try again later.'
      };
    }

    const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (m?.[1] && (await constantTimeEqual(m[1].trim(), adminToken))) {
      await callRateCheck(stub, clientKey, nowSec, 'reset');
      return { ok: true };
    }

    await callRateCheck(stub, clientKey, nowSec, 'hit');
    return {
      ok: false,
      status: 401,
      error: 'UNAUTHORIZED',
      message: 'Invalid Bearer token.'
    };
  }

  const cookieCheck = await verifySessionCookieValue(request.headers.get('cookie'), adminToken, nowSec);
  if (cookieCheck.valid && cookieCheck.nonce) {
    const checkResp = await stub.fetch('https://dmarc-store/auth/session-check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce: cookieCheck.nonce, nowSec })
    });
    if (checkResp.ok) {
      const data = (await checkResp.json()) as { active?: boolean };
      if (data.active) {
        return { ok: true };
      }
    }
  }

  return {
    ok: false,
    status: 401,
    error: 'UNAUTHORIZED',
    message: 'Admin authentication required.'
  };
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
 * Validates CORS origin strictly against configured ALLOWED_ORIGINS only.
 * Never allows wildcard "*" and defaults to same-origin only when unconfigured.
 */
export function resolveAllowedCorsOrigin(origin: string | null, allowedOriginsEnv?: string): string | null {
  if (!origin) return null;
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return null;
  }

  const configured = (allowedOriginsEnv ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => Boolean(s) && s !== '*');

  if (configured.includes(parsed.origin)) {
    return parsed.origin;
  }
  return null;
}

function withSecurityHeaders(headers: HeadersInit, isHtml = false): Headers {
  const out = new Headers(headers);
  out.set(
    'content-security-policy',
    isHtml
      ? "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
      : "default-src 'none'; frame-ancestors 'none'; object-src 'none'"
  );
  out.set('x-frame-options', 'DENY');
  out.set('x-content-type-options', 'nosniff');
  out.set('referrer-policy', 'no-referrer');
  out.set('cache-control', 'no-store');
  return out;
}

function withCorsAndSecurityHeaders(
  headers: HeadersInit,
  origin: string | null,
  allowedOriginsEnv?: string,
  isHtml = false
): Headers {
  const out = withSecurityHeaders(headers, isHtml);
  const allowed = resolveAllowedCorsOrigin(origin, allowedOriginsEnv);
  if (allowed) {
    out.set('access-control-allow-origin', allowed);
    out.set('vary', 'Origin');
    out.set('access-control-allow-methods', 'GET, POST, OPTIONS');
    out.set('access-control-allow-headers', 'Content-Type, Authorization');
    out.set('access-control-allow-credentials', 'true');
  }
  return out;
}

/**
 * SQLite-backed Durable Object storing sanitized RUA aggregate summaries
 * (keyed safely on (domain, org_name, report_id)), DNS/TLS baselines,
 * active admin session nonces, and login rate-limit counters.
 */
export class DmarcStoreDO {
  private readonly sql: SqlStorage;
  private queue: Promise<void> = Promise.resolve();

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS rua_reports (
        domain TEXT NOT NULL,
        org_name TEXT NOT NULL,
        report_id TEXT NOT NULL,
        policy TEXT NOT NULL,
        total_messages INTEGER NOT NULL,
        dmarc_pass INTEGER NOT NULL,
        dmarc_fail INTEGER NOT NULL,
        pass_rate REAL NOT NULL,
        suspicious_json TEXT NOT NULL,
        sources_json TEXT NOT NULL DEFAULT '[]',
        received_at TEXT NOT NULL,
        PRIMARY KEY (domain, org_name, report_id)
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
      CREATE TABLE IF NOT EXISTS auth_sessions (
        nonce TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS login_rate_limits (
        client_key TEXT PRIMARY KEY,
        attempts INTEGER NOT NULL,
        window_start INTEGER NOT NULL
      );
    `);
    try {
      this.sql.exec(`ALTER TABLE rua_reports ADD COLUMN sources_json TEXT NOT NULL DEFAULT '[]'`);
    } catch {
      // Column already present on fresh schemas.
    }

    // Migrate legacy single-column report_id PK table if upgrading an existing DO
    const schemaRows = this.sql
      .exec(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'rua_reports'`)
      .toArray() as Array<{ sql?: string }>;
    const createSql = String(schemaRows[0]?.sql ?? '');
    if (/report_id\s+TEXT\s+PRIMARY\s+KEY/i.test(createSql)) {
      this.sql.exec(`
        CREATE TABLE rua_reports_v2 (
          domain TEXT NOT NULL,
          org_name TEXT NOT NULL,
          report_id TEXT NOT NULL,
          policy TEXT NOT NULL,
          total_messages INTEGER NOT NULL,
          dmarc_pass INTEGER NOT NULL,
          dmarc_fail INTEGER NOT NULL,
          pass_rate REAL NOT NULL,
          suspicious_json TEXT NOT NULL,
          sources_json TEXT NOT NULL DEFAULT '[]',
          received_at TEXT NOT NULL,
          PRIMARY KEY (domain, org_name, report_id)
        );
        INSERT OR IGNORE INTO rua_reports_v2 (domain, org_name, report_id, policy, total_messages, dmarc_pass, dmarc_fail, pass_rate, suspicious_json, sources_json, received_at)
        SELECT domain, org_name, report_id, policy, total_messages, dmarc_pass, dmarc_fail, pass_rate, suspicious_json, sources_json, received_at FROM rua_reports;
        DROP TABLE rua_reports;
        ALTER TABLE rua_reports_v2 RENAME TO rua_reports;
      `);
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
        const normDomain = String(report.domain ?? '').trim().toLowerCase().replace(/\.+$/, '');
        const normOrg = String(report.orgName ?? '').trim().toLowerCase();
        const normReportId = String(report.reportId ?? '').trim();
        if (!normDomain || !normOrg || !normReportId) {
          return Response.json({ stored: false, inserted: false, error: 'Missing domain, orgName, or reportId' }, { status: 400 });
        }

        const existing = this.sql
          .exec(
            `SELECT 1 FROM rua_reports WHERE domain = ? AND org_name = ? AND report_id = ?`,
            normDomain,
            normOrg,
            normReportId
          )
          .toArray();
        if (existing.length > 0) {
          this.sql.exec(
            `INSERT INTO rua_reports
             (domain, org_name, report_id, policy, total_messages, dmarc_pass, dmarc_fail, pass_rate, suspicious_json, sources_json, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(domain, org_name, report_id) DO NOTHING`,
            normDomain,
            normOrg,
            normReportId,
            report.policy,
            report.totalMessages,
            report.dmarcPass,
            report.dmarcFail,
            report.passRate,
            JSON.stringify(report.suspiciousSources ?? []),
            JSON.stringify(report.sources ?? []),
            report.receivedAt
          );
          return Response.json({ stored: true, inserted: false, domain: normDomain, orgName: normOrg, reportId: normReportId });
        }

        const countRows = this.sql
          .exec(`SELECT COUNT(*) AS cnt FROM rua_reports`)
          .toArray() as Array<{ cnt: number }>;
        const currentCount = Number(countRows[0]?.cnt ?? 0);
        if (currentCount >= MAX_RUA_REPORT_ROWS) {
          const evictCount = currentCount - MAX_RUA_REPORT_ROWS + 1;
          this.sql.exec(
            `DELETE FROM rua_reports WHERE rowid IN (
              SELECT rowid FROM rua_reports ORDER BY received_at ASC, rowid ASC LIMIT ?
            )`,
            evictCount
          );
        }

        this.sql.exec(
          `INSERT INTO rua_reports
           (domain, org_name, report_id, policy, total_messages, dmarc_pass, dmarc_fail, pass_rate, suspicious_json, sources_json, received_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(domain, org_name, report_id) DO NOTHING`,
          normDomain,
          normOrg,
          normReportId,
          report.policy,
          report.totalMessages,
          report.dmarcPass,
          report.dmarcFail,
          report.passRate,
          JSON.stringify(report.suspiciousSources ?? []),
          JSON.stringify(report.sources ?? []),
          report.receivedAt
        );
        return Response.json({ stored: true, inserted: true, domain: normDomain, orgName: normOrg, reportId: normReportId });
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

      if (request.method === 'POST' && url.pathname === '/auth/rate-check') {
        const body = (await request.json()) as {
          clientKey?: string;
          nowSec?: number;
          maxAttempts?: number;
          windowSec?: number;
          mode?: 'check' | 'hit' | 'reset';
        };
        const clientKey = String(body.clientKey ?? 'unknown').slice(0, 128);
        const nowSec = Number(body.nowSec ?? Math.floor(Date.now() / 1000));
        const maxAttempts = Math.max(1, Number(body.maxAttempts ?? LOGIN_RATE_LIMIT_MAX));
        const windowSec = Math.max(1, Number(body.windowSec ?? LOGIN_RATE_LIMIT_WINDOW_SEC));
        const mode = body.mode;

        if (mode === 'reset') {
          this.sql.exec(`DELETE FROM login_rate_limits WHERE client_key = ?`, clientKey);
          return Response.json({ allowed: true });
        }

        this.sql.exec(`DELETE FROM login_rate_limits WHERE window_start <= ?`, nowSec - windowSec);
        const rows = this.sql
          .exec(`SELECT attempts, window_start FROM login_rate_limits WHERE client_key = ?`, clientKey)
          .toArray() as Array<{ attempts: number; window_start: number }>;
        const existing = rows[0];

        if (mode === 'check') {
          if (existing && existing.attempts >= maxAttempts) {
            const retryAfter = Math.max(1, existing.window_start + windowSec - nowSec);
            return Response.json({ allowed: false, retryAfter });
          }
          return Response.json({ allowed: true });
        }

        if (!existing) {
          const countRows = this.sql
            .exec(`SELECT COUNT(*) AS cnt FROM login_rate_limits`)
            .toArray() as Array<{ cnt: number }>;
          const currentCount = Number(countRows[0]?.cnt ?? 0);
          if (currentCount >= MAX_RATE_LIMIT_ROWS) {
            const evictCount = currentCount - MAX_RATE_LIMIT_ROWS + 1;
            this.sql.exec(
              `DELETE FROM login_rate_limits WHERE client_key IN (
                SELECT client_key FROM login_rate_limits ORDER BY window_start ASC, rowid ASC LIMIT ?
              )`,
              evictCount
            );
          }
          this.sql.exec(
            `INSERT INTO login_rate_limits (client_key, attempts, window_start) VALUES (?, ?, ?)`,
            clientKey,
            1,
            nowSec
          );
          return Response.json({ allowed: true });
        }

        if (existing.attempts >= maxAttempts) {
          const retryAfter = Math.max(1, existing.window_start + windowSec - nowSec);
          return Response.json({ allowed: false, retryAfter });
        }

        this.sql.exec(
          `UPDATE login_rate_limits SET attempts = attempts + 1 WHERE client_key = ?`,
          clientKey
        );
        return Response.json({ allowed: true });
      }

      if (request.method === 'POST' && url.pathname === '/auth/session-create') {
        const body = (await request.json()) as { nonce?: string; expiresAt?: number; nowSec?: number };
        const nonce = String(body.nonce ?? '');
        const expiresAt = Number(body.expiresAt ?? 0);
        const nowSec = Number(body.nowSec ?? Math.floor(Date.now() / 1000));
        if (!nonce || !Number.isFinite(expiresAt)) {
          return Response.json({ ok: false }, { status: 400 });
        }
        this.sql.exec(`DELETE FROM auth_sessions WHERE expires_at < ?`, nowSec);
        this.sql.exec(
          `INSERT OR REPLACE INTO auth_sessions (nonce, expires_at) VALUES (?, ?)`,
          nonce,
          expiresAt
        );
        return Response.json({ ok: true });
      }

      if (request.method === 'POST' && url.pathname === '/auth/session-check') {
        const body = (await request.json()) as { nonce?: string; nowSec?: number };
        const nonce = String(body.nonce ?? '');
        const nowSec = Number(body.nowSec ?? Math.floor(Date.now() / 1000));
        if (!nonce) {
          return Response.json({ active: false });
        }
        const rows = this.sql
          .exec(`SELECT nonce FROM auth_sessions WHERE nonce = ? AND expires_at >= ?`, nonce, nowSec)
          .toArray();
        return Response.json({ active: rows.length > 0 });
      }

      if (request.method === 'POST' && url.pathname === '/auth/session-revoke') {
        const body = (await request.json()) as { nonce?: string };
        const nonce = String(body.nonce ?? '');
        if (nonce) {
          this.sql.exec(`DELETE FROM auth_sessions WHERE nonce = ?`, nonce);
        }
        return Response.json({ revoked: true });
      }

      return new Response('Not Found', { status: 404 });
    });
  }
}

export function renderLoginHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DMARCZero Admin Sign In</title>
  <style>
    body { margin: 0; font-family: system-ui, -apple-system, sans-serif; background: #0b1120; color: #f1f5f9; display: grid; place-items: center; min-height: 100vh; padding: 20px; }
    .card { width: 100%; max-width: 400px; background: #162033; border: 1px solid #2a3952; border-radius: 10px; padding: 22px; }
    h1 { margin: 0 0 8px 0; font-size: 1.25rem; }
    p { margin: 0 0 14px 0; color: #94a3b8; font-size: 0.9rem; }
    input, button { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 6px; font-size: 0.92rem; }
    input { background: #0b1120; color: #f1f5f9; border: 1px solid #2a3952; margin-bottom: 10px; }
    button { background: #38bdf8; color: #0b1120; font-weight: 700; border: none; cursor: pointer; }
    #login-err { margin-top: 10px; color: #f87171; font-size: 0.86rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>DMARCZero Edge Dashboard</h1>
    <p>Enter your admin token to view RUA aggregate summaries and DNS/TLS baselines.</p>
    <form id="login-form">
      <input id="admin-token" type="password" placeholder="Admin Token" autocomplete="current-password" required />
      <button type="submit">Sign In</button>
    </form>
    <div id="login-err"></div>
  </div>
  <script>
    (function () {
      const form = document.getElementById('login-form');
      const tokenEl = document.getElementById('admin-token');
      const errEl = document.getElementById('login-err');
      form.addEventListener('submit', async function (ev) {
        ev.preventDefault();
        errEl.textContent = '';
        try {
          const resp = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ token: tokenEl.value })
          });
          if (resp.ok) {
            window.location.reload();
          } else {
            const data = await resp.json().catch(function () { return {}; });
            errEl.textContent = data.message || 'Invalid admin token.';
          }
        } catch (_err) {
          errEl.textContent = 'Authentication request failed.';
        }
      });
    })();
  </script>
</body>
</html>`;
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
    .header-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
    h1 { margin: 0 0 6px 0; font-size: 1.5rem; }
    h2 { margin: 0 0 12px 0; font-size: 1.1rem; }
    .muted { color: var(--muted); font-size: 0.9rem; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); }
    code { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.85em; }
    input, button { background: #0b1120; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-size: 0.88rem; }
    button { background: var(--accent); color: #0b1120; font-weight: 700; cursor: pointer; border: none; }
    button.secondary { background: #1e293b; color: var(--text); border: 1px solid var(--border); }
    footer { color: var(--muted); font-size: 0.82rem; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="header-row">
        <div>
          <h1>DMARCZero Edge Dashboard</h1>
          <div class="muted">Self-Hosted Cloudflare Worker · Offline Mail-Provider Attribution · Strictly RUA (No RUF)</div>
        </div>
        <button id="logout-btn" type="button" class="secondary">Sign Out</button>
      </div>
    </div>
    <div class="card">
      <h2>Recent RUA Aggregate Reports &amp; White-Label Export</h2>
      <div class="row">
        <input id="wl-title" value="DMARC Security Audit" placeholder="White-label report title" style="flex:1 1 220px;" />
        <input id="wl-footer" value="" placeholder="Optional white-label footer" style="flex:1 1 220px;" />
        <button id="export-report-btn" type="button">Export White-Label HTML Report</button>
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
    <footer>DMARCZero v${WORKER_VERSION} · MIT Open Source · Self-Hosted Cloudflare Worker</footer>
  </div>
  <script>
    (async function () {
      const statusEl = document.getElementById('rua-status');
      const ruaBody = document.getElementById('rua-body');
      const dnsBody = document.getElementById('dns-body');
      const exportBtn = document.getElementById('export-report-btn');
      const logoutBtn = document.getElementById('logout-btn');
      const wlTitleInput = document.getElementById('wl-title');
      const wlFooterInput = document.getElementById('wl-footer');
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

      function buildWhiteLabelReportHtml(title, footer, summary) {
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
        const footerHtml = footer ? '<footer><p>' + escapeHtmlText(footer) + '</p></footer>' : '';

        return [
          '<!DOCTYPE html>',
          '<html lang="en"><head><meta charset="utf-8" />',
          '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\';" />',
          '<title>' + escapeHtmlText(title) + '</title>',
          '<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#f8fafc;padding:28px;margin:0}h1{margin:0 0 8px}table{width:100%;border-collapse:collapse;margin:12px 0 24px}th,td{text-align:left;padding:8px;border-bottom:1px solid #334155}footer{margin-top:24px;color:#94a3b8;font-size:0.85rem}</style>',
          '</head><body>',
          '<h1>' + escapeHtmlText(title) + '</h1>',
          '<p>Generated at ' + escapeHtmlText(new Date().toISOString()) + ' (Zero-CDN Static Export)</p>',
          '<h2>DMARC Aggregate Summary</h2>',
          '<table><thead><tr><th>Domain</th><th>Org</th><th>Providers</th><th>Total</th><th>Pass</th><th>Fail</th><th>Pass Rate</th></tr></thead><tbody>' + reportRows + '</tbody></table>',
          '<h2>DNS &amp; TLS Baselines</h2>',
          '<table><thead><tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>TLS</th><th>Checked At</th></tr></thead><tbody>' + snapRows + '</tbody></table>',
          footerHtml,
          '</body></html>'
        ].join('\n');
      }

      exportBtn.addEventListener('click', function () {
        const title = (wlTitleInput.value || '').trim() || 'DMARC Security Audit';
        const footer = (wlFooterInput.value || '').trim();
        const htmlDoc = buildWhiteLabelReportHtml(title, footer, latestSummary);
        const blob = new Blob([htmlDoc], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'dmarc-report.html';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      });

      logoutBtn.addEventListener('click', async function () {
        await fetch('/api/auth/logout', { method: 'POST' });
        window.location.reload();
      });

      try {
        const resp = await fetch('/api/summary');
        if (!resp.ok) {
          statusEl.textContent = 'Unauthorized or failed to load summary.';
          return;
        }
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
      } catch (_err) {
        statusEl.textContent = 'Failed to load summary.';
      }
    })();
  </script>
</body>
</html>`;
}

export async function handleWorkerFetch(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const origin = request.headers.get('origin');

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: withCorsAndSecurityHeaders({}, origin, env.ALLOWED_ORIGINS)
    });
  }

  if (request.method === 'GET' && url.pathname === '/api/health') {
    return new Response(
      JSON.stringify({
        ok: true,
        service: 'dmarczero-worker',
        version: WORKER_VERSION
      }),
      {
        status: 200,
        headers: withCorsAndSecurityHeaders(
          { 'content-type': 'application/json; charset=utf-8' },
          origin,
          env.ALLOWED_ORIGINS
        )
      }
    );
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/login') {
    const adminToken = (env.DASHBOARD_ADMIN_TOKEN ?? '').trim();
    if (!adminToken) {
      return new Response(
        JSON.stringify({ ok: false, error: 'ADMIN_AUTH_UNCONFIGURED', message: 'DASHBOARD_ADMIN_TOKEN is not configured.' }),
        {
          status: 503,
          headers: withCorsAndSecurityHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
        }
      );
    }

    const clientKey = getClientKey(request);
    const nowSec = Math.floor(Date.now() / 1000);
    const id = env.DMARC_STORE.idFromName('global');
    const stub = env.DMARC_STORE.get(id);
    const rateData = await callRateCheck(stub, clientKey, nowSec, 'check');
    if (!rateData.allowed) {
      return new Response(
        JSON.stringify({
          ok: false,
          error: 'RATE_LIMITED',
          message: 'Too many login attempts; please try again later.'
        }),
        {
          status: 429,
          headers: withCorsAndSecurityHeaders(
            {
              'content-type': 'application/json; charset=utf-8',
              'retry-after': String(rateData.retryAfter ?? LOGIN_RATE_LIMIT_WINDOW_SEC)
            },
            origin,
            env.ALLOWED_ORIGINS
          )
        }
      );
    }

    const parsed = await parseBoundedJsonBody<{ token?: string }>(request);
    if (!parsed.ok) {
      await callRateCheck(stub, clientKey, nowSec, 'hit');
      return new Response(JSON.stringify({ ok: false, error: parsed.error, message: parsed.message }), {
        status: parsed.status,
        headers: withCorsAndSecurityHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      });
    }

    const provided = typeof parsed.data.token === 'string' ? parsed.data.token.trim() : '';
    if (!provided || !(await constantTimeEqual(provided, adminToken))) {
      await callRateCheck(stub, clientKey, nowSec, 'hit');
      return new Response(JSON.stringify({ ok: false, error: 'UNAUTHORIZED', message: 'Invalid admin token.' }), {
        status: 401,
        headers: withCorsAndSecurityHeaders({ 'content-type': 'application/json; charset=utf-8' }, origin, env.ALLOWED_ORIGINS)
      });
    }

    await callRateCheck(stub, clientKey, nowSec, 'reset');
    const session = await createSessionCookiePayload(adminToken, nowSec);
    await stub.fetch('https://dmarc-store/auth/session-create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce: session.nonce, expiresAt: session.expiresAt, nowSec })
    });

    const secureAttr = url.protocol === 'https:' ? '; Secure' : '';
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: withCorsAndSecurityHeaders(
        {
          'content-type': 'application/json; charset=utf-8',
          'set-cookie': `${SESSION_COOKIE_NAME}=${session.cookieValue}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secureAttr}`
        },
        origin,
        env.ALLOWED_ORIGINS
      )
    });
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
    const adminToken = (env.DASHBOARD_ADMIN_TOKEN ?? '').trim();
    if (adminToken) {
      const cookieCheck = await verifySessionCookieValue(request.headers.get('cookie'), adminToken);
      if (cookieCheck.valid && cookieCheck.nonce) {
        const id = env.DMARC_STORE.idFromName('global');
        const stub = env.DMARC_STORE.get(id);
        await stub.fetch('https://dmarc-store/auth/session-revoke', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ nonce: cookieCheck.nonce })
        });
      }
    }

    const secureAttr = url.protocol === 'https:' ? '; Secure' : '';
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: withCorsAndSecurityHeaders(
        {
          'content-type': 'application/json; charset=utf-8',
          'set-cookie': `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secureAttr}`
        },
        origin,
        env.ALLOWED_ORIGINS
      )
    });
  }

  if (request.method === 'GET' && url.pathname === '/api/summary') {
    const auth = await authenticateAdminRequest(request, env);
    if (!auth.ok) {
      const headers = withCorsAndSecurityHeaders(
        {
          'content-type': 'application/json; charset=utf-8',
          ...(auth.status === 401 ? { 'www-authenticate': 'Bearer' } : {}),
          ...(auth.status === 429 ? { 'retry-after': String(auth.retryAfter ?? LOGIN_RATE_LIMIT_WINDOW_SEC) } : {})
        },
        origin,
        env.ALLOWED_ORIGINS
      );
      return new Response(JSON.stringify({ ok: false, error: auth.error, message: auth.message }), {
        status: auth.status,
        headers
      });
    }

    const id = env.DMARC_STORE.idFromName('global');
    const stub = env.DMARC_STORE.get(id);
    const resp = await stub.fetch('https://dmarc-store/summary');
    const body = await resp.text();
    return new Response(body, {
      status: resp.status,
      headers: withCorsAndSecurityHeaders(
        { 'content-type': 'application/json; charset=utf-8' },
        origin,
        env.ALLOWED_ORIGINS
      )
    });
  }

  if (request.method === 'GET' && url.pathname === '/') {
    const auth = await authenticateAdminRequest(request, env);
    if (!auth.ok) {
      if (auth.status === 503) {
        return new Response('Service Unavailable: DASHBOARD_ADMIN_TOKEN is not configured.', {
          status: 503,
          headers: withSecurityHeaders({ 'content-type': 'text/plain; charset=utf-8' })
        });
      }
      if (auth.status === 429) {
        return new Response('Too Many Requests: Please retry later.', {
          status: 429,
          headers: withSecurityHeaders({
            'content-type': 'text/plain; charset=utf-8',
            'retry-after': String(auth.retryAfter ?? LOGIN_RATE_LIMIT_WINDOW_SEC)
          })
        });
      }
      return new Response(renderLoginHtml(), {
        status: 401,
        headers: withSecurityHeaders(
          {
            'content-type': 'text/html; charset=utf-8',
            'www-authenticate': 'Bearer'
          },
          true
        )
      });
    }

    return new Response(renderDashboardHtml(), {
      status: 200,
      headers: withSecurityHeaders({ 'content-type': 'text/html; charset=utf-8' }, true)
    });
  }

  return new Response('Not Found', {
    status: 404,
    headers: withSecurityHeaders({ 'content-type': 'text/plain; charset=utf-8' })
  });
}

function parseConfiguredMonitoredDomains(raw?: string): string[] {
  const validDomains: string[] = [];
  for (const entry of (raw ?? '').split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const check = validateMonitoredDomain(trimmed);
    if (check.valid && check.domain) {
      validDomains.push(check.domain);
    }
  }
  return validDomains;
}

export async function handleWorkerEmail(
  rawMime: string,
  env: Env,
  fetchFn: typeof fetch = fetch
): Promise<{ accepted: boolean; stored: number; rejectedReason?: string }> {
  const allowUnlisted = (env.ALLOW_UNLISTED_DOMAINS ?? '').trim().toLowerCase() === 'true';
  const allowedDomains = new Set(parseConfiguredMonitoredDomains(env.MONITORED_DOMAINS));

  if (!allowUnlisted && allowedDomains.size === 0) {
    return {
      accepted: false,
      stored: 0,
      rejectedReason: 'MONITORED_DOMAINS is not configured (fail-closed; configure MONITORED_DOMAINS or set ALLOW_UNLISTED_DOMAINS="true")'
    };
  }

  const parsed = await parseIncomingRuaMime(rawMime);
  if (!parsed.accepted) {
    return { accepted: false, stored: 0, rejectedReason: parsed.rejectedReason };
  }

  if (!allowUnlisted) {
    for (const rep of parsed.reports) {
      const repDomain = rep.domain.trim().toLowerCase().replace(/\.+$/, '');
      if (!allowedDomains.has(repDomain)) {
        return {
          accepted: false,
          stored: 0,
          rejectedReason: `Unmonitored RUA domain rejected: ${rep.domain}`
        };
      }
    }
  }

  const id = env.DMARC_STORE.idFromName('global');
  const stub = env.DMARC_STORE.get(id);
  const parsedThreshold = Number.parseFloat(env.PASS_RATE_ALERT_THRESHOLD ?? '90');
  const threshold = Number.isFinite(parsedThreshold) ? parsedThreshold : 90;

  let insertedCount = 0;
  for (const rep of parsed.reports) {
    const storeResp = await stub.fetch('https://dmarc-store/rua', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(rep)
    });
    const storeData = (await storeResp.json()) as { inserted?: boolean };
    if (storeData.inserted) {
      insertedCount += 1;
      if (env.ALERT_WEBHOOK_URL && rep.totalMessages > 0 && rep.passRate < threshold) {
        const extraHosts = (env.WEBHOOK_ALLOWLIST ?? '').split(',').filter(Boolean);
        await sendSafeWebhookAlert(
          env.ALERT_WEBHOOK_URL,
          `[DMARCZero Alert] ${rep.domain} DMARC pass rate dropped to ${rep.passRate}% (${rep.dmarcFail}/${rep.totalMessages} failed, org: ${rep.orgName})`,
          { extraAllowedHosts: extraHosts, telegramChatId: env.TELEGRAM_CHAT_ID, fetchFn }
        );
      }
    }
  }

  return { accepted: true, stored: insertedCount };
}

export async function handleWorkerScheduled(
  env: Env,
  fetchFn: typeof fetch = fetch
): Promise<{ checked: number; alertsSent: number; skippedInvalid: string[] }> {
  const validDomains: string[] = [];
  const skippedInvalid: string[] = [];

  for (const raw of (env.MONITORED_DOMAINS ?? '').split(',')) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const check = validateMonitoredDomain(trimmed);
    if (check.valid && check.domain) {
      validDomains.push(check.domain);
    } else {
      skippedInvalid.push(trimmed);
    }
  }

  const id = env.DMARC_STORE.idFromName('global');
  const stub = env.DMARC_STORE.get(id);
  const extraHosts = (env.WEBHOOK_ALLOWLIST ?? '').split(',').filter(Boolean);

  let alertsSent = 0;
  for (const domain of validDomains) {
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
        { extraAllowedHosts: extraHosts, telegramChatId: env.TELEGRAM_CHAT_ID, fetchFn }
      );
      if (alertRes.sent) alertsSent += 1;
    }
  }

  return { checked: validDomains.length, alertsSent, skippedInvalid };
}
