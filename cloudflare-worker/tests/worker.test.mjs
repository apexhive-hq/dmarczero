import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { rm as rmAsync } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import {
  DmarcStoreDO,
  handleWorkerEmail,
  handleWorkerFetch,
  handleWorkerScheduled,
  MAX_RATE_LIMIT_ROWS,
  renderDashboardHtml,
  WORKER_VERSION
} from '../dist/worker-app.js';
import {
  MAX_MIME_PARTS,
  MAX_UNCOMPRESSED_BYTES,
  parseIncomingRuaMime,
  readBoundedEmailStream
} from '../dist/email-handler.js';
import {
  sendSafeWebhookAlert,
  validateMonitoredDomain,
  validateWebhookUrl
} from '../dist/cron-monitor.js';

const execFileAsync = promisify(execFile);
const WORKER_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)));

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function buildMultiEntryZip(entries) {
  const localParts = [];
  const cdParts = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.filename, 'utf8');
    const raw = Buffer.from(entry.data);
    const method = entry.method ?? 8; // 0 = STORE, 8 = DEFLATE
    const compressed = method === 0 ? raw : zlib.deflateRawSync(raw);
    const crc = crc32(raw);

    const localHeader = Buffer.alloc(30 + nameBuf.length);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(raw.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);
    nameBuf.copy(localHeader, 30);

    const cdHeader = Buffer.alloc(46 + nameBuf.length);
    cdHeader.writeUInt32LE(0x02014b50, 0);
    cdHeader.writeUInt16LE(20, 4);
    cdHeader.writeUInt16LE(20, 6);
    cdHeader.writeUInt16LE(0, 8);
    cdHeader.writeUInt16LE(method, 10);
    cdHeader.writeUInt32LE(crc, 16);
    cdHeader.writeUInt32LE(compressed.length, 20);
    cdHeader.writeUInt32LE(raw.length, 24);
    cdHeader.writeUInt16LE(nameBuf.length, 28);
    cdHeader.writeUInt32LE(offset, 42);
    nameBuf.copy(cdHeader, 46);

    localParts.push(localHeader, compressed);
    cdParts.push(cdHeader);
    offset += localHeader.length + compressed.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

function createSqliteDoEnv(overrides = {}) {
  const db = new DatabaseSync(':memory:');
  const fakeSqlStorage = {
    exec(query, ...params) {
      const trimmed = query.trim();
      if (/^SELECT/i.test(trimmed)) {
        const stmt = db.prepare(trimmed);
        return { toArray: () => stmt.all(...params) };
      }
      if (params.length === 0 && trimmed.includes(';')) {
        db.exec(trimmed);
        return { toArray: () => [] };
      }
      const stmt = db.prepare(trimmed);
      stmt.run(...params);
      return { toArray: () => [] };
    }
  };

  const doInstance = new DmarcStoreDO({ storage: { sql: fakeSqlStorage } });
  const env = {
    DMARC_STORE: {
      idFromName: (name) => name,
      get: () => ({
        fetch: (input, init) => {
          const req = input instanceof Request ? input : new Request(input, init);
          return doInstance.fetch(req);
        }
      })
    },
    ...overrides
  };
  return { env, db };
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
  });
}

async function waitForHealth(url, proc, getLogs, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error(`wrangler dev exited early (${proc.exitCode}):\n${getLogs()}`);
    }
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      // poll until ready
    }
    await new Promise((r) => setTimeout(r, 350));
  }
  throw new Error(`Timed out waiting for ${url}:\n${getLogs()}`);
}

function makeSampleRuaXml(domain = 'worker.example', reportId = 'w-rep-1', passCount = 25, failCount = 0) {
  return `<feedback><report_metadata><org_name>google.com</org_name><report_id>${reportId}</report_id><date_range><begin>100</begin><end>200</end></date_range></report_metadata><policy_published><domain>${domain}</domain><p>reject</p></policy_published>${
    passCount > 0
      ? `<record><row><source_ip>209.85.220.41</source_ip><count>${passCount}</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>${domain}</header_from></identifiers></record>`
      : ''
  }${
    failCount > 0
      ? `<record><row><source_ip>198.51.100.77</source_ip><count>${failCount}</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>${domain}</header_from></identifiers></record>`
      : ''
  }</feedback>`;
}

describe('cloudflare-worker: Email RUA ingestion, ZIP/MIME safety, and RUF privacy firewall', () => {
  it('ingests MIME email with gzipped RUA XML into SQLite DO with provider attribution via authenticated /api/summary', async () => {
    const token = 'super-secret-admin-token-123';
    const { env } = createSqliteDoEnv({
      DASHBOARD_ADMIN_TOKEN: token,
      MONITORED_DOMAINS: 'worker.example'
    });
    const gzB64 = zlib.gzipSync(Buffer.from(makeSampleRuaXml(), 'utf8')).toString('base64');
    const rawMime = [
      'From: noreply@google.com',
      'To: dmarc@worker.example',
      'Subject: Report domain: worker.example Submitter: google.com',
      'Content-Type: multipart/mixed; boundary="BOUND42"',
      '',
      '--BOUND42',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Attached is your DMARC aggregate report.',
      '--BOUND42',
      'Content-Type: application/gzip; name="google.com!worker.example!100!200.xml.gz"',
      'Content-Disposition: attachment; filename="google.com!worker.example!100!200.xml.gz"',
      'Content-Transfer-Encoding: base64',
      '',
      gzB64,
      '--BOUND42--'
    ].join('\r\n');

    const ingest = await handleWorkerEmail(rawMime, env);
    assert.equal(ingest.accepted, true);
    assert.equal(ingest.stored, 1);

    const summaryResp = await handleWorkerFetch(
      new Request('https://worker.local/api/summary', {
        headers: { authorization: `Bearer ${token}` }
      }),
      env
    );
    assert.equal(summaryResp.status, 200);
    const summary = await summaryResp.json();
    assert.equal(summary.reports.length, 1);
    assert.equal(summary.reports[0].domain, 'worker.example');
    assert.equal(summary.reports[0].total_messages, 25);
    assert.equal(summary.reports[0].provider_breakdown['Google Workspace'], 25);
    assert.equal(summary.reports[0].sources[0].providerId, 'google-workspace');
  });

  it('supports nested multipart/* MIME parts and large >256KB gzipped RUA without DecompressionStream deadlock', async () => {
    const bigRecords = Array.from({ length: 1200 }, (_, idx) =>
      `<record><row><source_ip>209.85.220.${(idx % 200) + 1}</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>nested.example</header_from></identifiers></record>`
    ).join('');
    const bigXml = `<feedback><report_metadata><org_name>google.com</org_name><report_id>big-1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published><domain>nested.example</domain><p>reject</p></policy_published>${bigRecords}</feedback>`;
    assert.ok(Buffer.byteLength(bigXml) > 256 * 1024);

    const gzB64 = zlib.gzipSync(Buffer.from(bigXml, 'utf8')).toString('base64');
    const nestedMime = [
      'From: noreply@google.com',
      'Content-Type: multipart/mixed; boundary="OUTER"',
      '',
      '--OUTER',
      'Content-Type: multipart/related; boundary="INNER"',
      '',
      '--INNER',
      'Content-Type: text/plain',
      '',
      'Nested wrapper body',
      '--INNER',
      'Content-Type: application/gzip',
      'Content-Disposition: attachment; filename="nested.xml.gz"',
      'Content-Transfer-Encoding: base64',
      '',
      gzB64,
      '--INNER--',
      '--OUTER--'
    ].join('\r\n');

    const res = await parseIncomingRuaMime(nestedMime);
    assert.equal(res.accepted, true);
    assert.equal(res.reports.length, 1);
    assert.equal(res.reports[0].totalMessages, 1200);
  });

  it('inspects ALL ZIP entries, handles 0-byte STORE safely, and enforces cumulative caps across attachments & raw stream', async () => {
    const zipWithHiddenRuf = buildMultiEntryZip([
      { filename: 'valid-rua.xml', method: 0, data: Buffer.from(makeSampleRuaXml(), 'utf8') },
      { filename: 'hidden!ruf!2.xml', method: 8, data: Buffer.from('<feedback/>', 'utf8') }
    ]);
    const mimeRufZip = [
      'Content-Type: multipart/mixed; boundary="Z1"',
      '',
      '--Z1',
      'Content-Type: application/zip',
      'Content-Disposition: attachment; filename="bundle.zip"',
      'Content-Transfer-Encoding: base64',
      '',
      zipWithHiddenRuf.toString('base64'),
      '--Z1--'
    ].join('\r\n');

    const rufRes = await parseIncomingRuaMime(mimeRufZip);
    assert.equal(rufRes.accepted, false);
    assert.ok(rufRes.rejectedReason?.toLowerCase().includes('ruf'));

    // 0-byte STORE entry followed by valid RUA XML entry must NOT slice entry #1 to EOF
    const zeroStoreZip = buildMultiEntryZip([
      { filename: 'empty.txt', method: 0, data: Buffer.alloc(0) },
      { filename: 'valid.xml', method: 0, data: Buffer.from(makeSampleRuaXml('worker.example', 'z0'), 'utf8') }
    ]);
    const mimeZeroStore = [
      'Content-Type: multipart/mixed; boundary="Z0"',
      '',
      '--Z0',
      'Content-Type: application/zip',
      'Content-Disposition: attachment; filename="z0.zip"',
      'Content-Transfer-Encoding: base64',
      '',
      zeroStoreZip.toString('base64'),
      '--Z0--'
    ].join('\r\n');
    const z0Res = await parseIncomingRuaMime(mimeZeroStore);
    assert.equal(z0Res.accepted, true);
    assert.equal(z0Res.reports.length, 1);
    assert.equal(z0Res.reports[0].reportId, 'z0');

    // Enforce size cap on STORE (method=0) entries
    const storeZip = buildMultiEntryZip([
      { filename: 'big-store.xml', method: 0, data: Buffer.from('A'.repeat(2048), 'utf8') }
    ]);
    const mimeStoreZip = [
      'Content-Type: multipart/mixed; boundary="Z2"',
      '',
      '--Z2',
      'Content-Type: application/zip',
      'Content-Disposition: attachment; filename="store.zip"',
      'Content-Transfer-Encoding: base64',
      '',
      storeZip.toString('base64'),
      '--Z2--'
    ].join('\r\n');
    const storeCapRes = await parseIncomingRuaMime(mimeStoreZip, 1024);
    assert.equal(storeCapRes.accepted, false);
    assert.ok(storeCapRes.rejectedReason?.includes('exceeds'));

    // Cumulative cap across multiple attachments (two 700-byte XML parts > 1024 cumulative budget)
    const xmlPartA = makeSampleRuaXml('worker.example', 'a'.repeat(500));
    const xmlPartB = makeSampleRuaXml('worker.example', 'b'.repeat(500));
    assert.ok(xmlPartA.length > 600 && xmlPartA.length < 1024);
    const twoPartsMime = [
      'Content-Type: multipart/mixed; boundary="Z2B"',
      '',
      '--Z2B',
      'Content-Type: application/xml',
      'Content-Disposition: attachment; filename="a.xml"',
      '',
      xmlPartA,
      '--Z2B',
      'Content-Type: application/xml',
      'Content-Disposition: attachment; filename="b.xml"',
      '',
      xmlPartB,
      '--Z2B--'
    ].join('\r\n');
    const cumRes = await parseIncomingRuaMime(twoPartsMime, 1024);
    assert.equal(cumRes.accepted, false);
    assert.ok(cumRes.rejectedReason?.includes('exceeds'));

    // Enforce size cap BEFORE Base64 decoding
    const oversizedB64 = Buffer.alloc(MAX_UNCOMPRESSED_BYTES + 1024, 65).toString('base64');
    const oversizedMime = [
      'Content-Type: multipart/mixed; boundary="Z3"',
      '',
      '--Z3',
      'Content-Type: application/xml',
      'Content-Disposition: attachment; filename="huge.xml"',
      'Content-Transfer-Encoding: base64',
      '',
      oversizedB64,
      '--Z3--'
    ].join('\r\n');
    const b64CapRes = await parseIncomingRuaMime(oversizedMime);
    assert.equal(b64CapRes.accepted, false);
    assert.ok(b64CapRes.rejectedReason?.includes('exceeds'));

    // readBoundedEmailStream rejects oversized email stream before loading full message
    const bigStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(600));
        controller.enqueue(new Uint8Array(600));
        controller.close();
      }
    });
    await assert.rejects(
      () => readBoundedEmailStream(bigStream, undefined, 1024),
      (err) => err instanceof Error && err.message.includes('exceeds')
    );

    // Caps MIME parts at MAX_MIME_PARTS (64) against nested-multipart DoS
    const manyParts = Array.from({ length: MAX_MIME_PARTS + 2 }, (_, idx) => [
      '--MANY',
      'Content-Type: text/plain',
      '',
      `part ${idx}`
    ].join('\r\n')).join('\r\n');
    const manyMime = `Content-Type: multipart/mixed; boundary="MANY"\r\n\r\n${manyParts}\r\n--MANY--`;
    const manyRes = await parseIncomingRuaMime(manyMime);
    assert.equal(manyRes.accepted, false);
    assert.ok(manyRes.rejectedReason?.includes('MIME parts count exceeded'));
  });

  it('fails closed when MONITORED_DOMAINS is empty, enforces domain isolation & composite PK, and handles PASS_RATE_ALERT_THRESHOLD="0"', async () => {
    const wrapXmlMime = (xml) => [
      'Content-Type: multipart/mixed; boundary="M1"',
      '',
      '--M1',
      'Content-Type: application/xml',
      'Content-Disposition: attachment; filename="r.xml"',
      '',
      xml,
      '--M1--'
    ].join('\r\n');

    // 1. Fail-closed when MONITORED_DOMAINS="" and ALLOW_UNLISTED_DOMAINS is not "true"
    const { env: closedEnv } = createSqliteDoEnv({ MONITORED_DOMAINS: '' });
    const closedRes = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('any.example', 'rep-1')), closedEnv);
    assert.equal(closedRes.accepted, false);
    assert.equal(closedRes.stored, 0);
    assert.ok(closedRes.rejectedReason?.includes('MONITORED_DOMAINS'));

    // 2. Explicit ALLOW_UNLISTED_DOMAINS="true" allows ingestion when configured
    const { env: openEnv } = createSqliteDoEnv({ ALLOW_UNLISTED_DOMAINS: 'true' });
    const openRes = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('any.example', 'rep-open')), openEnv);
    assert.equal(openRes.accepted, true);
    assert.equal(openRes.stored, 1);

    // 3. Monitored domains + composite PK isolation (same report_id across domains does NOT overwrite)
    const token = 'admin-tok';
    const { env } = createSqliteDoEnv({
      DASHBOARD_ADMIN_TOKEN: token,
      MONITORED_DOMAINS: 'allowed.example, second.example',
      PASS_RATE_ALERT_THRESHOLD: '0',
      ALERT_WEBHOOK_URL: 'https://hooks.slack.com/services/T/B/X'
    });

    const unmonitoredRes = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('evil.example', 'rep-evil')), env);
    assert.equal(unmonitoredRes.accepted, false);
    assert.equal(unmonitoredRes.stored, 0);
    assert.ok(unmonitoredRes.rejectedReason?.includes('Unmonitored'));

    let alertsTriggered = 0;
    const mockFetch = async () => {
      alertsTriggered += 1;
      return new Response('ok', { status: 200 });
    };
    const r1 = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('allowed.example', 'shared-id', 0, 10)), env, mockFetch);
    const r2 = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('second.example', 'shared-id', 15, 0)), env, mockFetch);
    assert.equal(r1.accepted, true);
    assert.equal(r1.stored, 1);
    assert.equal(r2.accepted, true);
    assert.equal(r2.stored, 1);
    assert.equal(alertsTriggered, 0);

    // Duplicate RUA (same domain, org_name, report_id) uses DO NOTHING and does NOT re-trigger webhook alerts
    const { env: dupEnv } = createSqliteDoEnv({
      MONITORED_DOMAINS: 'dup.example',
      PASS_RATE_ALERT_THRESHOLD: '90',
      ALERT_WEBHOOK_URL: 'https://hooks.slack.com/services/T/B/X'
    });
    let dupAlerts = 0;
    const dupFetch = async () => {
      dupAlerts += 1;
      return new Response('ok', { status: 200 });
    };
    const d1 = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('dup.example', 'dup-1', 0, 10)), dupEnv, dupFetch);
    const d2 = await handleWorkerEmail(wrapXmlMime(makeSampleRuaXml('dup.example', 'dup-1', 0, 10)), dupEnv, dupFetch);
    assert.equal(d1.stored, 1);
    assert.equal(d2.stored, 0);
    assert.equal(dupAlerts, 1);

    const summary = await (
      await handleWorkerFetch(
        new Request('https://worker.local/api/summary', { headers: { authorization: `Bearer ${token}` } }),
        env
      )
    ).json();
    assert.equal(summary.reports.length, 2);
  });

  it('strictly rejects RUF forensic emails without storing PII', async () => {
    const { env } = createSqliteDoEnv({ ALLOW_UNLISTED_DOMAINS: 'true' });
    const rufMime = [
      'From: postmaster@isp.example',
      'To: dmarc@worker.example',
      'Content-Type: message/feedback-report',
      '',
      'Feedback-Type: auth-failure',
      'Original-Mail-From: private-user@worker.example',
      'Arrival-Date: Thu, 26 Nov 2026 00:00:00 +0000'
    ].join('\r\n');

    const ingest = await handleWorkerEmail(rufMime, env);
    assert.equal(ingest.accepted, false);
    assert.equal(ingest.stored, 0);
    assert.ok(ingest.rejectedReason?.toLowerCase().includes('ruf'));
  });
});

describe('cloudflare-worker: SSRF-protected webhook relay, Telegram chat_id & Cron FQDN sentinel', () => {
  it('blocks SSRF targets (HTTP, loopback, IPv4, IPv6 ::ffff:/::, metadata, non-allowlisted hosts, 3xx redirects)', async () => {
    assert.equal(validateWebhookUrl('http://discord.com/api/webhooks/1/a').valid, false);
    assert.equal(validateWebhookUrl('https://127.0.0.1/hook').valid, false);
    assert.equal(validateWebhookUrl('https://169.254.169.254/latest/meta-data/').valid, false);
    assert.equal(validateWebhookUrl('https://10.0.0.5/internal').valid, false);
    assert.equal(validateWebhookUrl('https://localhost/hook').valid, false);
    assert.equal(validateWebhookUrl('https://[::1]/hook').valid, false);
    assert.equal(validateWebhookUrl('https://[::]/hook').valid, false);
    assert.equal(validateWebhookUrl('https://[::ffff:127.0.0.1]/hook').valid, false);
    assert.equal(validateWebhookUrl('https://evil.example.com/steal').valid, false);
    assert.equal(validateWebhookUrl('https://user:pass@discord.com/api/webhooks/1/a').valid, false);

    assert.equal(validateWebhookUrl('https://discord.com/api/webhooks/123/abc').valid, true);
    assert.equal(validateWebhookUrl('https://hooks.slack.com/services/T/B/X').valid, true);
    assert.equal(validateWebhookUrl('https://api.telegram.org/bot123/sendMessage').valid, true);

    const tgMissing = await sendSafeWebhookAlert('https://api.telegram.org/bot123/sendMessage', 'hello');
    assert.equal(tgMissing.sent, false);
    assert.ok(tgMissing.reason?.includes('TELEGRAM_CHAT_ID'));

    let tgBody = null;
    let tgSignal = null;
    const tgOk = await sendSafeWebhookAlert('https://api.telegram.org/bot123/sendMessage', 'drift alert', {
      telegramChatId: '-100999888',
      fetchFn: async (_url, init) => {
        tgBody = JSON.parse(init.body);
        tgSignal = init.signal;
        return new Response('ok', { status: 200 });
      }
    });
    assert.equal(tgOk.sent, true);
    assert.equal(tgBody.chat_id, '-100999888');
    assert.equal(tgBody.text, 'drift alert');
    assert.ok(tgSignal instanceof AbortSignal);

    let seenRedirectMode = '';
    const redirectMockFetch = async (_url, init) => {
      seenRedirectMode = init?.redirect ?? '';
      return new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } });
    };
    const res = await sendSafeWebhookAlert('https://discord.com/api/webhooks/123/abc', 'test', {
      fetchFn: redirectMockFetch
    });
    assert.equal(seenRedirectMode, 'manual');
    assert.equal(res.sent, false);
    assert.ok(res.reason?.includes('3xx'));
  });

  it('validates MONITORED_DOMAINS as strict FQDNs and detects DNS drift on second cron run', async () => {
    assert.equal(validateMonitoredDomain('localhost').valid, false);
    assert.equal(validateMonitoredDomain('127.0.0.1').valid, false);
    assert.equal(validateMonitoredDomain('[::ffff:127.0.0.1]').valid, false);
    assert.equal(validateMonitoredDomain('169.254.169.254').valid, false);
    assert.equal(validateMonitoredDomain('evil.com/path').valid, false);
    assert.equal(validateMonitoredDomain('sentinel.example').valid, true);

    const { env } = createSqliteDoEnv({
      MONITORED_DOMAINS: 'sentinel.example, 127.0.0.1, localhost',
      ALERT_WEBHOOK_URL: 'https://hooks.slack.com/services/T00/B00/XYZ'
    });

    let currentSpf = 'v=spf1 ip4:203.0.113.1 -all';
    const alerts = [];
    const fetchedUrls = [];

    const mockFetch = async (url, init) => {
      const u = String(url);
      fetchedUrls.push(u);
      assert.ok(init?.signal instanceof AbortSignal);
      if (u.startsWith('https://hooks.slack.com/')) {
        alerts.push(JSON.parse(init.body));
        return new Response('ok', { status: 200 });
      }
      if (u.includes('type=TXT') && u.includes('_dmarc.')) {
        return Response.json({ Answer: [{ data: '"v=DMARC1; p=reject"' }] });
      }
      if (u.includes('type=TXT')) {
        return Response.json({ Answer: [{ data: `"${currentSpf}"` }] });
      }
      if (u.includes('type=MX')) {
        return Response.json({ Answer: [{ data: '10 mx.sentinel.example.' }] });
      }
      return Response.json({ Answer: [] });
    };

    const run1 = await handleWorkerScheduled(env, mockFetch);
    assert.equal(run1.checked, 1);
    assert.deepEqual(run1.skippedInvalid, ['127.0.0.1', 'localhost']);
    assert.equal(run1.alertsSent, 0);
    assert.ok(!fetchedUrls.some((u) => u.includes('127.0.0.1') || u.includes('localhost')));

    currentSpf = 'v=spf1 ip4:203.0.113.1 +all';
    const run2 = await handleWorkerScheduled(env, mockFetch);
    assert.equal(run2.alertsSent, 1);
    assert.equal(alerts.length, 1);
    assert.ok(alerts[0].text.includes('SPF changed'));
  });
});

describe('cloudflare-worker: Fail-Closed Admin Auth, Rate Limit, Session Revocation, Strict CORS & Zero-XSS Dashboard', () => {
  it('fails closed 503 when unset, enforces Bearer + DO-backed HttpOnly HMAC session revocation on logout, and rate-limits login (429)', async () => {
    const { env: unconfiguredEnv } = createSqliteDoEnv();
    const r503Api = await handleWorkerFetch(new Request('https://worker.local/api/summary'), unconfiguredEnv);
    assert.equal(r503Api.status, 503);
    const r503Dash = await handleWorkerFetch(new Request('https://worker.local/'), unconfiguredEnv);
    assert.equal(r503Dash.status, 503);

    const healthResp = await handleWorkerFetch(new Request('https://worker.local/api/health'), unconfiguredEnv);
    assert.equal(healthResp.status, 200);
    const healthJson = await healthResp.json();
    assert.deepEqual(healthJson, { ok: true, service: 'dmarczero-worker', version: WORKER_VERSION });
    assert.equal(healthResp.headers.get('x-frame-options'), 'DENY');
    assert.equal(healthResp.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(healthResp.headers.get('referrer-policy'), 'no-referrer');

    const { env } = createSqliteDoEnv({ DASHBOARD_ADMIN_TOKEN: 'correct-horse-battery-staple' });

    const r401Api = await handleWorkerFetch(new Request('https://worker.local/api/summary'), env);
    assert.equal(r401Api.status, 401);
    const r401Dash = await handleWorkerFetch(new Request('https://worker.local/'), env);
    assert.equal(r401Dash.status, 401);
    const r401Html = await r401Dash.text();
    assert.ok(!r401Html.includes('Export White-Label HTML Report'));

    const rBadBearer = await handleWorkerFetch(
      new Request('https://worker.local/api/summary', { headers: { authorization: 'Bearer wrong-token' } }),
      env
    );
    assert.equal(rBadBearer.status, 401);

    // Login -> sets HttpOnly HMAC cookie tracked in DO
    const loginResp = await handleWorkerFetch(
      new Request('https://worker.local/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.10' },
        body: JSON.stringify({ token: 'correct-horse-battery-staple' })
      }),
      env
    );
    assert.equal(loginResp.status, 200);
    const setCookie = loginResp.headers.get('set-cookie') ?? '';
    assert.ok(setCookie.includes('HttpOnly'));
    assert.ok(setCookie.includes('SameSite=Strict'));
    assert.ok(setCookie.includes('Secure'));
    const cookiePair = setCookie.split(';')[0];

    const authedDash = await handleWorkerFetch(
      new Request('https://worker.local/', { headers: { cookie: cookiePair } }),
      env
    );
    assert.equal(authedDash.status, 200);
    assert.equal(authedDash.headers.get('x-frame-options'), 'DENY');
    assert.equal(authedDash.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(authedDash.headers.get('referrer-policy'), 'no-referrer');
    assert.ok(authedDash.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"));
    const dashBody = await authedDash.text();
    assert.ok(dashBody.includes('Export White-Label HTML Report'));

    const authedSummary = await handleWorkerFetch(
      new Request('https://worker.local/api/summary', { headers: { cookie: cookiePair } }),
      env
    );
    assert.equal(authedSummary.status, 200);

    // Logout revokes session nonce in DO -> replaying old cookie fails 401
    const logoutResp = await handleWorkerFetch(
      new Request('https://worker.local/api/auth/logout', {
        method: 'POST',
        headers: { cookie: cookiePair }
      }),
      env
    );
    assert.equal(logoutResp.status, 200);

    const replayedSummary = await handleWorkerFetch(
      new Request('https://worker.local/api/summary', { headers: { cookie: cookiePair } }),
      env
    );
    assert.equal(replayedSummary.status, 401);

    // Rate limiting: 5 attempts allowed per 60s window per IP, 6th returns 429
    for (let i = 0; i < 5; i++) {
      const bad = await handleWorkerFetch(
        new Request('https://worker.local/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.99' },
          body: JSON.stringify({ token: 'wrong' })
        }),
        env
      );
      assert.equal(bad.status, 401);
    }
    const limited = await handleWorkerFetch(
      new Request('https://worker.local/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.99' },
        body: JSON.stringify({ token: 'wrong' })
      }),
      env
    );
    assert.equal(limited.status, 429);
    assert.ok(limited.headers.get('retry-after'));

    // Authorization: Bearer brute-force rate limit (429 after 5 failed attempts on GET /api/summary & GET /)
    for (let i = 0; i < 5; i++) {
      const badBearer = await handleWorkerFetch(
        new Request('https://worker.local/api/summary', {
          headers: { authorization: 'Bearer wrong-secret', 'cf-connecting-ip': '198.51.100.77' }
        }),
        env
      );
      assert.equal(badBearer.status, 401);
    }
    const limitedBearerSummary = await handleWorkerFetch(
      new Request('https://worker.local/api/summary', {
        headers: { authorization: 'Bearer correct-horse-battery-staple', 'cf-connecting-ip': '198.51.100.77' }
      }),
      env
    );
    assert.equal(limitedBearerSummary.status, 429);
    assert.ok(limitedBearerSummary.headers.get('retry-after'));
    const limitedBearerDash = await handleWorkerFetch(
      new Request('https://worker.local/', {
        headers: { authorization: 'Bearer correct-horse-battery-staple', 'cf-connecting-ip': '198.51.100.77' }
      }),
      env
    );
    assert.equal(limitedBearerDash.status, 429);

    // Valid Bearer resets rate limit counter for a clean IP
    for (let i = 0; i < 3; i++) {
      const bad = await handleWorkerFetch(
        new Request('https://worker.local/api/summary', {
          headers: { authorization: 'Bearer bad', 'cf-connecting-ip': '198.51.100.88' }
        }),
        env
      );
      assert.equal(bad.status, 401);
    }
    const okReset = await handleWorkerFetch(
      new Request('https://worker.local/api/summary', {
        headers: { authorization: 'Bearer correct-horse-battery-staple', 'cf-connecting-ip': '198.51.100.88' }
      }),
      env
    );
    assert.equal(okReset.status, 200);

    // Caps login_rate_limits at MAX_RATE_LIMIT_ROWS (10_000) by evicting oldest window_start entries
    const { env: capEnv, db: capDb } = createSqliteDoEnv();
    const baseNow = 2_000_000_000;
    const insertStmt = capDb.prepare(
      `INSERT INTO login_rate_limits (client_key, attempts, window_start) VALUES (?, ?, ?)`
    );
    for (let i = 0; i < MAX_RATE_LIMIT_ROWS; i++) {
      insertStmt.run(`ip-old-${i}`, 1, baseNow + (i === 0 ? 0 : 10));
    }
    const stub = capEnv.DMARC_STORE.get(capEnv.DMARC_STORE.idFromName('global'));
    const capResp = await stub.fetch('https://dmarc-store/auth/rate-check', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientKey: 'ip-newest',
        nowSec: baseNow + 20,
        maxAttempts: 5,
        windowSec: 60
      })
    });
    assert.equal(capResp.status, 200);
    assert.equal((await capResp.json()).allowed, true);
    const totalRows = capDb.prepare(`SELECT COUNT(*) AS cnt FROM login_rate_limits`).get().cnt;
    assert.equal(totalRows, MAX_RATE_LIMIT_ROWS);
    const oldestStillPresent = capDb
      .prepare(`SELECT client_key FROM login_rate_limits WHERE client_key = ?`)
      .get('ip-old-0');
    assert.equal(oldestStillPresent, undefined);
    const newestPresent = capDb
      .prepare(`SELECT client_key FROM login_rate_limits WHERE client_key = ?`)
      .get('ip-newest');
    assert.equal(newestPresent?.client_key, 'ip-newest');
  });

  it('enforces strict ALLOWED_ORIGINS CORS allowlist (never wildcard *)', async () => {
    const { env } = createSqliteDoEnv({ ALLOWED_ORIGINS: 'https://ops.example, *' });

    const rEvil = await handleWorkerFetch(
      new Request('https://worker.local/api/health', { headers: { origin: 'https://evil.example' } }),
      env
    );
    assert.equal(rEvil.headers.get('access-control-allow-origin'), null);

    const rLocal = await handleWorkerFetch(
      new Request('https://worker.local/api/health', { headers: { origin: 'http://localhost:8787' } }),
      env
    );
    assert.equal(rLocal.headers.get('access-control-allow-origin'), null);

    const rAllowed = await handleWorkerFetch(
      new Request('https://worker.local/api/health', { headers: { origin: 'https://ops.example' } }),
      env
    );
    assert.equal(rAllowed.headers.get('access-control-allow-origin'), 'https://ops.example');
  });

  it('serves Zero-CDN XSS-safe dashboard with neutral white-label export and zero ApexHive/wallet/commercial strings', () => {
    const html = renderDashboardHtml();
    assert.ok(!html.includes('innerHTML'));
    assert.ok(!html.includes('outerHTML'));
    assert.ok(!html.includes('insertAdjacentHTML'));
    assert.ok(!html.includes('document.write'));
    assert.ok(!html.includes('eval('));
    assert.ok(!html.includes('ApexHive'));
    assert.ok(!html.includes('USDC'));
    assert.ok(!/0x[0-9a-fA-F]{40}/.test(html));
    assert.ok(html.includes('textContent'));
    assert.ok(html.includes('Export White-Label HTML Report'));
  });

  it('boots real wrangler dev --local and verifies /api/health, fail-closed auth & protected /api/summary', async () => {
    const wranglerJs = path.join(WORKER_DIR, 'node_modules', 'wrangler', 'bin', 'wrangler.js');
    assert.ok(existsSync(wranglerJs), `Expected wrangler entrypoint at ${wranglerJs}`);

    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const adminToken = 'wrangler-local-test-token-42';

    const tempHome = mkdtempSync(path.join(os.tmpdir(), 'dmarczero-wrangler-'));
    const devVarsPath = path.join(WORKER_DIR, '.dev.vars');
    writeFileSync(devVarsPath, `DASHBOARD_ADMIN_TOKEN=${adminToken}\n`, 'utf8');

    let logs = '';
    const proc = spawn(
      process.execPath,
      [wranglerJs, 'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--persist-to', path.join(tempHome, 'state')],
      {
        cwd: WORKER_DIR,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          HOME: tempHome,
          USERPROFILE: tempHome,
          XDG_CONFIG_HOME: path.join(tempHome, 'xdg-config'),
          WRANGLER_SEND_METRICS: 'false',
          CI: 'true'
        }
      }
    );
    proc.stdout?.on('data', (c) => { logs += String(c); });
    proc.stderr?.on('data', (c) => { logs += String(c); });

    try {
      await waitForHealth(`${baseUrl}/api/health`, proc, () => logs);

      const healthResp = await fetch(`${baseUrl}/api/health`);
      const health = await healthResp.json();
      assert.deepEqual(health, { ok: true, service: 'dmarczero-worker', version: '1.0.0' });
      assert.equal(healthResp.headers.get('x-frame-options'), 'DENY');

      const unauthedSummary = await fetch(`${baseUrl}/api/summary`);
      assert.equal(unauthedSummary.status, 401);

      const unauthedDash = await fetch(`${baseUrl}/`);
      assert.equal(unauthedDash.status, 401);

      const authedDash = await fetch(`${baseUrl}/`, {
        headers: { authorization: `Bearer ${adminToken}` }
      });
      assert.equal(authedDash.status, 200);
      assert.ok((await authedDash.text()).includes('Export White-Label HTML Report'));

      const authedSummary = await fetch(`${baseUrl}/api/summary`, {
        headers: { authorization: `Bearer ${adminToken}` }
      });
      assert.equal(authedSummary.status, 200);
    } finally {
      if (proc.exitCode === null) {
        if (process.platform === 'win32' && proc.pid) {
          await execFileAsync('taskkill', ['/pid', String(proc.pid), '/T', '/F']).catch(() => {});
        } else {
          proc.kill('SIGTERM');
          await new Promise((r) => {
            const timer = setTimeout(() => {
              if (proc.exitCode === null) proc.kill('SIGKILL');
              r(undefined);
            }, 3000);
            proc.once('exit', () => {
              clearTimeout(timer);
              r(undefined);
            });
          });
        }
        await new Promise((r) => setTimeout(r, 400));
      }
      rmSync(devVarsPath, { force: true });
      await rmAsync(tempHome, { recursive: true, force: true, maxRetries: 15, retryDelay: 250 }).catch(() => {});
    }
  });
});
