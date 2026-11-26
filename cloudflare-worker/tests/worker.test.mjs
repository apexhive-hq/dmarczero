import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { rm as rmAsync } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import zlib from 'node:zlib';

const execFileAsync = promisify(execFile);
import { DatabaseSync } from 'node:sqlite';
import { privateKeyToAccount } from 'viem/accounts';
import {
  APEXHIVE_BASE_USDC_RECIPIENT,
  BASE_USDC_CONTRACT,
  DmarcStoreDO,
  handleWorkerEmail,
  handleWorkerFetch,
  handleWorkerScheduled,
  renderDashboardHtml
} from '../dist/worker-app.js';
import { sendSafeWebhookAlert, validateWebhookUrl } from '../dist/cron-monitor.js';

const WORKER_DIR = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const BOOL_TRUE_HEX = '0x' + '0'.repeat(63) + '1';
const BOOL_FALSE_HEX = '0x' + '0'.repeat(64);
const ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function padTopicAddr(addr) {
  return '0x' + addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

function encodeUsdcTransferLog(from, to, atomicAmount) {
  return {
    address: BASE_USDC_CONTRACT,
    topics: [ERC20_TRANSFER_TOPIC, padTopicAddr(from), padTopicAddr(to)],
    data: '0x' + BigInt(atomicAmount).toString(16).padStart(64, '0')
  };
}

function canonicalizeLicensePayload(payload) {
  return JSON.stringify({
    product: payload.product,
    tier: payload.tier,
    holder: payload.holder,
    seats: payload.seats,
    issuedAt: payload.issuedAt,
    txHash: payload.txHash
  });
}

async function generateEd25519Keypair() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const privJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  const pubPem = crypto
    .createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' })
    .export({ type: 'spki', format: 'pem' })
    .toString();
  return {
    privateJwkJson: JSON.stringify(privJwk),
    spkiB64: Buffer.from(spki).toString('base64'),
    pubPem
  };
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

function startMockBaseRpc(state) {
  const server = http.createServer(async (req, res) => {
    if (req.url === '/flaky') {
      state.flakyHits += 1;
      const status = state.flakyHits % 2 === 1 ? 429 : 500;
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: `simulated flaky RPC HTTP ${status}` }));
      return;
    }
    if (req.url !== '/ok' || req.method !== 'POST') {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    let result = null;
    if (body.method === 'eth_blockNumber') {
      result = '0x' + state.headBlock.toString(16);
    } else if (body.method === 'eth_getTransactionReceipt') {
      result = state.receipts.get(String(body.params?.[0] ?? '').toLowerCase()) ?? null;
    } else if (body.method === 'eth_call') {
      const data = String(body.params?.[0]?.data ?? '').toLowerCase();
      const ok = data.includes(state.smartWalletAddr.slice(2).toLowerCase()) && data.includes('cc'.repeat(32));
      result = ok ? BOOL_TRUE_HEX : BOOL_FALSE_HEX;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id ?? 1, result }));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
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

describe('cloudflare-worker: Email RUA ingestion, provider attribution & RUF privacy firewall', () => {
  it('ingests MIME email with gzipped RUA XML into SQLite DO with provider attribution via /api/summary', async () => {
    const { env } = createSqliteDoEnv();
    const xml = `<feedback><report_metadata><org_name>google.com</org_name><report_id>w-rep-1</report_id><date_range><begin>100</begin><end>200</end></date_range></report_metadata><policy_published><domain>worker.example</domain><p>reject</p></policy_published><record><row><source_ip>209.85.220.41</source_ip><count>25</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>worker.example</header_from></identifiers></record></feedback>`;
    const gzB64 = zlib.gzipSync(Buffer.from(xml, 'utf8')).toString('base64');
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

    const summaryResp = await handleWorkerFetch(new Request('https://worker.local/api/summary'), env);
    assert.equal(summaryResp.status, 200);
    const summary = await summaryResp.json();
    assert.equal(summary.reports.length, 1);
    assert.equal(summary.reports[0].domain, 'worker.example');
    assert.equal(summary.reports[0].total_messages, 25);
    assert.equal(summary.reports[0].provider_breakdown['Google Workspace'], 25);
    assert.equal(summary.reports[0].sources[0].providerId, 'google-workspace');
  });

  it('strictly rejects RUF forensic emails without storing PII', async () => {
    const { env } = createSqliteDoEnv();
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

describe('cloudflare-worker: SSRF-protected webhook relay & Cron drift sentinel', () => {
  it('blocks SSRF targets (HTTP, loopback, metadata IP, private IP, non-allowlisted hosts, 3xx redirects)', async () => {
    assert.equal(validateWebhookUrl('http://discord.com/api/webhooks/1/a').valid, false);
    assert.equal(validateWebhookUrl('https://127.0.0.1/hook').valid, false);
    assert.equal(validateWebhookUrl('https://169.254.169.254/latest/meta-data/').valid, false);
    assert.equal(validateWebhookUrl('https://10.0.0.5/internal').valid, false);
    assert.equal(validateWebhookUrl('https://localhost/hook').valid, false);
    assert.equal(validateWebhookUrl('https://[::1]/hook').valid, false);
    assert.equal(validateWebhookUrl('https://evil.example.com/steal').valid, false);
    assert.equal(validateWebhookUrl('https://user:pass@discord.com/api/webhooks/1/a').valid, false);

    assert.equal(validateWebhookUrl('https://discord.com/api/webhooks/123/abc').valid, true);
    assert.equal(validateWebhookUrl('https://hooks.slack.com/services/T/B/X').valid, true);
    assert.equal(validateWebhookUrl('https://api.telegram.org/bot123/sendMessage').valid, true);

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

  it('detects DNS drift on second cron run and sends webhook alert', async () => {
    const { env } = createSqliteDoEnv({
      MONITORED_DOMAINS: 'sentinel.example',
      ALERT_WEBHOOK_URL: 'https://hooks.slack.com/services/T00/B00/XYZ'
    });

    let currentSpf = 'v=spf1 ip4:203.0.113.1 -all';
    const alerts = [];

    const mockFetch = async (url, init) => {
      const u = String(url);
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
    assert.equal(run1.alertsSent, 0);

    currentSpf = 'v=spf1 ip4:203.0.113.1 +all';
    const run2 = await handleWorkerScheduled(env, mockFetch);
    assert.equal(run2.alertsSent, 1);
    assert.equal(alerts.length, 1);
    assert.ok(alerts[0].text.includes('SPF changed'));
  });
});

describe('cloudflare-worker: CORS, Zero-XSS White-Label Dashboard & Real Base USDC Verification', () => {
  it('enforces strict CORS (no wildcard *) and allows loopback + configured origins', async () => {
    const { env } = createSqliteDoEnv({ ALLOWED_ORIGINS: 'https://ops.apexhive.example' });

    const r1 = await handleWorkerFetch(
      new Request('https://worker.local/api/health', { headers: { origin: 'https://evil.example' } }),
      env
    );
    assert.equal(r1.headers.get('access-control-allow-origin'), null);

    const r2 = await handleWorkerFetch(
      new Request('https://worker.local/api/health', { headers: { origin: 'http://localhost:8787' } }),
      env
    );
    assert.equal(r2.headers.get('access-control-allow-origin'), 'http://localhost:8787');

    const r3 = await handleWorkerFetch(
      new Request('https://worker.local/api/health', { headers: { origin: 'https://ops.apexhive.example' } }),
      env
    );
    assert.equal(r3.headers.get('access-control-allow-origin'), 'https://ops.apexhive.example');
  });

  it('serves Zero-CDN XSS-safe dashboard with white-label HTML report export and zero unsafe DOM sinks', () => {
    const html = renderDashboardHtml();
    assert.ok(!html.includes('innerHTML'));
    assert.ok(!html.includes('outerHTML'));
    assert.ok(!html.includes('insertAdjacentHTML'));
    assert.ok(!html.includes('document.write'));
    assert.ok(!html.includes('eval('));
    assert.ok(html.includes('textContent'));
    assert.ok(html.includes('Export White-Label Client HTML Report'));
    assert.ok(html.includes(APEXHIVE_BASE_USDC_RECIPIENT));
  });

  it('enforces fail-closed 500, RPC confirmations, EIP-191 EOA, ERC-1271/6492 Smart Wallet, atomic replay lock & Ed25519 certs', async () => {
    const payer = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
    const attacker = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
    const smartWalletAddr = '0x4444444444444444444444444444444444444444';
    const smartWalletSig = '0x' + 'cc'.repeat(256);

    const txTeam = '0x' + '11'.repeat(32);
    const txUnderpaid = '0x' + '22'.repeat(32);
    const txEnterpriseSmart = '0x' + '33'.repeat(32);
    const txFake = '0x' + '99'.repeat(32);

    const rpcState = {
      flakyHits: 0,
      headBlock: 100,
      smartWalletAddr,
      receipts: new Map([
        [
          txTeam,
          {
            status: '0x1',
            blockNumber: '0x64', // block 100 -> 1 conf initially, 2 confs once headBlock=101
            logs: [encodeUsdcTransferLog(payer.address, APEXHIVE_BASE_USDC_RECIPIENT, 99_000_000n)]
          }
        ],
        [
          txUnderpaid,
          {
            status: '0x1',
            blockNumber: '0x62',
            logs: [encodeUsdcTransferLog(payer.address, APEXHIVE_BASE_USDC_RECIPIENT, 50_000_000n)]
          }
        ],
        [
          txEnterpriseSmart,
          {
            status: '0x1',
            blockNumber: '0x62',
            logs: [encodeUsdcTransferLog(smartWalletAddr, APEXHIVE_BASE_USDC_RECIPIENT, 499_000_000n)]
          }
        ]
      ])
    };

    const rpcServer = await startMockBaseRpc(rpcState);
    const rpcPort = rpcServer.address().port;

    try {
      const { privateJwkJson, spkiB64, pubPem } = await generateEd25519Keypair();

      // 0. Fail-closed 500 when LICENSE_SIGNING_PRIVATE_JWK missing
      const { env: unconfiguredEnv } = createSqliteDoEnv({
        BASE_RPC_URLS: `http://127.0.0.1:${rpcPort}/ok`
      });
      const r500 = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: txTeam, nonce: '12345678', signature: '0x' + 'aa'.repeat(65), tier: 'team' })
        }),
        unconfiguredEnv
      );
      assert.equal(r500.status, 500);

      const { env } = createSqliteDoEnv({
        BASE_RPC_URLS: `http://127.0.0.1:${rpcPort}/flaky,http://127.0.0.1:${rpcPort}/ok`,
        BASE_USDC_CONTRACT,
        PAY_TO_EVM_ADDRESS: APEXHIVE_BASE_USDC_RECIPIENT,
        MIN_CONFIRMATIONS: '2',
        LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
        LICENSE_SIGNING_PUBLIC_SPKI_B64: spkiB64
      });

      // 1. Challenge fails cleanly on invalid tier
      const badTier = await handleWorkerFetch(
        new Request('https://worker.local/api/license/challenge', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: txTeam, tier: 'solo' })
        }),
        env
      );
      assert.equal(badTier.status, 400);

      // 2. Request Team challenge -> 1-conf rejected -> head advances -> bad attacker sig rejected -> payer sig passes
      const chTeam = await (
        await handleWorkerFetch(
          new Request('https://worker.local/api/license/challenge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ txHash: txTeam, tier: 'team' })
          }),
          env
        )
      ).json();
      assert.ok(chTeam.nonce && chTeam.message.includes('product=dmarczero'));

      const sigPayer = await payer.signMessage({ message: chTeam.message });
      const sigAttacker = await attacker.signMessage({ message: chTeam.message });

      const conf1Res = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            tier: 'team',
            holder: 'Acme Agency',
            txHash: txTeam,
            nonce: chTeam.nonce,
            signature: sigPayer
          })
        }),
        env
      );
      assert.equal(conf1Res.status, 403);
      assert.equal((await conf1Res.json()).error, 'INSUFFICIENT_CONFIRMATIONS');
      assert.ok(rpcState.flakyHits >= 2, 'Expected Base RPC failover');

      // Advance block -> 2 confirmations
      rpcState.headBlock = 101;

      const badSigRes = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            tier: 'team',
            holder: 'Acme Agency',
            txHash: txTeam,
            nonce: chTeam.nonce,
            signature: sigAttacker
          })
        }),
        env
      );
      assert.equal(badSigRes.status, 403);
      assert.equal((await badSigRes.json()).error, 'PAYMENT_OR_SIGNATURE_INVALID');

      // Real payer signature succeeds & issues Ed25519 certificate verifiable offline
      const okRes = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            tier: 'team',
            holder: 'Acme Agency',
            txHash: txTeam,
            nonce: chTeam.nonce,
            signature: sigPayer
          })
        }),
        env
      );
      assert.equal(okRes.status, 200);
      const okBody = await okRes.json();
      assert.equal(okBody.valid, true);
      assert.equal(okBody.tier, 'team');
      assert.equal(okBody.paidAtomic, '99000000');
      assert.equal(okBody.featuresUnlocked, true);
      assert.ok(okBody.certificate?.signature);

      const certVerified = crypto.verify(
        null,
        Buffer.from(canonicalizeLicensePayload(okBody.certificate.payload), 'utf8'),
        pubPem,
        Buffer.from(okBody.certificate.signature, 'base64url')
      );
      assert.equal(certVerified, true);

      // 3. Replay with a fresh nonce against same txHash must fail 409 TX_ALREADY_CLAIMED
      const chReplay = await (
        await handleWorkerFetch(
          new Request('https://worker.local/api/license/challenge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ txHash: txTeam, tier: 'team' })
          }),
          env
        )
      ).json();
      const replaySig = await payer.signMessage({ message: chReplay.message });
      const replayRes = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            tier: 'team',
            holder: 'Acme Agency',
            txHash: txTeam,
            nonce: chReplay.nonce,
            signature: replaySig
          })
        }),
        env
      );
      assert.equal(replayRes.status, 409);
      assert.equal((await replayRes.json()).error, 'TX_ALREADY_CLAIMED');

      // 4. Fake non-existent txHash fails closed 403 TX_NOT_CONFIRMED
      const chFake = await (
        await handleWorkerFetch(
          new Request('https://worker.local/api/license/challenge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ txHash: txFake, tier: 'team' })
          }),
          env
        )
      ).json();
      const fakeRes = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            tier: 'team',
            txHash: txFake,
            nonce: chFake.nonce,
            signature: await payer.signMessage({ message: chFake.message })
          })
        }),
        env
      );
      assert.equal(fakeRes.status, 403);
      assert.equal((await fakeRes.json()).error, 'TX_NOT_CONFIRMED');

      // 5. Underpaid 50 USDC tx fails 403 PAYMENT_OR_SIGNATURE_INVALID
      const chUnder = await (
        await handleWorkerFetch(
          new Request('https://worker.local/api/license/challenge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ txHash: txUnderpaid, tier: 'team' })
          }),
          env
        )
      ).json();
      const underRes = await handleWorkerFetch(
        new Request('https://worker.local/api/license/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            tier: 'team',
            txHash: txUnderpaid,
            nonce: chUnder.nonce,
            signature: await payer.signMessage({ message: chUnder.message })
          })
        }),
        env
      );
      assert.equal(underRes.status, 403);
      assert.equal((await underRes.json()).error, 'PAYMENT_OR_SIGNATURE_INVALID');

      // 6. Concurrent Smart Wallet (ERC-1271 / EIP-6492) Enterprise 499 USDC race: 1 wins 200, 1 loses 409
      const [swCh1, swCh2] = await Promise.all([
        (
          await handleWorkerFetch(
            new Request('https://worker.local/api/license/challenge', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ txHash: txEnterpriseSmart, tier: 'enterprise' })
            }),
            env
          )
        ).json(),
        (
          await handleWorkerFetch(
            new Request('https://worker.local/api/license/challenge', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ txHash: txEnterpriseSmart, tier: 'enterprise' })
            }),
            env
          )
        ).json()
      ]);

      const [swRes1, swRes2] = await Promise.all([
        handleWorkerFetch(
          new Request('https://worker.local/api/license/verify', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              tier: 'enterprise',
              holder: 'Global MSP Enterprise',
              txHash: txEnterpriseSmart,
              nonce: swCh1.nonce,
              signature: smartWalletSig
            })
          }),
          env
        ),
        handleWorkerFetch(
          new Request('https://worker.local/api/license/verify', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              tier: 'enterprise',
              holder: 'Global MSP Enterprise',
              txHash: txEnterpriseSmart,
              nonce: swCh2.nonce,
              signature: smartWalletSig
            })
          }),
          env
        )
      ]);
      assert.deepEqual([swRes1.status, swRes2.status].sort((a, b) => a - b), [200, 409]);
    } finally {
      rpcServer.close();
    }
  });

  it('boots real wrangler dev --local and verifies /api/health, /api/config, dashboard HTML & fail-closed /api/license/verify', async () => {
    const wranglerJs = path.join(WORKER_DIR, 'node_modules', 'wrangler', 'bin', 'wrangler.js');
    assert.ok(existsSync(wranglerJs), `Expected wrangler entrypoint at ${wranglerJs}`);

    const rpcState = { flakyHits: 0, headBlock: 100, smartWalletAddr: '0x0000000000000000000000000000000000000000', receipts: new Map() };
    const rpcServer = await startMockBaseRpc(rpcState);
    const rpcPort = rpcServer.address().port;
    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const { privateJwkJson } = await generateEd25519Keypair();

    const tempHome = mkdtempSync(path.join(os.tmpdir(), 'dmarczero-wrangler-'));
    const devVarsPath = path.join(WORKER_DIR, '.dev.vars');
    writeFileSync(
      devVarsPath,
      [
        `LICENSE_SIGNING_PRIVATE_JWK=${privateJwkJson}`,
        `BASE_RPC_URLS=http://127.0.0.1:${rpcPort}/ok`,
        `BASE_RPC_URL=http://127.0.0.1:${rpcPort}/ok`
      ].join('\n'),
      'utf8'
    );

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

      const health = await (await fetch(`${baseUrl}/api/health`)).json();
      assert.equal(health.status, 'ok');
      assert.equal(health.durableObjectLockBound, true);
      assert.deepEqual(health.smartWalletSupport, ['EOA', 'ERC-1271', 'EIP-6492']);

      const cfg = await (await fetch(`${baseUrl}/api/config`)).json();
      assert.equal(cfg.tiers.solo.priceUsd, '0');
      assert.equal(cfg.tiers.team.priceAtomic, '99000000');
      assert.equal(cfg.tiers.enterprise.priceAtomic, '499000000');

      const dashHtml = await (await fetch(`${baseUrl}/`)).text();
      assert.ok(dashHtml.includes('Export White-Label Client HTML Report'));

      const txFake = '0x' + 'fe'.repeat(32);
      const ch = await (
        await fetch(`${baseUrl}/api/license/challenge`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: txFake, tier: 'team' })
        })
      ).json();
      const payer = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
      const fakeVerify = await fetch(`${baseUrl}/api/license/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: txFake,
          nonce: ch.nonce,
          signature: await payer.signMessage({ message: ch.message }),
          tier: 'team'
        })
      });
      assert.equal(fakeVerify.status, 403);
      assert.equal((await fakeVerify.json()).error, 'TX_NOT_CONFIRMED');
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
      rpcServer.close();
      rmSync(devVarsPath, { force: true });
      await rmAsync(tempHome, { recursive: true, force: true, maxRetries: 15, retryDelay: 250 }).catch(() => {});
    }
  });
});
