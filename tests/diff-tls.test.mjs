import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import tls from 'node:tls';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { auditTls, auditDns, createSnapshot, diffSnapshots, saveSnapshot, loadSnapshot } from '../dist/index.js';

function derLen(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

function derSeq(parts) {
  return derTag(0x30, Buffer.concat(parts));
}

function derSet(parts) {
  return derTag(0x31, Buffer.concat(parts));
}

function derUtcTime(date) {
  const iso = date.toISOString();
  const yy = iso.slice(2, 4);
  const mm = iso.slice(5, 7);
  const dd = iso.slice(8, 10);
  const hh = iso.slice(11, 13);
  const mi = iso.slice(14, 16);
  const ss = iso.slice(17, 19);
  return derTag(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${mi}${ss}Z`, 'ascii'));
}

function createSelfSignedCertPem(daysValid = 45) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  // OIDs: sha256WithRSAEncryption = 1.2.840.113549.1.1.11, CN = 2.5.4.3, O = 2.5.4.10
  const sigAlg = derSeq([
    derTag(0x06, Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])),
    derTag(0x05, Buffer.alloc(0))
  ]);
  const cnAttr = derSet([
    derSeq([derTag(0x06, Buffer.from([0x55, 0x04, 0x03])), derTag(0x0c, Buffer.from('localhost', 'utf8'))])
  ]);
  const orgAttr = derSet([
    derSeq([derTag(0x06, Buffer.from([0x55, 0x04, 0x0a])), derTag(0x0c, Buffer.from('ApexHiveTest', 'utf8'))])
  ]);
  const nameSeq = derSeq([cnAttr, orgAttr]);

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + daysValid * 24 * 60 * 60 * 1000);
  const validity = derSeq([derUtcTime(notBefore), derUtcTime(notAfter)]);

  const tbs = derSeq([
    derTag(0xa0, derTag(0x02, Buffer.from([0x02]))), // version v3
    derTag(0x02, Buffer.from([0x01])), // serialNumber 1
    sigAlg,
    nameSeq, // issuer
    validity,
    nameSeq, // subject
    spkiDer
  ]);

  const sigBytes = crypto.sign('sha256', tbs, privateKey);
  const sigBitString = derTag(0x03, Buffer.concat([Buffer.from([0x00]), sigBytes]));
  const certDer = derSeq([tbs, sigAlg, sigBitString]);
  const b64 = certDer.toString('base64').replace(/(.{64})/g, '$1\n');
  const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
  return { keyPem, certPem };
}

describe('tls-audit: ephemeral local loopback TLS certificate expiry checks', () => {
  let server;
  let port;

  before(async () => {
    const { keyPem, certPem } = createSelfSignedCertPem(45);
    server = tls.createServer({ key: keyPem, cert: certPem }, (socket) => {
      socket.end();
    });

    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('reads certificate chain and classifies >=30d as ok, <30d as warning, <14d as critical, <0d as expired', async () => {
    const okRes = await auditTls('127.0.0.1', { port, servername: 'localhost' });
    assert.equal(okRes.reachable, true);
    assert.equal(okRes.status, 'ok');
    assert.ok(okRes.daysRemaining >= 30);
    assert.ok(okRes.issuerChain.length >= 1);
    assert.ok(okRes.subject?.includes('CN=localhost'));

    const validToMs = new Date(okRes.validTo).getTime();

    const warnRes = await auditTls('127.0.0.1', {
      port,
      servername: 'localhost',
      now: new Date(validToMs - 20 * 24 * 60 * 60 * 1000)
    });
    assert.equal(warnRes.status, 'warning');

    const critRes = await auditTls('127.0.0.1', {
      port,
      servername: 'localhost',
      now: new Date(validToMs - 7 * 24 * 60 * 60 * 1000)
    });
    assert.equal(critRes.status, 'critical');

    const expRes = await auditTls('127.0.0.1', {
      port,
      servername: 'localhost',
      now: new Date(validToMs + 2 * 24 * 60 * 60 * 1000)
    });
    assert.equal(expRes.status, 'expired');
  });
});

describe('diff: snapshot creation, persistence, and drift detection', () => {
  it('detects zero drift when records match and precise drift when SPF/DMARC/MX change', async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'dmarczero-diff-'));
    try {
      const baseResolver = {
        async resolveTxt(h) {
          if (h === 'guard.example') return [['v=spf1 ip4:203.0.113.10 -all']];
          if (h === '_dmarc.guard.example') return [['v=DMARC1; p=reject; rua=mailto:dmarc@guard.example']];
          const err = new Error('ENODATA');
          err.code = 'ENODATA';
          throw err;
        },
        async resolveMx() {
          return [{ priority: 10, exchange: 'mx1.guard.example' }];
        },
        async resolveCaa() {
          return [{ critical: 0, issue: 'letsencrypt.org' }];
        }
      };

      const dns1 = await auditDns('guard.example', { selectors: ['google'], resolver: baseResolver });
      const snap1 = createSnapshot(dns1, null);
      const snapPath = path.join(tmpDir, 'dmarczero.snapshot.json');
      await saveSnapshot(snapPath, snap1);
      const loaded = await loadSnapshot(snapPath);

      const noDrift = diffSnapshots(loaded, snap1);
      assert.equal(noDrift.hasDrift, false);
      assert.equal(noDrift.changes.length, 0);

      // Simulate accidental SPF & DMARC downgrade
      const driftedResolver = {
        ...baseResolver,
        async resolveTxt(h) {
          if (h === 'guard.example') return [['v=spf1 ip4:203.0.113.10 +all']];
          if (h === '_dmarc.guard.example') return [['v=DMARC1; p=none; rua=mailto:dmarc@guard.example']];
          const err = new Error('ENODATA');
          err.code = 'ENODATA';
          throw err;
        }
      };
      const dns2 = await auditDns('guard.example', { selectors: ['google'], resolver: driftedResolver });
      const snap2 = createSnapshot(dns2, null);

      const drift = diffSnapshots(loaded, snap2);
      assert.equal(drift.hasDrift, true);
      assert.ok(drift.changes.some((c) => c.field === 'dns.spfRecord'));
      assert.ok(drift.changes.some((c) => c.field === 'dns.dmarcRecord'));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
