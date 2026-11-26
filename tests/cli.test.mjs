import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runCli, signLicensePayload } from '../dist/index.js';

function createCapturedRuntime(resolver) {
  const out = [];
  const err = [];
  return {
    out,
    err,
    runtime: {
      stdout: (line) => out.push(line),
      stderr: (line) => err.push(line),
      resolver
    }
  };
}

describe('cli: E2E offline workflow tests', () => {
  it('runs check, snapshot, and diff --fail-on-drift end-to-end', async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'dmarczero-cli-'));
    try {
      let spfValue = 'v=spf1 ip4:203.0.113.5 -all';
      const resolver = {
        async resolveTxt(h) {
          if (h === 'cli.example') return [[spfValue]];
          if (h === '_dmarc.cli.example') return [['v=DMARC1; p=reject; rua=mailto:dmarc@cli.example']];
          const e = new Error('ENODATA');
          e.code = 'ENODATA';
          throw e;
        },
        async resolveMx() {
          return [{ priority: 10, exchange: 'mx.cli.example' }];
        },
        async resolveCaa() {
          return [{ critical: 0, issue: 'letsencrypt.org' }];
        }
      };

      // 1. check --json --no-tls
      const c1 = createCapturedRuntime(resolver);
      const code1 = await runCli(['check', 'cli.example', '--no-tls', '--json'], c1.runtime);
      assert.equal(code1, 0);
      const parsed = JSON.parse(c1.out.join('\n'));
      assert.equal(parsed.dns.domain, 'cli.example');

      // 2. snapshot
      const snapFile = path.join(tmpDir, 'dmarczero.snapshot.json');
      const c2 = createCapturedRuntime(resolver);
      const code2 = await runCli(['snapshot', 'cli.example', '--no-tls', '--out', snapFile], c2.runtime);
      assert.equal(code2, 0);

      // 3. diff (no drift -> exit 0)
      const c3 = createCapturedRuntime(resolver);
      const code3 = await runCli(['diff', 'cli.example', '--no-tls', '--snapshot', snapFile, '--fail-on-drift'], c3.runtime);
      assert.equal(code3, 0);

      // 4. diff after accidental SPF change -> exit 1
      spfValue = 'v=spf1 ip4:203.0.113.99 ~all';
      const c4 = createCapturedRuntime(resolver);
      const code4 = await runCli(['diff', 'cli.example', '--no-tls', '--snapshot', snapFile, '--fail-on-drift'], c4.runtime);
      assert.equal(code4, 1);
      assert.ok(c4.out.join('\n').includes('DRIFT DETECTED'));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('runs parse-rua and report on a directory containing RUA + rejected RUF', async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'dmarczero-rua-cli-'));
    try {
      const ruaXml = `<feedback><report_metadata><org_name>yahoo.com</org_name><email>dmarc@yahoo.com</email><report_id>r1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published><domain>cli.example</domain><p>reject</p></policy_published><record><row><source_ip>192.0.2.5</source_ip><count>10</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>cli.example</header_from></identifiers></record></feedback>`;
      writeFileSync(path.join(tmpDir, 'valid-rua.xml'), ruaXml, 'utf8');
      writeFileSync(path.join(tmpDir, 'forensic!ruf!99.xml'), 'Feedback-Type: auth-failure\nOriginal-Mail-From: a@b.com', 'utf8');

      const c1 = createCapturedRuntime();
      const code1 = await runCli(['parse-rua', tmpDir, '--json'], c1.runtime);
      assert.equal(code1, 0);
      const parsed = JSON.parse(c1.out.join('\n'));
      assert.equal(parsed.reports.length, 1);
      assert.equal(parsed.rejectedFiles.length, 1);
      assert.equal(parsed.totalMessages, 10);

      const reportOut = path.join(tmpDir, 'out.html');
      const c2 = createCapturedRuntime();
      const code2 = await runCli(['report', tmpDir, '--out', reportOut], c2.runtime);
      assert.equal(code2, 0);
      const html = readFileSync(reportOut, 'utf8');
      assert.ok(html.includes('DMARCZero'));
      assert.ok(html.includes('192.0.2.5'));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('verifies Ed25519 Team/Enterprise license offline while never locking features', async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'dmarczero-lic-'));
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

      const cert = signLicensePayload({
        product: 'dmarczero',
        tier: 'team',
        holder: 'Acme MSP',
        seats: 15,
        issuedAt: '2026-11-26T00:00:00.000Z'
      }, privPem);

      const pubPath = path.join(tmpDir, 'pub.pem');
      const licPath = path.join(tmpDir, 'license.json');
      writeFileSync(pubPath, pubPem, 'utf8');
      writeFileSync(licPath, JSON.stringify(cert), 'utf8');

      const c1 = createCapturedRuntime();
      const code1 = await runCli(['verify-license', licPath, '--pubkey', pubPath, '--json'], c1.runtime);
      assert.equal(code1, 0);
      const res1 = JSON.parse(c1.out.join('\n'));
      assert.equal(res1.valid, true);
      assert.equal(res1.tier, 'team');
      assert.equal(res1.featuresUnlocked, true);

      // Tampered signature still keeps featuresUnlocked === true
      const tampered = { ...cert, signature: 'invalid-sig' };
      const badPath = path.join(tmpDir, 'bad.json');
      writeFileSync(badPath, JSON.stringify(tampered), 'utf8');

      const c2 = createCapturedRuntime();
      const code2 = await runCli(['verify-license', badPath, '--pubkey', pubPath, '--json'], c2.runtime);
      assert.equal(code2, 1);
      const res2 = JSON.parse(c2.out.join('\n'));
      assert.equal(res2.valid, false);
      assert.equal(res2.tier, 'solo');
      assert.equal(res2.featuresUnlocked, true);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
