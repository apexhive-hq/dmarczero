import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runCli } from '../dist/index.js';

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

  it('runs parse-rua and white-label report on a directory containing RUA + rejected RUF', async () => {
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
      const code2 = await runCli(
        ['report', tmpDir, '--out', reportOut, '--title', 'Acme Client Audit', '--footer', 'Prepared by Acme SecOps'],
        c2.runtime
      );
      assert.equal(code2, 0);
      const html = readFileSync(reportOut, 'utf8');
      assert.ok(html.includes('Acme Client Audit'));
      assert.ok(html.includes('Prepared by Acme SecOps'));
      assert.ok(html.includes('192.0.2.5'));
      assert.ok(!/0x[0-9a-fA-F]{40}/.test(html));
      assert.ok(!html.includes('USDC'));
      assert.ok(!html.includes('ApexHive'));

      // --footer "" must suppress the default footer cleanly
      const noFooterOut = path.join(tmpDir, 'nofooter.html');
      const c3 = createCapturedRuntime();
      const code3 = await runCli(
        ['report', tmpDir, '--out', noFooterOut, '--footer', ''],
        c3.runtime
      );
      assert.equal(code3, 0);
      const noFooterHtml = readFileSync(noFooterOut, 'utf8');
      assert.ok(!noFooterHtml.includes('<footer>'));
      assert.ok(!noFooterHtml.includes('MIT Open Source'));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('rejects removed commercial verify-license command cleanly', async () => {
    const c = createCapturedRuntime();
    const code = await runCli(['verify-license', 'license.json'], c.runtime);
    assert.equal(code, 2);
    assert.ok(c.err.join('\n').includes('Unknown command'));
  });
});
