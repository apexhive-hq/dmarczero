import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { auditDns, auditSpf, auditDmarc, auditDkim } from '../dist/index.js';

function makeMockResolver(records) {
  return {
    async resolveTxt(hostname) {
      const key = hostname.toLowerCase();
      const val = records.txt?.[key];
      if (!val) {
        const err = new Error(`ENODATA ${key}`);
        err.code = 'ENODATA';
        throw err;
      }
      return val;
    },
    async resolveMx(hostname) {
      return records.mx?.[hostname.toLowerCase()] ?? [];
    },
    async resolveCaa(hostname) {
      return records.caa?.[hostname.toLowerCase()] ?? [];
    }
  };
}

function generateRsaSpkiBase64(bits) {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits });
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return Buffer.from(der).toString('base64');
}

describe('dns-audit: SPF recursive lookup counting & loop protection', () => {
  it('passes a clean SPF record under 10 lookups', async () => {
    const resolver = makeMockResolver({
      txt: {
        'clean.example': [['v=spf1 include:_spf.a.example mx -all']],
        '_spf.a.example': [['v=spf1 ip4:203.0.113.0/24 ~all']]
      }
    });

    const res = await auditSpf('clean.example', resolver);
    assert.equal(res.present, true);
    assert.equal(res.lookupCount, 2);
    assert.equal(res.status, 'ok');
    assert.equal(res.allQualifier, '-all');
    assert.deepEqual(res.loops, []);
  });

  it('warns when SPF reaches 9/10 DNS lookups', async () => {
    const resolver = makeMockResolver({
      txt: {
        'near.example': [['v=spf1 include:i1.ex include:i2.ex include:i3.ex include:i4.ex include:i5.ex include:i6.ex include:i7.ex a mx -all']],
        'i1.ex': [['v=spf1 ip4:198.51.100.1 -all']],
        'i2.ex': [['v=spf1 ip4:198.51.100.2 -all']],
        'i3.ex': [['v=spf1 ip4:198.51.100.3 -all']],
        'i4.ex': [['v=spf1 ip4:198.51.100.4 -all']],
        'i5.ex': [['v=spf1 ip4:198.51.100.5 -all']],
        'i6.ex': [['v=spf1 ip4:198.51.100.6 -all']],
        'i7.ex': [['v=spf1 ip4:198.51.100.7 -all']]
      }
    });

    const res = await auditSpf('near.example', resolver);
    assert.equal(res.lookupCount, 9);
    assert.equal(res.status, 'warn');
    assert.ok(res.findings.some((f) => f.code === 'SPF_LOOKUP_NEAR_LIMIT'));
  });

  it('errors when recursive SPF exceeds 10 DNS lookups', async () => {
    const resolver = makeMockResolver({
      txt: {
        'over.example': [['v=spf1 include:l1.ex include:l2.ex include:l3.ex a mx exists:%{i}.check.ex -all']],
        'l1.ex': [['v=spf1 include:l1a.ex include:l1b.ex -all']],
        'l1a.ex': [['v=spf1 a mx -all']],
        'l1b.ex': [['v=spf1 ip4:192.0.2.1 -all']],
        'l2.ex': [['v=spf1 redirect=l2r.ex']],
        'l2r.ex': [['v=spf1 mx -all']],
        'l3.ex': [['v=spf1 ip4:192.0.2.2 -all']]
      }
    });

    const res = await auditSpf('over.example', resolver);
    assert.ok(res.lookupCount > 10, `Expected >10 lookups, got ${res.lookupCount}`);
    assert.equal(res.status, 'error');
    assert.ok(res.findings.some((f) => f.code === 'SPF_LOOKUP_EXCEEDED'));
  });

  it('detects and terminates circular SPF include references safely', async () => {
    const resolver = makeMockResolver({
      txt: {
        'loop-a.example': [['v=spf1 include:loop-b.example -all']],
        'loop-b.example': [['v=spf1 include:loop-a.example -all']]
      }
    });

    const res = await auditSpf('loop-a.example', resolver);
    assert.equal(res.status, 'error');
    assert.ok(res.loops.includes('loop-a.example'));
    assert.ok(res.findings.some((f) => f.code === 'SPF_LOOP'));
  });

  it('ignores redirect= when an all mechanism is present (RFC 7208 §6.1)', async () => {
    const resolver = makeMockResolver({
      txt: {
        'redir.example': [['v=spf1 ip4:203.0.113.10 -all redirect=ignored.example']],
        'ignored.example': [['v=spf1 mx -all']]
      }
    });

    const res = await auditSpf('redir.example', resolver);
    assert.equal(res.lookupCount, 0);
    assert.equal(res.status, 'ok');
  });
});

describe('dns-audit: DMARC, DKIM, MTA-STS, TLS-RPT, CAA', () => {
  it('parses DMARC record fields and flags p=none and ruf privacy note', async () => {
    const resolver = makeMockResolver({
      txt: {
        '_dmarc.corp.example': [['v=DMARC1; p=none; sp=quarantine; pct=50; adkim=s; aspf=r; rua=mailto:dmarc@corp.example; ruf=mailto:forensic@corp.example']]
      }
    });

    const res = await auditDmarc('corp.example', resolver);
    assert.equal(res.present, true);
    assert.equal(res.validVersion, true);
    assert.equal(res.policy, 'none');
    assert.equal(res.subdomainPolicy, 'quarantine');
    assert.equal(res.pct, 50);
    assert.equal(res.adkim, 's');
    assert.equal(res.aspf, 'r');
    assert.deepEqual(res.rua, ['mailto:dmarc@corp.example']);
    assert.deepEqual(res.ruf, ['mailto:forensic@corp.example']);
    assert.ok(res.findings.some((f) => f.code === 'DMARC_POLICY_NONE'));
    assert.ok(res.findings.some((f) => f.code === 'DMARC_RUF_PRIVACY_NOTE'));
  });

  it('flags weak 1024-bit RSA DKIM keys and accepts 2048-bit RSA keys', async () => {
    const weakPub = generateRsaSpkiBase64(1024);
    const strongPub = generateRsaSpkiBase64(2048);

    const resolver = makeMockResolver({
      txt: {
        'weak._domainkey.mail.example': [[`v=DKIM1; k=rsa; p=${weakPub}`]],
        'strong._domainkey.mail.example': [[`v=DKIM1; k=rsa; p=${strongPub}`]],
        'revoked._domainkey.mail.example': [['v=DKIM1; k=rsa; p=']]
      }
    });

    const results = await auditDkim('mail.example', ['weak', 'strong', 'revoked'], resolver);
    const weak = results.find((r) => r.selector === 'weak');
    const strong = results.find((r) => r.selector === 'strong');
    const revoked = results.find((r) => r.selector === 'revoked');

    assert.equal(weak?.keyBits, 1024);
    assert.equal(weak?.status, 'warn');
    assert.ok(weak?.findings.some((f) => f.code === 'DKIM_WEAK_RSA_KEY'));

    assert.equal(strong?.keyBits, 2048);
    assert.equal(strong?.status, 'ok');

    assert.equal(revoked?.revoked, true);
    assert.equal(revoked?.status, 'warn');
  });

  it('produces a full 100/100 DNS audit report for a hardened domain', async () => {
    const strongPub = generateRsaSpkiBase64(2048);
    const resolver = makeMockResolver({
      txt: {
        'hardened.example': [['v=spf1 ip4:203.0.113.10 -all']],
        '_dmarc.hardened.example': [['v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@hardened.example']],
        'google._domainkey.hardened.example': [[`v=DKIM1; k=rsa; p=${strongPub}`]],
        '_mta-sts.hardened.example': [['v=STSv1; id=20261126T000000']],
        '_smtp._tls.hardened.example': [['v=TLSRPTv1; rua=mailto:tlsrpt@hardened.example']]
      },
      mx: {
        'hardened.example': [{ priority: 10, exchange: 'mx1.hardened.example' }]
      },
      caa: {
        'hardened.example': [{ critical: 0, issue: 'letsencrypt.org' }]
      }
    });

    const report = await auditDns('hardened.example', { selectors: ['google'], resolver });
    assert.equal(report.score, 100);
    assert.equal(report.findings.length, 0);
    assert.equal(report.mtaSts.present, true);
    assert.equal(report.tlsRpt.present, true);
    assert.equal(report.caa.present, true);
  });
});
