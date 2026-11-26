import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateHtmlReport,
  matchMailProvider,
  parseRuaBuffer
} from '../dist/index.js';

describe('providers & white-label HTML report', () => {
  it('attributes all 7 supported mail providers offline via IPv4/IPv6 CIDR and hostname fallback', () => {
    assert.equal(matchMailProvider('209.85.220.41').providerId, 'google-workspace');
    assert.equal(matchMailProvider('2607:f8b0:4000:800::200e').providerId, 'google-workspace');
    assert.equal(matchMailProvider('40.107.22.55').providerId, 'microsoft-365');
    assert.equal(matchMailProvider('167.89.100.12').providerId, 'sendgrid');
    assert.equal(matchMailProvider('54.240.14.20').providerId, 'amazon-ses');
    assert.equal(matchMailProvider('198.61.254.10').providerId, 'mailgun');
    assert.equal(matchMailProvider('50.31.156.42').providerId, 'postmark');
    assert.equal(matchMailProvider('104.30.10.5').providerId, 'cloudflare-email');
    assert.equal(matchMailProvider('192.0.2.99', ['bounce.sendgrid.net']).providerId, 'sendgrid');
    assert.equal(matchMailProvider('198.51.100.77').providerId, 'unknown');
  });

  it('enriches RUA parsed sources and zero-CDN white-label HTML report without hardcoded promo or wallets', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>prov-1</report_id><date_range><begin>100</begin><end>200</end></date_range></report_metadata>
  <policy_published><domain>msp-client.example</domain><p>reject</p></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>18</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>msp-client.example</header_from></identifiers>
  </record>
  <record>
    <row><source_ip>54.240.14.20</source_ip><count>7</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>msp-client.example</header_from></identifiers>
  </record>
</feedback>`;

    const parsed = await parseRuaBuffer(Buffer.from(xml, 'utf8'));
    assert.equal(parsed.sources[0].provider, 'Google Workspace');
    assert.equal(parsed.sources[1].provider, 'Amazon SES');

    const html = generateHtmlReport({
      title: 'Custom Client Report',
      footerText: 'Confidential Client Summary',
      rua: {
        reports: [parsed],
        rejectedFiles: [],
        totalMessages: parsed.totalMessages,
        dmarcPass: parsed.dmarcPass,
        dmarcFail: parsed.dmarcFail,
        passRate: parsed.passRate,
        suspiciousSources: parsed.suspiciousSources
      }
    });
    assert.ok(html.includes('Google Workspace'));
    assert.ok(html.includes('Amazon SES'));
    assert.ok(html.includes('Custom Client Report'));
    assert.ok(html.includes('Confidential Client Summary'));
    assert.ok(!html.includes('ApexHive'));
    assert.ok(!/0x[0-9a-fA-F]{40}/.test(html));
    assert.ok(!html.includes('USDC'));
  });
});
