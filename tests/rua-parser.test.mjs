import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { Readable } from 'node:stream';
import {
  parseRuaBuffer,
  parseRuaXmlStream,
  RufRejectedError,
  RuaLimitError,
  generateHtmlReport
} from '../dist/index.js';

const SAMPLE_RUA_XML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890123456</report_id>
    <date_range>
      <begin>1764028800</begin>
      <end>1764115199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>apexhive.example</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.10</source_ip>
      <count>42</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>apexhive.example</header_from>
    </identifiers>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.77</source_ip>
      <count>8</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>spoof&lt;script&gt;alert(1)&lt;/script&gt;.example</header_from>
    </identifiers>
  </record>
</feedback>`;

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

function buildSingleFileZip(filename, contentBuffer) {
  const nameBuf = Buffer.from(filename, 'utf8');
  const compressed = zlib.deflateRawSync(contentBuffer);
  const crc = crc32(contentBuffer);

  // Local file header (30 bytes + filename)
  const localHeader = Buffer.alloc(30 + nameBuf.length);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(8, 8); // deflate
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(crc >>> 0, 14);
  localHeader.writeUInt32LE(compressed.length, 18);
  localHeader.writeUInt32LE(contentBuffer.length, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  localHeader.writeUInt16LE(0, 28);
  nameBuf.copy(localHeader, 30);

  const cdOffset = localHeader.length + compressed.length;
  const cdHeader = Buffer.alloc(46 + nameBuf.length);
  cdHeader.writeUInt32LE(0x02014b50, 0);
  cdHeader.writeUInt16LE(20, 4);
  cdHeader.writeUInt16LE(20, 6);
  cdHeader.writeUInt16LE(0, 8);
  cdHeader.writeUInt16LE(8, 10);
  cdHeader.writeUInt16LE(0, 12);
  cdHeader.writeUInt16LE(0, 14);
  cdHeader.writeUInt32LE(crc >>> 0, 16);
  cdHeader.writeUInt32LE(compressed.length, 20);
  cdHeader.writeUInt32LE(contentBuffer.length, 24);
  cdHeader.writeUInt16LE(nameBuf.length, 28);
  cdHeader.writeUInt16LE(0, 30);
  cdHeader.writeUInt16LE(0, 32);
  cdHeader.writeUInt16LE(0, 34);
  cdHeader.writeUInt16LE(0, 36);
  cdHeader.writeUInt32LE(0, 38);
  cdHeader.writeUInt32LE(0, 42);
  nameBuf.copy(cdHeader, 46);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdHeader.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([localHeader, compressed, cdHeader, eocd]);
}

describe('rua-parser: streaming RUA XML / .gz / .zip, RUF rejection & OOM guard', () => {
  it('parses plain RUA XML accurately and identifies suspicious sources', async () => {
    const res = await parseRuaBuffer(Buffer.from(SAMPLE_RUA_XML, 'utf8'));
    assert.equal(res.metadata.orgName, 'google.com');
    assert.equal(res.policyPublished.domain, 'apexhive.example');
    assert.equal(res.totalMessages, 50);
    assert.equal(res.dmarcPass, 42);
    assert.equal(res.dmarcFail, 8);
    assert.equal(res.passRate, 84);
    assert.equal(res.suspiciousSources.length, 1);
    assert.equal(res.suspiciousSources[0].sourceIp, '198.51.100.77');
  });

  it('parses gzipped .xml.gz RUA reports', async () => {
    const gz = zlib.gzipSync(Buffer.from(SAMPLE_RUA_XML, 'utf8'));
    const res = await parseRuaBuffer(gz, { filenameHint: 'google.com!apexhive.example!1764028800!1764115199.xml.gz' });
    assert.equal(res.totalMessages, 50);
    assert.equal(res.dmarcPass, 42);
  });

  it('parses zipped .zip RUA reports without external dependencies', async () => {
    const zip = buildSingleFileZip('google.com!apexhive.example!1.xml', Buffer.from(SAMPLE_RUA_XML, 'utf8'));
    const res = await parseRuaBuffer(zip, { filenameHint: 'report.zip' });
    assert.equal(res.totalMessages, 50);
    assert.equal(res.dmarcFail, 8);
  });

  it('strictly rejects RUF forensic reports (payload and filename)', async () => {
    const rufPayload = `Feedback-Type: auth-failure\r\nUser-Agent: Mailer\r\nVersion: 1\r\nOriginal-Mail-From: victim@example.com\r\nArrival-Date: Thu, 26 Nov 2026 00:00:00 +0000\r\n`;
    await assert.rejects(
      () => parseRuaBuffer(Buffer.from(rufPayload, 'utf8')),
      (err) => err instanceof RufRejectedError
    );

    await assert.rejects(
      () => parseRuaBuffer(Buffer.from(SAMPLE_RUA_XML, 'utf8'), { filenameHint: 'mail!ruf!1234.xml' }),
      (err) => err instanceof RufRejectedError
    );
  });

  it('inspects full stream past 256B and rejects RUF markers or multi-entry ZIPs hiding RUF/oversized STORE', async () => {
    const padding = '<!-- ' + 'X'.repeat(600) + ' -->\n';
    const lateRufStream = Readable.from([
      padding.slice(0, 300),
      padding.slice(300) + '<feedback><forensic><sample_message>secret</sample_message></forensic></feedback>'
    ]);
    await assert.rejects(
      () => parseRuaXmlStream(lateRufStream),
      (err) => err instanceof RufRejectedError
    );

    const splitHeadersStream = Readable.from([
      'X-Header: 1\r\n' + 'A'.repeat(400) + '\r\nOriginal-Mail-From: a@b.com\r\n',
      'B'.repeat(700) + '\r\nArrival-Date: Thu, 26 Nov 2026 00:00:00 +0000\r\n'
    ]);
    await assert.rejects(
      () => parseRuaXmlStream(splitHeadersStream),
      (err) => err instanceof RufRejectedError
    );

    // Multi-file ZIP where entry #1 is valid RUA and entry #2 is hidden RUF
    const name1 = Buffer.from('valid.xml', 'utf8');
    const data1 = Buffer.from(SAMPLE_RUA_XML, 'utf8');
    const name2 = Buffer.from('hidden!ruf!2.xml', 'utf8');
    const data2 = Buffer.from('<feedback/>', 'utf8');
    const makeLocal = (n, d) => {
      const h = Buffer.alloc(30 + n.length);
      h.writeUInt32LE(0x04034b50, 0);
      h.writeUInt16LE(20, 4);
      h.writeUInt16LE(0, 8); // STORE
      h.writeUInt32LE(crc32(d), 14);
      h.writeUInt32LE(d.length, 18);
      h.writeUInt32LE(d.length, 22);
      h.writeUInt16LE(n.length, 26);
      n.copy(h, 30);
      return Buffer.concat([h, d]);
    };
    const multiZip = Buffer.concat([makeLocal(name1, data1), makeLocal(name2, data2)]);
    await assert.rejects(
      () => parseRuaBuffer(multiZip),
      (err) => err instanceof RufRejectedError
    );
    // Case-insensitive metadata/policy tags + multi-entry ZIP with corrupt 2nd deflate stream does not throw unhandled error
    const upperXml = SAMPLE_RUA_XML
      .replace(/<report_metadata>/g, '<REPORT_METADATA>')
      .replace(/<\/report_metadata>/g, '</REPORT_METADATA>')
      .replace(/<policy_published>/g, '<POLICY_PUBLISHED>')
      .replace(/<\/policy_published>/g, '</POLICY_PUBLISHED>');
    const upperRes = await parseRuaBuffer(Buffer.from(upperXml, 'utf8'));
    assert.equal(upperRes.metadata.orgName, 'google.com');
    assert.equal(upperRes.policyPublished.domain, 'apexhive.example');

    const badDeflateName = Buffer.from('corrupt.xml', 'utf8');
    const badDeflateData = Buffer.from([0xff, 0xff, 0xff, 0xff]);
    const hBad = Buffer.alloc(30 + badDeflateName.length);
    hBad.writeUInt32LE(0x04034b50, 0);
    hBad.writeUInt16LE(20, 4);
    hBad.writeUInt16LE(8, 8); // DEFLATE
    hBad.writeUInt32LE(badDeflateData.length, 18);
    hBad.writeUInt32LE(10, 22);
    hBad.writeUInt16LE(badDeflateName.length, 26);
    badDeflateName.copy(hBad, 30);
    const corruptMultiZip = Buffer.concat([makeLocal(name1, data1), hBad, badDeflateData]);
    await assert.rejects(() => parseRuaBuffer(corruptMultiZip));
  });

  it('enforces maxUncompressedBytes OOM / zip-bomb guard during streaming', async () => {
    const chunkedStream = Readable.from([
      '<feedback><report_metadata><org_name>test</org_name></report_metadata>',
      'A'.repeat(2048)
    ]);
    await assert.rejects(
      () => parseRuaXmlStream(chunkedStream, { maxUncompressedBytes: 512 }),
      (err) => err instanceof RuaLimitError
    );
  });

  it('escapes XSS payloads in zero-CDN standalone HTML report', async () => {
    const res = await parseRuaBuffer(Buffer.from(SAMPLE_RUA_XML, 'utf8'));
    const html = generateHtmlReport({
      rua: {
        reports: [res],
        rejectedFiles: [],
        totalMessages: res.totalMessages,
        dmarcPass: res.dmarcPass,
        dmarcFail: res.dmarcFail,
        passRate: res.passRate,
        suspiciousSources: res.suspiciousSources
      }
    });
    assert.ok(!html.includes('<script>alert(1)</script>'), 'Unescaped script tag found in HTML report');
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.ok(!html.includes('innerHTML'));
    assert.ok(!html.includes('https://cdn'));
  });

  it('streams chunked <record id="1"> elements with attributes incrementally', async () => {
    const chunks = [
      '<feedback><report_metadata><org_name>chunk.org</org_name></report_metadata>',
      '<policy_published><domain>stream.example</domain><p>reject</p></policy_published>',
      '<record id="1"><row><source_ip>192.0.2.10</source_ip><count>7</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>stream.example</header_from></identifiers></record>',
      '<RECORD id="2"><row><source_ip>192.0.2.11</source_ip><count>3</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>stream.example</header_from></identifiers></RECORD></feedback>'
    ];
    const res = await parseRuaXmlStream(Readable.from(chunks));
    assert.equal(res.totalMessages, 10);
    assert.equal(res.dmarcPass, 7);
    assert.equal(res.dmarcFail, 3);
  });
});
