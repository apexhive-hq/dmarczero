import { createReadStream } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';
import { matchMailProvider, type MailProviderCategory } from './providers.js';

export class RufRejectedError extends Error {
  constructor(message = 'RUF forensic reports are strictly rejected by DMARCZero privacy policy') {
    super(message);
    this.name = 'RufRejectedError';
  }
}

export class RuaLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuaLimitError';
  }
}

export interface RuaReportMetadata {
  orgName: string;
  email: string;
  reportId: string;
  dateRangeBegin: number;
  dateRangeEnd: number;
}

export interface RuaPolicyPublished {
  domain: string;
  adkim: string;
  aspf: string;
  p: string;
  sp: string;
  pct: number;
}

export interface RuaSourceSummary {
  sourceIp: string;
  headerFrom: string;
  providerId: string;
  provider: string;
  providerCategory: MailProviderCategory;
  totalCount: number;
  dmarcPass: number;
  dmarcFail: number;
  spfPass: number;
  dkimPass: number;
  dispositions: Record<string, number>;
  suspicious: boolean;
}

export interface RuaSummary {
  metadata: RuaReportMetadata;
  policyPublished: RuaPolicyPublished;
  totalMessages: number;
  dmarcPass: number;
  dmarcFail: number;
  spfPass: number;
  spfFail: number;
  dkimPass: number;
  dkimFail: number;
  passRate: number;
  sources: RuaSourceSummary[];
  suspiciousSources: RuaSourceSummary[];
}

export interface RuaParseOptions {
  maxUncompressedBytes?: number;
  filenameHint?: string;
}

export interface RuaDirectoryResult {
  reports: RuaSummary[];
  rejectedFiles: Array<{ file: string; reason: string }>;
  totalMessages: number;
  dmarcPass: number;
  dmarcFail: number;
  passRate: number;
  suspiciousSources: RuaSourceSummary[];
}

const DEFAULT_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024; // 50 MB zip-bomb / OOM guard

function decodeXmlEntities(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function extractTag(xml: string, tag: string): string {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const m = re.exec(xml);
  return m?.[1] ? decodeXmlEntities(m[1].trim()) : '';
}

function extractAllTags(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
  const results: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    if (m[1] !== undefined) results.push(m[1]);
  }
  return results;
}

export function isRufPayload(sample: string, filenameHint?: string): boolean {
  if (filenameHint) {
    const lowerName = filenameHint.toLowerCase();
    if (lowerName.includes('!ruf!') || lowerName.endsWith('.eml') || /(^|[._-])ruf([._-]|$)/.test(lowerName)) {
      return true;
    }
  }
  // ARF / RUF forensic mail headers or forensic XML tags
  if (/Feedback-Type:\s*auth-failure/i.test(sample)) return true;
  if (/Content-Type:\s*message\/feedback-report/i.test(sample)) return true;
  if (/Original-Mail-From:/i.test(sample) && /Arrival-Date:/i.test(sample)) return true;
  if (/<forensic[\s>]/i.test(sample) || /<auth_failure[\s>]/i.test(sample) || /<sample_message[\s>]/i.test(sample)) {
    return true;
  }
  return false;
}

/**
 * Constant-memory streaming parser for DMARC RUA XML streams.
 * Processes each <record>...</record> block incrementally and releases XML chunks immediately.
 */
export async function parseRuaXmlStream(
  stream: Readable,
  options: RuaParseOptions = {}
): Promise<RuaSummary> {
  const maxBytes = options.maxUncompressedBytes ?? DEFAULT_MAX_UNCOMPRESSED_BYTES;
  if (options.filenameHint && isRufPayload('', options.filenameHint)) {
    stream.destroy();
    throw new RufRejectedError(`Rejected RUF file based on filename: ${options.filenameHint}`);
  }

  let totalBytes = 0;
  let buffer = '';
  let checkedHeader = false;
  let sawFeedbackRoot = false;

  const metadata: RuaReportMetadata = {
    orgName: '',
    email: '',
    reportId: '',
    dateRangeBegin: 0,
    dateRangeEnd: 0
  };

  const policyPublished: RuaPolicyPublished = {
    domain: '',
    adkim: 'r',
    aspf: 'r',
    p: 'none',
    sp: '',
    pct: 100
  };

  let totalMessages = 0;
  let dmarcPass = 0;
  let dmarcFail = 0;
  let spfPass = 0;
  let spfFail = 0;
  let dkimPass = 0;
  let dkimFail = 0;

  const sourceMap = new Map<string, RuaSourceSummary>();

  const processRecordBlock = (recXml: string) => {
    const rowXml = extractTag(recXml, 'row');
    const sourceIp = extractTag(rowXml || recXml, 'source_ip') || 'unknown';
    const countRaw = extractTag(rowXml || recXml, 'count');
    const count = Math.max(0, Number.parseInt(countRaw || '0', 10) || 0);

    const policyEval = extractTag(rowXml || recXml, 'policy_evaluated');
    const disposition = (extractTag(policyEval, 'disposition') || 'none').toLowerCase();
    const evalDkim = (extractTag(policyEval, 'dkim') || 'fail').toLowerCase();
    const evalSpf = (extractTag(policyEval, 'spf') || 'fail').toLowerCase();

    const identifiersXml = extractTag(recXml, 'identifiers');
    const headerFrom = extractTag(identifiersXml || recXml, 'header_from') || policyPublished.domain || 'unknown';

    const authHints: string[] = [];
    const authXml = extractTag(recXml, 'auth_results');
    if (authXml) {
      for (const dkimBlock of extractAllTags(authXml, 'dkim')) {
        if ((extractTag(dkimBlock, 'result') || '').toLowerCase() === 'pass') {
          const dom = extractTag(dkimBlock, 'domain');
          if (dom) authHints.push(dom);
        }
      }
      for (const spfBlock of extractAllTags(authXml, 'spf')) {
        if ((extractTag(spfBlock, 'result') || '').toLowerCase() === 'pass') {
          const dom = extractTag(spfBlock, 'domain');
          if (dom) authHints.push(dom);
        }
      }
    }

    const isSpfPass = evalSpf === 'pass';
    const isDkimPass = evalDkim === 'pass';
    const isDmarcPass = isSpfPass || isDkimPass;

    totalMessages += count;
    if (isDmarcPass) dmarcPass += count;
    else dmarcFail += count;
    if (isSpfPass) spfPass += count;
    else spfFail += count;
    if (isDkimPass) dkimPass += count;
    else dkimFail += count;

    const key = `${sourceIp}|${headerFrom.toLowerCase()}`;
    let entry = sourceMap.get(key);
    if (!entry) {
      const matched = matchMailProvider(sourceIp, authHints);
      entry = {
        sourceIp,
        headerFrom,
        providerId: matched.providerId,
        provider: matched.provider,
        providerCategory: matched.category,
        totalCount: 0,
        dmarcPass: 0,
        dmarcFail: 0,
        spfPass: 0,
        dkimPass: 0,
        dispositions: {},
        suspicious: false
      };
      sourceMap.set(key, entry);
    }

    entry.totalCount += count;
    if (isDmarcPass) entry.dmarcPass += count;
    else entry.dmarcFail += count;
    if (isSpfPass) entry.spfPass += count;
    if (isDkimPass) entry.dkimPass += count;
    entry.dispositions[disposition] = (entry.dispositions[disposition] ?? 0) + count;
    if (!isDmarcPass || disposition === 'quarantine' || disposition === 'reject') {
      entry.suspicious = true;
    }
  };

  for await (const rawChunk of stream) {
    const chunkBuf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(String(rawChunk), 'utf8');
    totalBytes += chunkBuf.length;
    if (totalBytes > maxBytes) {
      stream.destroy();
      throw new RuaLimitError(`Uncompressed RUA XML exceeds safety limit of ${maxBytes} bytes`);
    }

    buffer += chunkBuf.toString('utf8');

    if (!checkedHeader && buffer.length >= 256) {
      checkedHeader = true;
      if (isRufPayload(buffer)) {
        stream.destroy();
        throw new RufRejectedError();
      }
    }

    if (!sawFeedbackRoot && /<feedback[\s>]/i.test(buffer)) {
      sawFeedbackRoot = true;
    }

    // Extract report_metadata once complete
    const metaEnd = buffer.indexOf('</report_metadata>');
    if (metaEnd !== -1) {
      const metaStart = buffer.indexOf('<report_metadata');
      if (metaStart !== -1 && metaStart < metaEnd) {
        const metaXml = buffer.slice(metaStart, metaEnd + '</report_metadata>'.length);
        metadata.orgName = extractTag(metaXml, 'org_name');
        metadata.email = extractTag(metaXml, 'email');
        metadata.reportId = extractTag(metaXml, 'report_id');
        metadata.dateRangeBegin = Number.parseInt(extractTag(metaXml, 'begin') || '0', 10) || 0;
        metadata.dateRangeEnd = Number.parseInt(extractTag(metaXml, 'end') || '0', 10) || 0;
        buffer = buffer.slice(0, metaStart) + buffer.slice(metaEnd + '</report_metadata>'.length);
      }
    }

    // Extract policy_published once complete
    const polEnd = buffer.indexOf('</policy_published>');
    if (polEnd !== -1) {
      const polStart = buffer.indexOf('<policy_published');
      if (polStart !== -1 && polStart < polEnd) {
        const polXml = buffer.slice(polStart, polEnd + '</policy_published>'.length);
        policyPublished.domain = extractTag(polXml, 'domain');
        policyPublished.adkim = extractTag(polXml, 'adkim') || 'r';
        policyPublished.aspf = extractTag(polXml, 'aspf') || 'r';
        policyPublished.p = extractTag(polXml, 'p') || 'none';
        policyPublished.sp = extractTag(polXml, 'sp') || policyPublished.p;
        const pctVal = Number.parseInt(extractTag(polXml, 'pct') || '100', 10);
        policyPublished.pct = Number.isFinite(pctVal) ? pctVal : 100;
        buffer = buffer.slice(0, polStart) + buffer.slice(polEnd + '</policy_published>'.length);
      }
    }

    // Incrementally consume all complete <record ...>...</record> blocks (case-insensitive, supports attributes)
    while (true) {
      const startMatch = /<record(?:\s[^>]*)?>/i.exec(buffer);
      if (!startMatch) break;
      const recStart = startMatch.index;
      const endMatch = /<\/record>/i.exec(buffer.slice(recStart));
      if (!endMatch) break;
      const recEnd = recStart + endMatch.index + endMatch[0].length;
      const recXml = buffer.slice(recStart, recEnd);
      processRecordBlock(recXml);
      buffer = buffer.slice(recEnd);
    }

    // Prevent unbounded buffer growth if malformed input lacks closing tags
    if (buffer.length > 4 * 1024 * 1024) {
      stream.destroy();
      throw new RuaLimitError('Malformed RUA XML: single record exceeded 4MB streaming window');
    }
  }

  // Final check on short files
  if (isRufPayload(buffer)) {
    throw new RufRejectedError();
  }

  // Drain any remaining tags in buffer
  if (!metadata.orgName && buffer.includes('</report_metadata>')) {
    const metaXml = extractTag(buffer, 'report_metadata');
    metadata.orgName = extractTag(metaXml, 'org_name');
    metadata.email = extractTag(metaXml, 'email');
    metadata.reportId = extractTag(metaXml, 'report_id');
    metadata.dateRangeBegin = Number.parseInt(extractTag(metaXml, 'begin') || '0', 10) || 0;
    metadata.dateRangeEnd = Number.parseInt(extractTag(metaXml, 'end') || '0', 10) || 0;
  }
  if (!policyPublished.domain && buffer.includes('</policy_published>')) {
    const polXml = extractTag(buffer, 'policy_published');
    policyPublished.domain = extractTag(polXml, 'domain');
    policyPublished.adkim = extractTag(polXml, 'adkim') || 'r';
    policyPublished.aspf = extractTag(polXml, 'aspf') || 'r';
    policyPublished.p = extractTag(polXml, 'p') || 'none';
    policyPublished.sp = extractTag(polXml, 'sp') || policyPublished.p;
    const pctVal = Number.parseInt(extractTag(polXml, 'pct') || '100', 10);
    policyPublished.pct = Number.isFinite(pctVal) ? pctVal : 100;
  }
  for (const recXml of extractAllTags(buffer, 'record')) {
    processRecordBlock(recXml);
  }

  if (!sawFeedbackRoot && !/<feedback[\s>]/i.test(buffer) && totalMessages === 0 && !policyPublished.domain) {
    throw new Error('Invalid DMARC RUA XML: missing <feedback> root element');
  }

  const sources = [...sourceMap.values()].sort((a, b) => b.totalCount - a.totalCount);
  const suspiciousSources = sources.filter((s) => s.suspicious);
  const passRate = totalMessages > 0 ? Number(((dmarcPass / totalMessages) * 100).toFixed(2)) : 0;

  return {
    metadata,
    policyPublished,
    totalMessages,
    dmarcPass,
    dmarcFail,
    spfPass,
    spfFail,
    dkimPass,
    dkimFail,
    passRate,
    sources,
    suspiciousSources
  };
}

/**
 * Zero-dependency ZIP extractor for single-entry RUA .zip archives (supports store=0 and deflate=8).
 */
export function extractFirstZipEntryStream(zipBuffer: Buffer, maxUncompressedBytes = DEFAULT_MAX_UNCOMPRESSED_BYTES): {
  filename: string;
  stream: Readable;
} {
  // Check local file header signature PK\x03\x04
  if (zipBuffer.length < 30 || zipBuffer.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('Invalid ZIP archive header');
  }

  const flags = zipBuffer.readUInt16LE(6);
  const compressionMethod = zipBuffer.readUInt16LE(8);
  let compressedSize = zipBuffer.readUInt32LE(18);
  let uncompressedSize = zipBuffer.readUInt32LE(22);
  const fileNameLength = zipBuffer.readUInt16LE(26);
  const extraFieldLength = zipBuffer.readUInt16LE(28);
  const filename = zipBuffer.subarray(30, 30 + fileNameLength).toString('utf8');
  const dataOffset = 30 + fileNameLength + extraFieldLength;

  // If data descriptor bit (bit 3) is set, locate central directory to get exact sizes
  if ((flags & 0x0008) !== 0 || compressedSize === 0) {
    const eocdSig = 0x06054b50;
    let eocdOffset = -1;
    for (let i = zipBuffer.length - 22; i >= Math.max(0, zipBuffer.length - 65557); i--) {
      if (zipBuffer.readUInt32LE(i) === eocdSig) {
        eocdOffset = i;
        break;
      }
    }
    if (eocdOffset !== -1) {
      const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
      if (cdOffset + 46 <= zipBuffer.length && zipBuffer.readUInt32LE(cdOffset) === 0x02014b50) {
        compressedSize = zipBuffer.readUInt32LE(cdOffset + 20);
        uncompressedSize = zipBuffer.readUInt32LE(cdOffset + 24);
      }
    }
  }

  if (uncompressedSize > maxUncompressedBytes) {
    throw new RuaLimitError(`ZIP entry uncompressed size (${uncompressedSize}) exceeds limit (${maxUncompressedBytes})`);
  }

  const compressedData = compressedSize > 0
    ? zipBuffer.subarray(dataOffset, dataOffset + compressedSize)
    : zipBuffer.subarray(dataOffset);

  if (compressionMethod === 0) {
    return { filename, stream: Readable.from(compressedData) };
  }
  if (compressionMethod === 8) {
    const inflate = zlib.createInflateRaw();
    Readable.from(compressedData).pipe(inflate);
    return { filename, stream: inflate };
  }
  throw new Error(`Unsupported ZIP compression method: ${compressionMethod}`);
}

export async function parseRuaBuffer(data: Buffer, options: RuaParseOptions = {}): Promise<RuaSummary> {
  const maxBytes = options.maxUncompressedBytes ?? DEFAULT_MAX_UNCOMPRESSED_BYTES;
  if (options.filenameHint && isRufPayload('', options.filenameHint)) {
    throw new RufRejectedError(`Rejected RUF file: ${options.filenameHint}`);
  }

  // Gzip magic bytes: 1f 8b
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) {
    const gunzip = zlib.createGunzip();
    Readable.from(data).pipe(gunzip);
    return parseRuaXmlStream(gunzip, { ...options, maxUncompressedBytes: maxBytes });
  }

  // ZIP magic bytes: 50 4b 03 04
  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b && data[2] === 0x03 && data[3] === 0x04) {
    const { filename, stream } = extractFirstZipEntryStream(data, maxBytes);
    return parseRuaXmlStream(stream, { ...options, filenameHint: filename, maxUncompressedBytes: maxBytes });
  }

  // Plain XML
  return parseRuaXmlStream(Readable.from(data), { ...options, maxUncompressedBytes: maxBytes });
}

export async function parseRuaFile(filePath: string, options: RuaParseOptions = {}): Promise<RuaSummary> {
  const filename = path.basename(filePath);
  const lower = filename.toLowerCase();
  if (isRufPayload('', filename)) {
    throw new RufRejectedError(`Rejected RUF file: ${filename}`);
  }

  const maxBytes = options.maxUncompressedBytes ?? DEFAULT_MAX_UNCOMPRESSED_BYTES;

  if (lower.endsWith('.gz')) {
    const fileStream = createReadStream(filePath);
    const gunzip = zlib.createGunzip();
    fileStream.pipe(gunzip);
    return parseRuaXmlStream(gunzip, { ...options, filenameHint: filename, maxUncompressedBytes: maxBytes });
  }

  if (lower.endsWith('.zip')) {
    const chunks: Buffer[] = [];
    for await (const chunk of createReadStream(filePath)) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return parseRuaBuffer(Buffer.concat(chunks), { ...options, filenameHint: filename, maxUncompressedBytes: maxBytes });
  }

  return parseRuaXmlStream(createReadStream(filePath), { ...options, filenameHint: filename, maxUncompressedBytes: maxBytes });
}

export async function parseRuaPath(targetPath: string, options: RuaParseOptions = {}): Promise<RuaDirectoryResult> {
  const info = await stat(targetPath);
  const files: string[] = [];

  if (info.isFile()) {
    files.push(targetPath);
  } else if (info.isDirectory()) {
    const entries = await readdir(targetPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        if (lower.endsWith('.xml') || lower.endsWith('.gz') || lower.endsWith('.zip') || lower.endsWith('.eml')) {
          files.push(path.join(targetPath, entry.name));
        }
      }
    }
    files.sort();
  }

  const reports: RuaSummary[] = [];
  const rejectedFiles: Array<{ file: string; reason: string }> = [];

  for (const file of files) {
    try {
      const summary = await parseRuaFile(file, options);
      reports.push(summary);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      rejectedFiles.push({ file: path.basename(file), reason: msg });
    }
  }

  const totalMessages = reports.reduce((acc, r) => acc + r.totalMessages, 0);
  const dmarcPass = reports.reduce((acc, r) => acc + r.dmarcPass, 0);
  const dmarcFail = reports.reduce((acc, r) => acc + r.dmarcFail, 0);
  const passRate = totalMessages > 0 ? Number(((dmarcPass / totalMessages) * 100).toFixed(2)) : 0;

  const mergedSuspicious = new Map<string, RuaSourceSummary>();
  for (const r of reports) {
    for (const s of r.suspiciousSources) {
      const key = `${s.sourceIp}|${s.headerFrom.toLowerCase()}`;
      const existing = mergedSuspicious.get(key);
      if (!existing) {
        mergedSuspicious.set(key, { ...s, dispositions: { ...s.dispositions } });
      } else {
        existing.totalCount += s.totalCount;
        existing.dmarcPass += s.dmarcPass;
        existing.dmarcFail += s.dmarcFail;
        existing.spfPass += s.spfPass;
        existing.dkimPass += s.dkimPass;
        for (const [disp, cnt] of Object.entries(s.dispositions)) {
          existing.dispositions[disp] = (existing.dispositions[disp] ?? 0) + cnt;
        }
      }
    }
  }

  return {
    reports,
    rejectedFiles,
    totalMessages,
    dmarcPass,
    dmarcFail,
    passRate,
    suspiciousSources: [...mergedSuspicious.values()].sort((a, b) => b.dmarcFail - a.dmarcFail)
  };
}
