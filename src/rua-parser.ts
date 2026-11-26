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
const MAX_ZIP_ENTRIES = 64;

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
 * Continuously inspects the full stream for RUF PII indicators and processes each <record> block incrementally.
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
  let rufTail = '';
  let sawOriginalMailFrom = false;
  let sawArrivalDate = false;
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

  const inspectChunkForRuf = (chunkStr: string) => {
    const windowText = rufTail + chunkStr;
    if (/Original-Mail-From:/i.test(windowText)) sawOriginalMailFrom = true;
    if (/Arrival-Date:/i.test(windowText)) sawArrivalDate = true;
    if ((sawOriginalMailFrom && sawArrivalDate) || isRufPayload(windowText)) {
      stream.destroy();
      throw new RufRejectedError();
    }
    rufTail = windowText.slice(-512);
  };

  const processRecordBlock = (recXml: string) => {
    if (isRufPayload(recXml)) {
      throw new RufRejectedError();
    }

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

    const chunkStr = chunkBuf.toString('utf8');
    inspectChunkForRuf(chunkStr);
    buffer += chunkStr;

    if (!sawFeedbackRoot && /<feedback[\s>]/i.test(buffer)) {
      sawFeedbackRoot = true;
    }

    // Extract report_metadata once complete (case-insensitive)
    const metaEndMatch = /<\/report_metadata>/i.exec(buffer);
    if (metaEndMatch) {
      const metaStartMatch = /<report_metadata(?:\s[^>]*)?>/i.exec(buffer);
      if (metaStartMatch && metaStartMatch.index < metaEndMatch.index) {
        const metaEndIdx = metaEndMatch.index + metaEndMatch[0].length;
        const metaXml = buffer.slice(metaStartMatch.index, metaEndIdx);
        metadata.orgName = extractTag(metaXml, 'org_name');
        metadata.email = extractTag(metaXml, 'email');
        metadata.reportId = extractTag(metaXml, 'report_id');
        metadata.dateRangeBegin = Number.parseInt(extractTag(metaXml, 'begin') || '0', 10) || 0;
        metadata.dateRangeEnd = Number.parseInt(extractTag(metaXml, 'end') || '0', 10) || 0;
        buffer = buffer.slice(0, metaStartMatch.index) + buffer.slice(metaEndIdx);
      }
    }

    // Extract policy_published once complete (case-insensitive)
    const polEndMatch = /<\/policy_published>/i.exec(buffer);
    if (polEndMatch) {
      const polStartMatch = /<policy_published(?:\s[^>]*)?>/i.exec(buffer);
      if (polStartMatch && polStartMatch.index < polEndMatch.index) {
        const polEndIdx = polEndMatch.index + polEndMatch[0].length;
        const polXml = buffer.slice(polStartMatch.index, polEndIdx);
        policyPublished.domain = extractTag(polXml, 'domain');
        policyPublished.adkim = extractTag(polXml, 'adkim') || 'r';
        policyPublished.aspf = extractTag(polXml, 'aspf') || 'r';
        policyPublished.p = extractTag(polXml, 'p') || 'none';
        policyPublished.sp = extractTag(polXml, 'sp') || policyPublished.p;
        const pctVal = Number.parseInt(extractTag(polXml, 'pct') || '100', 10);
        policyPublished.pct = Number.isFinite(pctVal) ? pctVal : 100;
        buffer = buffer.slice(0, polStartMatch.index) + buffer.slice(polEndIdx);
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

  // Final check on remaining buffer
  if (isRufPayload(buffer)) {
    throw new RufRejectedError();
  }

  // Drain any remaining tags in buffer
  if (!metadata.orgName && /<\/report_metadata>/i.test(buffer)) {
    const metaXml = extractTag(buffer, 'report_metadata');
    metadata.orgName = extractTag(metaXml, 'org_name');
    metadata.email = extractTag(metaXml, 'email');
    metadata.reportId = extractTag(metaXml, 'report_id');
    metadata.dateRangeBegin = Number.parseInt(extractTag(metaXml, 'begin') || '0', 10) || 0;
    metadata.dateRangeEnd = Number.parseInt(extractTag(metaXml, 'end') || '0', 10) || 0;
  }
  if (!policyPublished.domain && /<\/policy_published>/i.test(buffer)) {
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

interface ZipEntrySpec {
  filename: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  dataOffset: number;
}

function findEocdOffset(zipBuffer: Buffer): number {
  const eocdSig = 0x06054b50;
  for (let i = zipBuffer.length - 22; i >= Math.max(0, zipBuffer.length - 65557); i--) {
    if (zipBuffer.readUInt32LE(i) === eocdSig) {
      return i;
    }
  }
  return -1;
}

function collectZipEntriesFromCentralDirectory(zipBuffer: Buffer, eocdOffset: number): ZipEntrySpec[] {
  const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
  if (totalEntries > MAX_ZIP_ENTRIES) {
    throw new RuaLimitError(`ZIP archive contains too many entries (${totalEntries} > ${MAX_ZIP_ENTRIES})`);
  }
  const cdSize = zipBuffer.readUInt32LE(eocdOffset + 12);
  const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);
  if (cdOffset + cdSize > zipBuffer.length) {
    throw new Error('Corrupt ZIP central directory bounds');
  }

  const entries: ZipEntrySpec[] = [];
  let pos = cdOffset;

  for (let idx = 0; idx < totalEntries; idx++) {
    if (pos + 46 > zipBuffer.length || zipBuffer.readUInt32LE(pos) !== 0x02014b50) {
      throw new Error('Invalid ZIP central directory entry');
    }
    const compressionMethod = zipBuffer.readUInt16LE(pos + 10);
    const compressedSize = zipBuffer.readUInt32LE(pos + 20);
    const uncompressedSize = zipBuffer.readUInt32LE(pos + 24);
    const nameLen = zipBuffer.readUInt16LE(pos + 28);
    const extraLen = zipBuffer.readUInt16LE(pos + 30);
    const commentLen = zipBuffer.readUInt16LE(pos + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(pos + 42);

    if (pos + 46 + nameLen > zipBuffer.length) {
      throw new Error('Corrupt ZIP central directory filename bounds');
    }
    const filename = zipBuffer.subarray(pos + 46, pos + 46 + nameLen).toString('utf8');

    if (localHeaderOffset + 30 > zipBuffer.length || zipBuffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
      throw new Error(`Invalid ZIP local header for entry: ${filename}`);
    }
    const localNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
    const dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;

    entries.push({
      filename,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      dataOffset
    });

    pos += 46 + nameLen + extraLen + commentLen;
  }

  return entries;
}

function collectZipEntriesFromLocalHeaders(zipBuffer: Buffer): ZipEntrySpec[] {
  const entries: ZipEntrySpec[] = [];
  let pos = 0;

  while (pos + 30 <= zipBuffer.length && zipBuffer.readUInt32LE(pos) === 0x04034b50) {
    if (entries.length >= MAX_ZIP_ENTRIES) {
      throw new RuaLimitError(`ZIP archive exceeds max entries (${MAX_ZIP_ENTRIES})`);
    }
    const flags = zipBuffer.readUInt16LE(pos + 6);
    if ((flags & 0x0008) !== 0) {
      throw new Error('ZIP entry uses data descriptor without central directory');
    }
    const compressionMethod = zipBuffer.readUInt16LE(pos + 8);
    const compressedSize = zipBuffer.readUInt32LE(pos + 18);
    const uncompressedSize = zipBuffer.readUInt32LE(pos + 22);
    const nameLen = zipBuffer.readUInt16LE(pos + 26);
    const extraLen = zipBuffer.readUInt16LE(pos + 28);
    const dataOffset = pos + 30 + nameLen + extraLen;
    if (dataOffset > zipBuffer.length) {
      throw new Error('Corrupt ZIP local header bounds');
    }
    const filename = zipBuffer.subarray(pos + 30, pos + 30 + nameLen).toString('utf8');
    entries.push({
      filename,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      dataOffset
    });
    pos = dataOffset + compressedSize;
  }

  return entries;
}

/**
 * Zero-dependency multi-entry ZIP extractor for RUA .zip archives (supports store=0 and deflate=8).
 * Inspects ALL entries for RUF filenames and cumulative uncompressed byte caps.
 */
export function extractAllZipEntryStreams(
  zipBuffer: Buffer,
  maxUncompressedBytes = DEFAULT_MAX_UNCOMPRESSED_BYTES
): Array<{
  filename: string;
  uncompressedSize: number;
  stream: Readable;
}> {
  if (zipBuffer.length < 30 || zipBuffer.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('Invalid ZIP archive header');
  }

  const eocdOffset = findEocdOffset(zipBuffer);
  const specs = eocdOffset !== -1
    ? collectZipEntriesFromCentralDirectory(zipBuffer, eocdOffset)
    : collectZipEntriesFromLocalHeaders(zipBuffer);

  if (specs.length === 0) {
    throw new Error('ZIP archive contains no entries');
  }

  const out: Array<{ filename: string; uncompressedSize: number; stream: Readable }> = [];
  let declaredTotal = 0;

  for (const spec of specs) {
    if (isRufPayload('', spec.filename)) {
      throw new RufRejectedError(`Rejected RUF entry in ZIP archive: ${spec.filename}`);
    }
    if (spec.uncompressedSize > maxUncompressedBytes || declaredTotal + spec.uncompressedSize > maxUncompressedBytes) {
      throw new RuaLimitError(
        `ZIP entry "${spec.filename}" uncompressed size (${spec.uncompressedSize}) exceeds limit (${maxUncompressedBytes})`
      );
    }
    if (spec.filename.endsWith('/') && spec.compressedSize === 0 && spec.uncompressedSize === 0) {
      continue;
    }
    if (spec.dataOffset + spec.compressedSize > zipBuffer.length) {
      throw new Error(`ZIP entry "${spec.filename}" is truncated`);
    }

    const slice = zipBuffer.subarray(spec.dataOffset, spec.dataOffset + spec.compressedSize);

    if (spec.compressionMethod === 0) {
      if (slice.length > maxUncompressedBytes || declaredTotal + slice.length > maxUncompressedBytes) {
        throw new RuaLimitError(
          `ZIP STORE entry "${spec.filename}" size (${slice.length}) exceeds limit (${maxUncompressedBytes})`
        );
      }
      declaredTotal += slice.length;
      out.push({ filename: spec.filename, uncompressedSize: slice.length, stream: Readable.from(slice) });
    } else if (spec.compressionMethod === 8) {
      declaredTotal += spec.uncompressedSize;
      const inflate = zlib.createInflateRaw();
      const src = Readable.from(slice);
      src.on('error', (err) => inflate.destroy(err));
      src.pipe(inflate);
      out.push({ filename: spec.filename, uncompressedSize: spec.uncompressedSize, stream: inflate });
    } else {
      throw new Error(`Unsupported ZIP compression method: ${spec.compressionMethod}`);
    }
  }

  return out;
}

export function extractFirstZipEntryStream(zipBuffer: Buffer, maxUncompressedBytes = DEFAULT_MAX_UNCOMPRESSED_BYTES): {
  filename: string;
  stream: Readable;
} {
  const entries = extractAllZipEntryStreams(zipBuffer, maxUncompressedBytes);
  const first = entries[0];
  if (!first) {
    throw new Error('ZIP archive contains no readable file entries');
  }
  return { filename: first.filename, stream: first.stream };
}

function mergeRuaSummaries(summaries: RuaSummary[]): RuaSummary {
  const first = summaries[0]!;
  if (summaries.length === 1) return first;

  let totalMessages = 0;
  let dmarcPass = 0;
  let dmarcFail = 0;
  let spfPass = 0;
  let spfFail = 0;
  let dkimPass = 0;
  let dkimFail = 0;
  const sourceMap = new Map<string, RuaSourceSummary>();

  for (const s of summaries) {
    totalMessages += s.totalMessages;
    dmarcPass += s.dmarcPass;
    dmarcFail += s.dmarcFail;
    spfPass += s.spfPass;
    spfFail += s.spfFail;
    dkimPass += s.dkimPass;
    dkimFail += s.dkimFail;

    for (const src of s.sources) {
      const key = `${src.sourceIp}|${src.headerFrom.toLowerCase()}`;
      const existing = sourceMap.get(key);
      if (!existing) {
        sourceMap.set(key, { ...src, dispositions: { ...src.dispositions } });
      } else {
        existing.totalCount += src.totalCount;
        existing.dmarcPass += src.dmarcPass;
        existing.dmarcFail += src.dmarcFail;
        existing.spfPass += src.spfPass;
        existing.dkimPass += src.dkimPass;
        existing.suspicious = existing.suspicious || src.suspicious;
        for (const [disp, cnt] of Object.entries(src.dispositions)) {
          existing.dispositions[disp] = (existing.dispositions[disp] ?? 0) + cnt;
        }
      }
    }
  }

  const sources = [...sourceMap.values()].sort((a, b) => b.totalCount - a.totalCount);
  const suspiciousSources = sources.filter((s) => s.suspicious);
  const passRate = totalMessages > 0 ? Number(((dmarcPass / totalMessages) * 100).toFixed(2)) : 0;

  return {
    metadata: first.metadata,
    policyPublished: first.policyPublished,
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
    const entries = extractAllZipEntryStreams(data, maxBytes);
    const entryErrors = new Map<Readable, Error>();
    const errorHandlers = new Map<Readable, (err: Error) => void>();
    for (const entry of entries) {
      const handler = (err: Error) => {
        entryErrors.set(entry.stream, err);
      };
      errorHandlers.set(entry.stream, handler);
      entry.stream.on('error', handler);
    }

    const summaries: RuaSummary[] = [];
    let cumulativeBudget = maxBytes;

    for (const entry of entries) {
      const preErr = entryErrors.get(entry.stream);
      if (preErr) {
        for (const other of entries) other.stream.destroy();
        throw preErr;
      }

      let actualEntryBytes = 0;
      const counted = new Readable({
        read() {}
      });
      const existingHandler = errorHandlers.get(entry.stream);
      if (existingHandler) entry.stream.off('error', existingHandler);
      entry.stream.on('error', (err) => counted.destroy(err));
      entry.stream.on('data', (chunk: Buffer) => {
        actualEntryBytes += chunk.length;
        if (actualEntryBytes > cumulativeBudget) {
          const limitErr = new RuaLimitError(`Uncompressed ZIP entries exceed safety limit of ${maxBytes} bytes`);
          entry.stream.destroy(limitErr);
          counted.destroy(limitErr);
          return;
        }
        counted.push(chunk);
      });
      entry.stream.on('end', () => counted.push(null));

      const summary = await parseRuaXmlStream(counted, {
        ...options,
        filenameHint: entry.filename,
        maxUncompressedBytes: cumulativeBudget
      });
      cumulativeBudget -= actualEntryBytes;
      summaries.push(summary);
    }

    return mergeRuaSummaries(summaries);
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
    const maxCompressedBytes = maxBytes;
    const fileInfo = await stat(filePath);
    if (fileInfo.size > maxCompressedBytes) {
      throw new RuaLimitError(`ZIP file size (${fileInfo.size} bytes) exceeds safety limit of ${maxCompressedBytes} bytes`);
    }
    const chunks: Buffer[] = [];
    let totalZipBytes = 0;
    const stream = createReadStream(filePath);
    for await (const chunk of stream) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalZipBytes += buf.length;
      if (totalZipBytes > maxCompressedBytes) {
        stream.destroy();
        throw new RuaLimitError(`ZIP file stream exceeds safety limit of ${maxCompressedBytes} bytes`);
      }
      chunks.push(buf);
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
