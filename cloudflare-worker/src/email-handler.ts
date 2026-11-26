import { matchMailProvider, type MailProviderCategory } from './providers.js';

export interface WorkerRuaSource {
  sourceIp: string;
  headerFrom: string;
  providerId: string;
  provider: string;
  providerCategory: MailProviderCategory;
  totalCount: number;
  dmarcPass: number;
  dmarcFail: number;
  suspicious: boolean;
}

export interface WorkerRuaSummary {
  reportId: string;
  orgName: string;
  domain: string;
  policy: string;
  dateRangeBegin: number;
  dateRangeEnd: number;
  totalMessages: number;
  dmarcPass: number;
  dmarcFail: number;
  passRate: number;
  sources: WorkerRuaSource[];
  suspiciousSources: Array<{
    sourceIp: string;
    headerFrom: string;
    providerId: string;
    provider: string;
    totalCount: number;
    dmarcFail: number;
  }>;
  receivedAt: string;
}

export interface EmailIngestResult {
  accepted: boolean;
  rejectedReason?: string;
  reports: WorkerRuaSummary[];
}

export class WorkerRufRejectedError extends Error {
  constructor(message = 'RUF forensic reports are strictly rejected by DMARCZero privacy policy') {
    super(message);
    this.name = 'WorkerRufRejectedError';
  }
}

export const MAX_UNCOMPRESSED_BYTES = 15 * 1024 * 1024; // 15 MB Worker safety limit
export const MAX_EMAIL_RAW_BYTES = 25 * 1024 * 1024; // 25 MB raw MIME safety limit
const MAX_ZIP_ENTRIES = 64;
const MAX_MIME_DEPTH = 8;
export const MAX_MIME_PARTS = 64;

/**
 * Reads an incoming Email Worker ReadableStream up to maxBytes without loading unbounded payloads into memory.
 */
export async function readBoundedEmailStream(
  raw: ReadableStream<Uint8Array>,
  rawSize?: number,
  maxBytes = MAX_EMAIL_RAW_BYTES
): Promise<string> {
  if (typeof rawSize === 'number' && rawSize > maxBytes) {
    throw new Error(`Incoming email rawSize (${rawSize} bytes) exceeds ${maxBytes} byte safety limit`);
  }

  const reader = raw.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new Error(`Incoming email stream exceeds ${maxBytes} byte safety limit`);
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

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

export function isRufIndicator(text: string, filename?: string): boolean {
  if (filename) {
    const lower = filename.toLowerCase();
    if (lower.includes('!ruf!') || lower.endsWith('.eml') || /(^|[._-])ruf([._-]|$)/.test(lower)) {
      return true;
    }
  }
  if (/Feedback-Type:\s*auth-failure/i.test(text)) return true;
  if (/Content-Type:\s*message\/feedback-report/i.test(text)) return true;
  if (/Original-Mail-From:/i.test(text) && /Arrival-Date:/i.test(text)) return true;
  if (/<forensic[\s>]/i.test(text) || /<auth_failure[\s>]/i.test(text) || /<sample_message[\s>]/i.test(text)) {
    return true;
  }
  return false;
}

function estimateBase64DecodedBytes(rawB64: string, maxBytes: number): { clean: string; estimatedBytes: number } {
  // Reject huge raw bodies before allocating a stripped copy
  if (rawB64.length > maxBytes * 2 + 1024) {
    throw new Error(`Base64 attachment exceeds ${maxBytes} byte safety limit`);
  }
  const clean = rawB64.replace(/\s+/g, '');
  let padding = 0;
  if (clean.endsWith('==')) padding = 2;
  else if (clean.endsWith('=')) padding = 1;
  const estimatedBytes = Math.max(0, Math.floor((clean.length * 3) / 4) - padding);
  if (estimatedBytes > maxBytes) {
    throw new Error(`Base64 decoded attachment (~${estimatedBytes} bytes) exceeds ${maxBytes} byte limit`);
  }
  return { clean, estimatedBytes };
}

function decodeBase64ToBytes(cleanB64: string): Uint8Array {
  const bin = atob(cleanB64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Decompresses gzip or deflate-raw bytes while reading and writing concurrently
 * so Web Streams never deadlock on internal backpressure buffers.
 */
async function decompressStreamBytes(
  input: Uint8Array,
  format: 'gzip' | 'deflate-raw',
  maxBytes = MAX_UNCOMPRESSED_BYTES
): Promise<Uint8Array> {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();

  const writePromise = writer
    .write(input as unknown as BufferSource)
    .then(() => writer.close());

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          const limitErr = new Error(`Decompressed RUA payload exceeds ${maxBytes} bytes`);
          await reader.cancel().catch(() => {});
          await writer.abort(limitErr).catch(() => {});
          await writePromise.catch(() => {});
          throw limitErr;
        }
        chunks.push(value);
      }
    }
    await writePromise;
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return merged;
}

interface ZipEntrySpec {
  filename: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  dataOffset: number;
}

function findEocdOffset(zipBytes: Uint8Array, view: DataView): number {
  for (let i = zipBytes.byteLength - 22; i >= Math.max(0, zipBytes.byteLength - 65557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      return i;
    }
  }
  return -1;
}

function collectZipEntriesFromCentralDirectory(
  zipBytes: Uint8Array,
  view: DataView,
  eocdOffset: number
): ZipEntrySpec[] {
  const totalEntries = view.getUint16(eocdOffset + 10, true);
  if (totalEntries > MAX_ZIP_ENTRIES) {
    throw new Error(`ZIP archive contains too many entries (${totalEntries} > ${MAX_ZIP_ENTRIES})`);
  }
  const cdSize = view.getUint32(eocdOffset + 12, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);
  if (cdOffset + cdSize > zipBytes.byteLength) {
    throw new Error('Corrupt ZIP central directory bounds');
  }

  const decoder = new TextDecoder();
  const entries: ZipEntrySpec[] = [];
  let pos = cdOffset;

  for (let idx = 0; idx < totalEntries; idx++) {
    if (pos + 46 > zipBytes.byteLength || view.getUint32(pos, true) !== 0x02014b50) {
      throw new Error('Invalid ZIP central directory entry');
    }
    const compressionMethod = view.getUint16(pos + 10, true);
    const compressedSize = view.getUint32(pos + 20, true);
    const uncompressedSize = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const localHeaderOffset = view.getUint32(pos + 42, true);

    if (pos + 46 + nameLen > zipBytes.byteLength) {
      throw new Error('Corrupt ZIP central directory filename bounds');
    }
    const filename = decoder.decode(zipBytes.subarray(pos + 46, pos + 46 + nameLen));

    if (localHeaderOffset + 30 > zipBytes.byteLength || view.getUint32(localHeaderOffset, true) !== 0x04034b50) {
      throw new Error(`Invalid ZIP local header for entry: ${filename}`);
    }
    const localNameLen = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
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

function collectZipEntriesFromLocalHeaders(zipBytes: Uint8Array, view: DataView): ZipEntrySpec[] {
  const decoder = new TextDecoder();
  const entries: ZipEntrySpec[] = [];
  let pos = 0;

  while (pos + 30 <= zipBytes.byteLength && view.getUint32(pos, true) === 0x04034b50) {
    if (entries.length >= MAX_ZIP_ENTRIES) {
      throw new Error(`ZIP archive exceeds max entries (${MAX_ZIP_ENTRIES})`);
    }
    const flags = view.getUint16(pos + 6, true);
    if ((flags & 0x0008) !== 0) {
      throw new Error('ZIP entry uses data descriptor without central directory');
    }
    const compressionMethod = view.getUint16(pos + 8, true);
    const compressedSize = view.getUint32(pos + 18, true);
    const uncompressedSize = view.getUint32(pos + 22, true);
    const nameLen = view.getUint16(pos + 26, true);
    const extraLen = view.getUint16(pos + 28, true);
    const dataOffset = pos + 30 + nameLen + extraLen;
    if (dataOffset > zipBytes.byteLength) {
      throw new Error('Corrupt ZIP local header bounds');
    }
    const filename = decoder.decode(zipBytes.subarray(pos + 30, pos + 30 + nameLen));
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
 * Extracts and validates ALL entries in a ZIP attachment (both STORE=0 and DEFLATE=8).
 * Rejects immediately if any entry is an RUF forensic report or exceeds maxTotalBytes.
 */
async function extractAllZipEntries(
  zipBytes: Uint8Array,
  maxTotalBytes = MAX_UNCOMPRESSED_BYTES
): Promise<{ entries: Array<{ filename: string; data: Uint8Array }>; totalBytes: number }> {
  const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
  if (zipBytes.byteLength < 30 || view.getUint32(0, true) !== 0x04034b50) {
    throw new Error('Invalid ZIP attachment');
  }

  const eocdOffset = findEocdOffset(zipBytes, view);
  const specs = eocdOffset !== -1
    ? collectZipEntriesFromCentralDirectory(zipBytes, view, eocdOffset)
    : collectZipEntriesFromLocalHeaders(zipBytes, view);

  if (specs.length === 0) {
    throw new Error('ZIP archive contains no entries');
  }

  const entries: Array<{ filename: string; data: Uint8Array }> = [];
  let totalBytes = 0;

  for (const spec of specs) {
    if (isRufIndicator('', spec.filename)) {
      throw new WorkerRufRejectedError(`RUF forensic archive entry rejected: ${spec.filename}`);
    }

    if (spec.uncompressedSize > maxTotalBytes || totalBytes + spec.uncompressedSize > maxTotalBytes) {
      throw new Error(`ZIP entry "${spec.filename}" exceeds ${maxTotalBytes} byte uncompressed limit`);
    }

    if (spec.filename.endsWith('/') && spec.compressedSize === 0 && spec.uncompressedSize === 0) {
      continue;
    }

    if (spec.dataOffset + spec.compressedSize > zipBytes.byteLength) {
      throw new Error(`ZIP entry "${spec.filename}" truncated`);
    }

    // Exact bounds slice (handles 0-byte STORE entries cleanly without slicing to EOF)
    const slice = zipBytes.subarray(spec.dataOffset, spec.dataOffset + spec.compressedSize);

    if (spec.compressionMethod === 0) {
      if (slice.byteLength > maxTotalBytes || totalBytes + slice.byteLength > maxTotalBytes) {
        throw new Error(`ZIP STORE entry "${spec.filename}" exceeds ${maxTotalBytes} byte limit`);
      }
      totalBytes += slice.byteLength;
      entries.push({ filename: spec.filename, data: slice });
    } else if (spec.compressionMethod === 8) {
      const remaining = maxTotalBytes - totalBytes;
      const data = await decompressStreamBytes(slice, 'deflate-raw', remaining);
      totalBytes += data.byteLength;
      entries.push({ filename: spec.filename, data });
    } else {
      throw new Error(`Unsupported ZIP compression method: ${spec.compressionMethod}`);
    }
  }

  return { entries, totalBytes };
}

function extractAllTags(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'gi');
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    if (m[1] !== undefined) out.push(m[1]);
  }
  return out;
}

export function parseWorkerRuaXml(xml: string, filenameHint?: string): WorkerRuaSummary {
  if (isRufIndicator(xml, filenameHint)) {
    throw new WorkerRufRejectedError();
  }
  if (!/<feedback[\s>]/i.test(xml)) {
    throw new Error('Invalid RUA XML: missing <feedback> root element');
  }

  const metaXml = extractTag(xml, 'report_metadata');
  const polXml = extractTag(xml, 'policy_published');

  const orgName = extractTag(metaXml, 'org_name') || 'unknown';
  const reportId = extractTag(metaXml, 'report_id') || `rua-${Date.now()}`;
  const dateRangeBegin = Number.parseInt(extractTag(metaXml, 'begin') || '0', 10) || 0;
  const dateRangeEnd = Number.parseInt(extractTag(metaXml, 'end') || '0', 10) || 0;
  const domain = extractTag(polXml, 'domain') || 'unknown';
  const policy = extractTag(polXml, 'p') || 'none';

  let totalMessages = 0;
  let dmarcPass = 0;
  let dmarcFail = 0;
  const sourceMap = new Map<string, WorkerRuaSource>();

  const recordRe = /<record(?:\s[^>]*)?>([\s\S]*?)<\/record>/gi;
  let match: RegExpExecArray | null;
  while ((match = recordRe.exec(xml)) !== null) {
    const recXml = match[1] ?? '';
    const rowXml = extractTag(recXml, 'row') || recXml;
    const sourceIp = extractTag(rowXml, 'source_ip') || 'unknown';
    const count = Math.max(0, Number.parseInt(extractTag(rowXml, 'count') || '0', 10) || 0);
    const policyEval = extractTag(rowXml, 'policy_evaluated');
    const disposition = (extractTag(policyEval, 'disposition') || 'none').toLowerCase();
    const dkimPass = (extractTag(policyEval, 'dkim') || 'fail').toLowerCase() === 'pass';
    const spfPass = (extractTag(policyEval, 'spf') || 'fail').toLowerCase() === 'pass';
    const headerFrom = extractTag(extractTag(recXml, 'identifiers') || recXml, 'header_from') || domain;

    const authHints: string[] = [];
    const authXml = extractTag(recXml, 'auth_results');
    if (authXml) {
      for (const b of extractAllTags(authXml, 'dkim')) {
        if ((extractTag(b, 'result') || '').toLowerCase() === 'pass') {
          const dom = extractTag(b, 'domain');
          if (dom) authHints.push(dom);
        }
      }
      for (const b of extractAllTags(authXml, 'spf')) {
        if ((extractTag(b, 'result') || '').toLowerCase() === 'pass') {
          const dom = extractTag(b, 'domain');
          if (dom) authHints.push(dom);
        }
      }
    }

    const pass = dkimPass || spfPass;
    const isSuspicious = !pass || disposition === 'quarantine' || disposition === 'reject';
    totalMessages += count;
    if (pass) dmarcPass += count;
    else dmarcFail += count;

    const key = `${sourceIp}|${headerFrom.toLowerCase()}`;
    let existing = sourceMap.get(key);
    if (!existing) {
      const prov = matchMailProvider(sourceIp, authHints);
      existing = {
        sourceIp,
        headerFrom,
        providerId: prov.providerId,
        provider: prov.provider,
        providerCategory: prov.category,
        totalCount: 0,
        dmarcPass: 0,
        dmarcFail: 0,
        suspicious: false
      };
      sourceMap.set(key, existing);
    }
    existing.totalCount += count;
    if (pass) existing.dmarcPass += count;
    else existing.dmarcFail += count;
    if (isSuspicious) existing.suspicious = true;
  }

  const sources = [...sourceMap.values()].sort((a, b) => b.totalCount - a.totalCount);
  const suspiciousSources = sources
    .filter((s) => s.suspicious)
    .map((s) => ({
      sourceIp: s.sourceIp,
      headerFrom: s.headerFrom,
      providerId: s.providerId,
      provider: s.provider,
      totalCount: s.totalCount,
      dmarcFail: s.dmarcFail
    }))
    .sort((a, b) => b.dmarcFail - a.dmarcFail);

  const passRate = totalMessages > 0 ? Number(((dmarcPass / totalMessages) * 100).toFixed(2)) : 0;
  return {
    reportId,
    orgName,
    domain,
    policy,
    dateRangeBegin,
    dateRangeEnd,
    totalMessages,
    dmarcPass,
    dmarcFail,
    passRate,
    sources,
    suspiciousSources,
    receivedAt: new Date().toISOString()
  };
}

interface MimePart {
  headers: Record<string, string>;
  body: string;
}

function splitHeadersAndBody(raw: string): { headers: Record<string, string>; body: string } {
  const crlfIdx = raw.indexOf('\r\n\r\n');
  const lfIdx = raw.indexOf('\n\n');
  let idx = -1;
  let sepLen = 0;
  if (crlfIdx !== -1 && (lfIdx === -1 || crlfIdx < lfIdx)) {
    idx = crlfIdx;
    sepLen = 4;
  } else if (lfIdx !== -1) {
    idx = lfIdx;
    sepLen = 2;
  }
  if (idx === -1) return { headers: {}, body: raw };

  const headerText = raw.slice(0, idx).replace(/\r?\n[ \t]+/g, ' ');
  const body = raw.slice(idx + sepLen);
  const headers: Record<string, string> = {};
  for (const line of headerText.split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const val = line.slice(colon + 1).trim();
    headers[key] = val;
  }
  return { headers, body };
}

function extractMimeParts(
  rawMime: string,
  depth = 0,
  maxDepth = MAX_MIME_DEPTH,
  state: { count: number } = { count: 0 }
): MimePart[] {
  if (depth > maxDepth) {
    throw new Error(`MIME multipart nesting depth exceeded limit (${maxDepth})`);
  }

  state.count += 1;
  if (state.count > MAX_MIME_PARTS) {
    throw new Error(`MIME parts count exceeded limit (${MAX_MIME_PARTS})`);
  }

  const top = splitHeadersAndBody(rawMime);
  const ct = top.headers['content-type'] ?? '';
  const isMultipart = /^\s*multipart\//i.test(ct) || /\bmultipart\//i.test(ct);
  const boundaryMatch = /boundary=(?:"([^"]+)"|([^\s;]+))/i.exec(ct);
  const boundary = boundaryMatch?.[1] ?? boundaryMatch?.[2];

  if (!isMultipart || !boundary) {
    return [top];
  }

  const marker = `--${boundary}`;
  const segments = top.body.split(marker);
  const parts: MimePart[] = [];
  for (let i = 1; i < segments.length; i++) {
    const seg = segments[i] ?? '';
    if (seg.startsWith('--')) break;
    const trimmed = seg.replace(/^\r?\n/, '').replace(/\r?\n$/, '');
    if (!trimmed.trim()) continue;
    parts.push(...extractMimeParts(trimmed, depth + 1, maxDepth, state));
  }
  return parts;
}

export async function parseIncomingRuaMime(
  rawMime: string,
  maxBytes = MAX_UNCOMPRESSED_BYTES,
  maxRawBytes = MAX_EMAIL_RAW_BYTES
): Promise<EmailIngestResult> {
  if (rawMime.length > maxRawBytes) {
    return {
      accepted: false,
      rejectedReason: `Incoming raw email exceeds ${maxRawBytes} byte safety limit`,
      reports: []
    };
  }

  if (isRufIndicator(rawMime)) {
    return {
      accepted: false,
      rejectedReason: 'RUF forensic report rejected by privacy firewall',
      reports: []
    };
  }

  try {
    const parts = extractMimeParts(rawMime);
    const reports: WorkerRuaSummary[] = [];
    let cumulativeBytes = 0;

    for (const part of parts) {
      const ct = (part.headers['content-type'] ?? '').toLowerCase();
      const cd = part.headers['content-disposition'] ?? '';
      const cte = (part.headers['content-transfer-encoding'] ?? '').toLowerCase();
      const filenameMatch = /filename=(?:"([^"]+)"|([^\s;]+))/i.exec(cd) ?? /name=(?:"([^"]+)"|([^\s;]+))/i.exec(ct);
      const filename = filenameMatch?.[1] ?? filenameMatch?.[2] ?? '';

      if (isRufIndicator(`${ct}\n${cd}`, filename)) {
        return {
          accepted: false,
          rejectedReason: `RUF forensic attachment rejected: ${filename || ct}`,
          reports: []
        };
      }

      const isRuaCandidate =
        ct.includes('application/gzip') ||
        ct.includes('application/x-gzip') ||
        ct.includes('application/zip') ||
        ct.includes('application/xml') ||
        ct.includes('text/xml') ||
        filename.toLowerCase().endsWith('.gz') ||
        filename.toLowerCase().endsWith('.zip') ||
        filename.toLowerCase().endsWith('.xml');

      if (!isRuaCandidate) continue;

      const remainingBudget = maxBytes - cumulativeBytes;
      if (remainingBudget <= 0) {
        throw new Error(`Cumulative email attachment payload exceeds ${maxBytes} byte limit`);
      }

      let bytes: Uint8Array;
      if (cte.includes('base64')) {
        const { clean } = estimateBase64DecodedBytes(part.body, remainingBudget);
        bytes = decodeBase64ToBytes(clean);
      } else {
        if (part.body.length > remainingBudget) {
          throw new Error(`Attachment body exceeds remaining ${remainingBudget} byte budget`);
        }
        bytes = new TextEncoder().encode(part.body);
      }

      if (bytes.byteLength > remainingBudget) {
        throw new Error(`Cumulative decoded attachments exceed ${maxBytes} byte limit`);
      }

      if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
        const gunzipped = await decompressStreamBytes(bytes, 'gzip', remainingBudget);
        cumulativeBytes += gunzipped.byteLength;
        const xmlText = new TextDecoder().decode(gunzipped);
        reports.push(parseWorkerRuaXml(xmlText, filename));
      } else if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
        const { entries, totalBytes } = await extractAllZipEntries(bytes, remainingBudget);
        cumulativeBytes += totalBytes;
        for (const entry of entries) {
          const entryText = new TextDecoder().decode(entry.data);
          if (isRufIndicator(entryText, entry.filename)) {
            return {
              accepted: false,
              rejectedReason: `RUF forensic archive entry rejected: ${entry.filename}`,
              reports: []
            };
          }
          if (entry.filename.toLowerCase().endsWith('.xml') || /<feedback[\s>]/i.test(entryText)) {
            reports.push(parseWorkerRuaXml(entryText, entry.filename));
          }
        }
      } else {
        cumulativeBytes += bytes.byteLength;
        const xmlText = new TextDecoder().decode(bytes);
        reports.push(parseWorkerRuaXml(xmlText, filename));
      }
    }

    if (reports.length === 0) {
      return {
        accepted: false,
        rejectedReason: 'No valid DMARC RUA attachment found in incoming email',
        reports: []
      };
    }

    return { accepted: true, reports };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      accepted: false,
      rejectedReason: msg,
      reports: []
    };
  }
}
