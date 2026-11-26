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

const MAX_UNCOMPRESSED_BYTES = 15 * 1024 * 1024; // 15 MB Worker safety limit

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
  if (/<forensic[\s>]/i.test(text) || /<sample_message[\s>]/i.test(text)) return true;
  return false;
}

function decodeBase64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

async function decompressStreamBytes(input: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array> {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  await writer.write(input as unknown as BufferSource);
  await writer.close();

  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > MAX_UNCOMPRESSED_BYTES) {
        await reader.cancel();
        throw new Error(`Decompressed RUA payload exceeds ${MAX_UNCOMPRESSED_BYTES} bytes`);
      }
      chunks.push(value);
    }
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return merged;
}

async function extractFirstZipEntryBytes(zipBytes: Uint8Array): Promise<{ filename: string; data: Uint8Array }> {
  const view = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
  if (zipBytes.byteLength < 30 || view.getUint32(0, true) !== 0x04034b50) {
    throw new Error('Invalid ZIP attachment');
  }

  const compressionMethod = view.getUint16(8, true);
  let compressedSize = view.getUint32(18, true);
  const fileNameLength = view.getUint16(26, true);
  const extraFieldLength = view.getUint16(28, true);
  const filename = new TextDecoder().decode(zipBytes.subarray(30, 30 + fileNameLength));
  const dataOffset = 30 + fileNameLength + extraFieldLength;

  if (compressedSize === 0) {
    for (let i = zipBytes.byteLength - 22; i >= Math.max(0, zipBytes.byteLength - 65557); i--) {
      if (view.getUint32(i, true) === 0x06054b50) {
        const cdOffset = view.getUint32(i + 16, true);
        if (cdOffset + 46 <= zipBytes.byteLength && view.getUint32(cdOffset, true) === 0x02014b50) {
          compressedSize = view.getUint32(cdOffset + 20, true);
        }
        break;
      }
    }
  }

  const slice = compressedSize > 0
    ? zipBytes.subarray(dataOffset, dataOffset + compressedSize)
    : zipBytes.subarray(dataOffset);

  if (compressionMethod === 0) {
    return { filename, data: slice };
  }
  if (compressionMethod === 8) {
    const data = await decompressStreamBytes(slice, 'deflate-raw');
    return { filename, data };
  }
  throw new Error(`Unsupported ZIP compression method: ${compressionMethod}`);
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
  const sep = raw.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n';
  const idx = raw.indexOf(sep);
  if (idx === -1) return { headers: {}, body: raw };

  const headerText = raw.slice(0, idx).replace(/\r?\n[ \t]+/g, ' ');
  const body = raw.slice(idx + sep.length);
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

function extractMimeParts(rawMime: string): MimePart[] {
  const top = splitHeadersAndBody(rawMime);
  const ct = top.headers['content-type'] ?? '';
  const boundaryMatch = /boundary="?([^";\s]+)"?/i.exec(ct);
  if (!boundaryMatch?.[1]) {
    return [top];
  }

  const boundary = boundaryMatch[1];
  const segments = top.body.split(`--${boundary}`);
  const parts: MimePart[] = [];
  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed || trimmed === '--') continue;
    parts.push(splitHeadersAndBody(trimmed));
  }
  return parts;
}

export async function parseIncomingRuaMime(rawMime: string): Promise<EmailIngestResult> {
  if (isRufIndicator(rawMime)) {
    return {
      accepted: false,
      rejectedReason: 'RUF forensic report rejected by privacy firewall',
      reports: []
    };
  }

  const parts = extractMimeParts(rawMime);
  const reports: WorkerRuaSummary[] = [];

  for (const part of parts) {
    const ct = (part.headers['content-type'] ?? '').toLowerCase();
    const cd = part.headers['content-disposition'] ?? '';
    const cte = (part.headers['content-transfer-encoding'] ?? '').toLowerCase();
    const filenameMatch = /filename="?([^";\r\n]+)"?/i.exec(cd) ?? /name="?([^";\r\n]+)"?/i.exec(ct);
    const filename = filenameMatch?.[1] ?? '';

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

    let bytes: Uint8Array;
    if (cte.includes('base64')) {
      bytes = decodeBase64ToBytes(part.body);
    } else {
      bytes = new TextEncoder().encode(part.body);
    }

    let xmlText = '';
    let innerFilename = filename;

    if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
      const gunzipped = await decompressStreamBytes(bytes, 'gzip');
      xmlText = new TextDecoder().decode(gunzipped);
    } else if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
      const entry = await extractFirstZipEntryBytes(bytes);
      innerFilename = entry.filename;
      if (isRufIndicator('', innerFilename)) {
        return {
          accepted: false,
          rejectedReason: `RUF forensic archive entry rejected: ${innerFilename}`,
          reports: []
        };
      }
      xmlText = new TextDecoder().decode(entry.data);
    } else {
      xmlText = new TextDecoder().decode(bytes);
    }

    const summary = parseWorkerRuaXml(xmlText, innerFilename);
    reports.push(summary);
  }

  if (reports.length === 0) {
    return {
      accepted: false,
      rejectedReason: 'No valid DMARC RUA attachment found in incoming email',
      reports: []
    };
  }

  return { accepted: true, reports };
}
