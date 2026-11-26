export const DEFAULT_WEBHOOK_ALLOWLIST = [
  'discord.com',
  'discordapp.com',
  'api.telegram.org',
  'hooks.slack.com'
] as const;

export interface WebhookValidationResult {
  valid: boolean;
  reason?: string;
  url?: URL;
}

export interface DomainValidationResult {
  valid: boolean;
  domain?: string;
  reason?: string;
}

function isPrivateOrLoopbackHost(hostname: string): boolean {
  const lower = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (!lower) return true;

  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.arpa')
  ) {
    return true;
  }

  // Reject any literal IPv6 address (including ::, ::1, ::ffff:..., fe80:, fc00:, fd00:)
  if (lower.includes(':')) {
    return true;
  }

  // Reject any literal or abbreviated IPv4 / numeric IP host (e.g. 127.0.0.1, 127.1, 2130706433, 0x7f000001)
  if (/^\d+(?:\.\d+){0,3}$/.test(lower) || /^0x[0-9a-f]+$/i.test(lower)) {
    return true;
  }

  // Require at least two labels (blocks single-label internal hostnames)
  if (!lower.includes('.')) {
    return true;
  }

  return false;
}

/**
 * Validates MONITORED_DOMAINS entries as strict public FQDNs.
 * Blocks IPv4/IPv6 literals, localhost, .local/.internal/.arpa, ports, paths, and SSRF targets.
 */
export function validateMonitoredDomain(raw: string): DomainValidationResult {
  const norm = raw.trim().toLowerCase().replace(/\.+$/, '');
  if (!norm) {
    return { valid: false, reason: 'Empty domain' };
  }
  if (norm.length > 253) {
    return { valid: false, reason: 'Domain exceeds 253 characters' };
  }
  if (/[\s/\\@:?#[\]%*]/.test(norm)) {
    return { valid: false, reason: `Domain contains disallowed characters: ${norm}` };
  }
  if (isPrivateOrLoopbackHost(norm)) {
    return { valid: false, reason: `Blocked private, loopback, or IP target: ${norm}` };
  }

  const labels = norm.split('.');
  if (labels.length < 2) {
    return { valid: false, reason: `Domain must be a multi-label FQDN: ${norm}` };
  }

  const labelRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (!labelRe.test(label)) {
      return { valid: false, reason: `Invalid DNS label "${label}" in domain: ${norm}` };
    }
  }

  const tld = labels[labels.length - 1] ?? '';
  if (/^\d+$/.test(tld)) {
    return { valid: false, reason: `Invalid numeric TLD in domain: ${norm}` };
  }

  return { valid: true, domain: norm };
}

/**
 * SSRF-hardened webhook URL validator:
 * - Requires HTTPS
 * - Rejects embedded credentials, non-443 ports, IPv4/IPv6 literals, and private/loopback hostnames
 * - Enforces explicit hostname allowlist (Discord, Telegram, Slack, or configured allowlist)
 */
export function validateWebhookUrl(
  rawUrl: string,
  extraAllowedHosts: string[] = []
): WebhookValidationResult {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'Invalid URL syntax' };
  }

  if (parsed.protocol !== 'https:') {
    return { valid: false, reason: 'Webhook URL must use HTTPS' };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, reason: 'Webhook URL must not contain embedded credentials' };
  }

  if (parsed.port && parsed.port !== '443') {
    return { valid: false, reason: 'Webhook URL must use standard HTTPS port 443' };
  }

  if (isPrivateOrLoopbackHost(parsed.hostname)) {
    return { valid: false, reason: `Blocked private/loopback/IP host: ${parsed.hostname}` };
  }

  const allowed = new Set<string>(DEFAULT_WEBHOOK_ALLOWLIST);
  for (const rawHost of extraAllowedHosts) {
    const clean = rawHost.trim().toLowerCase().replace(/\.+$/, '');
    if (clean && !isPrivateOrLoopbackHost(clean) && !/[/:@\s]/.test(clean)) {
      allowed.add(clean);
    }
  }

  const host = parsed.hostname.toLowerCase().replace(/\.+$/, '');
  if (!allowed.has(host)) {
    return { valid: false, reason: `Webhook host "${host}" is not in the SSRF allowlist` };
  }

  return { valid: true, url: parsed };
}

export async function sendSafeWebhookAlert(
  webhookUrl: string,
  message: string,
  options: {
    extraAllowedHosts?: string[];
    telegramChatId?: string;
    timeoutMs?: number;
    fetchFn?: typeof fetch;
  } = {}
): Promise<{ sent: boolean; status?: number; reason?: string }> {
  const check = validateWebhookUrl(webhookUrl, options.extraAllowedHosts);
  if (!check.valid || !check.url) {
    return { sent: false, reason: check.reason ?? 'Blocked by SSRF guard' };
  }

  const host = check.url.hostname.toLowerCase().replace(/\.+$/, '');
  let body: Record<string, unknown>;
  if (host === 'discord.com' || host === 'discordapp.com') {
    body = { content: message };
  } else if (host === 'hooks.slack.com') {
    body = { text: message };
  } else if (host === 'api.telegram.org') {
    const chatId = (options.telegramChatId ?? check.url.searchParams.get('chat_id') ?? '').trim();
    if (!chatId) {
      return {
        sent: false,
        reason: 'Missing TELEGRAM_CHAT_ID (or chat_id query parameter) for api.telegram.org webhook'
      };
    }
    body = { chat_id: chatId, text: message };
  } else {
    body = { text: message, content: message };
  }

  const fetchImpl = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 8000;
  try {
    const resp = await fetchImpl(check.url.toString(), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs)
    });

    if (resp.status >= 300 && resp.status < 400) {
      return { sent: false, status: resp.status, reason: 'Blocked 3xx redirect from webhook endpoint' };
    }

    return { sent: resp.ok, status: resp.status, reason: resp.ok ? undefined : `HTTP ${resp.status}` };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { sent: false, reason: `Webhook request failed: ${msg}` };
  }
}

export interface DohDnsSnapshot {
  domain: string;
  spf: string | null;
  dmarc: string | null;
  mx: string[];
  tlsStatus: 'ok' | 'error';
  tlsDetail: string;
  checkedAt: string;
}

interface DohAnswer {
  data?: string;
}

interface DohResponse {
  Answer?: DohAnswer[];
}

async function queryDoh(
  name: string,
  type: 'TXT' | 'MX',
  fetchFn: typeof fetch
): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  const resp = await fetchFn(url, {
    headers: { accept: 'application/dns-json' },
    redirect: 'manual',
    signal: AbortSignal.timeout(5000)
  });
  if (!resp.ok) return [];
  const data = (await resp.json()) as DohResponse;
  return (data.Answer ?? [])
    .map((a) => (a.data ?? '').replace(/^"|"$/g, '').replace(/"\s*"/g, ''))
    .filter(Boolean);
}

/**
 * Probes HTTPS/TLS reachability for a validated monitored FQDN (without following redirects).
 */
export async function probeDomainHttpsTls(
  domain: string,
  fetchFn: typeof fetch = fetch
): Promise<{ tlsStatus: 'ok' | 'error'; tlsDetail: string }> {
  const check = validateMonitoredDomain(domain);
  if (!check.valid || !check.domain) {
    return { tlsStatus: 'error', tlsDetail: check.reason ?? 'Invalid monitored domain' };
  }
  try {
    const resp = await fetchFn(`https://${check.domain}/`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(5000)
    });
    return { tlsStatus: 'ok', tlsDetail: `HTTPS ${resp.status}` };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { tlsStatus: 'error', tlsDetail: msg };
  }
}

export async function fetchDomainDnsSnapshot(
  domain: string,
  fetchFn: typeof fetch = fetch
): Promise<DohDnsSnapshot> {
  const check = validateMonitoredDomain(domain);
  if (!check.valid || !check.domain) {
    throw new Error(check.reason ?? `Invalid monitored domain: ${domain}`);
  }
  const norm = check.domain;
  const [rootTxt, dmarcTxt, mxRaw, tlsProbe] = await Promise.all([
    queryDoh(norm, 'TXT', fetchFn),
    queryDoh(`_dmarc.${norm}`, 'TXT', fetchFn),
    queryDoh(norm, 'MX', fetchFn),
    probeDomainHttpsTls(norm, fetchFn)
  ]);

  const spf = rootTxt.find((t) => /^v=spf1(\s|$)/i.test(t.trim())) ?? null;
  const dmarc = dmarcTxt.find((t) => /^v=DMARC1(\s*;|$)/i.test(t.trim())) ?? null;
  const mx = [...mxRaw].sort();

  return {
    domain: norm,
    spf,
    dmarc,
    mx,
    tlsStatus: tlsProbe.tlsStatus,
    tlsDetail: tlsProbe.tlsDetail,
    checkedAt: new Date().toISOString()
  };
}

export function diffDomainSnapshots(prev: DohDnsSnapshot | null, next: DohDnsSnapshot): string[] {
  if (!prev) return [];
  const diffs: string[] = [];
  if (prev.spf !== next.spf) {
    diffs.push(`SPF changed: "${prev.spf ?? '(none)'}" -> "${next.spf ?? '(none)'}"`);
  }
  if (prev.dmarc !== next.dmarc) {
    diffs.push(`DMARC changed: "${prev.dmarc ?? '(none)'}" -> "${next.dmarc ?? '(none)'}"`);
  }
  if (JSON.stringify(prev.mx) !== JSON.stringify(next.mx)) {
    diffs.push(`MX changed: ${JSON.stringify(prev.mx)} -> ${JSON.stringify(next.mx)}`);
  }
  if (prev.tlsStatus !== next.tlsStatus) {
    diffs.push(`TLS status changed: ${prev.tlsStatus} -> ${next.tlsStatus} (${next.tlsDetail})`);
  }
  return diffs;
}
