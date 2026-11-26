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

function isPrivateOrLoopbackHost(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    lower === 'localhost' ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower === '::1' ||
    lower === '0:0:0:0:0:0:0:1' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe80:')
  ) {
    return true;
  }

  // Reject any literal IPv4 address (especially RFC1918 / loopback / link-local / metadata)
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(lower);
  if (ipv4Match) {
    return true;
  }

  // Reject raw IPv6 literals
  if (lower.includes(':')) {
    return true;
  }

  return false;
}

/**
 * SSRF-hardened webhook URL validator:
 * - Requires HTTPS
 * - Rejects embedded credentials, non-443 ports, IP literals, and private/loopback hostnames
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

  const allowed = new Set<string>([
    ...DEFAULT_WEBHOOK_ALLOWLIST,
    ...extraAllowedHosts.map((h) => h.trim().toLowerCase()).filter(Boolean)
  ]);

  const host = parsed.hostname.toLowerCase();
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
    fetchFn?: typeof fetch;
  } = {}
): Promise<{ sent: boolean; status?: number; reason?: string }> {
  const check = validateWebhookUrl(webhookUrl, options.extraAllowedHosts);
  if (!check.valid || !check.url) {
    return { sent: false, reason: check.reason ?? 'Blocked by SSRF guard' };
  }

  const host = check.url.hostname.toLowerCase();
  let body: Record<string, unknown>;
  if (host === 'discord.com' || host === 'discordapp.com') {
    body = { content: message };
  } else if (host === 'hooks.slack.com') {
    body = { text: message };
  } else if (host === 'api.telegram.org') {
    body = { text: message };
  } else {
    body = { text: message, content: message };
  }

  const fetchImpl = options.fetchFn ?? fetch;
  const resp = await fetchImpl(check.url.toString(), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    redirect: 'manual'
  });

  if (resp.status >= 300 && resp.status < 400) {
    return { sent: false, status: resp.status, reason: 'Blocked 3xx redirect from webhook endpoint' };
  }

  return { sent: resp.ok, status: resp.status, reason: resp.ok ? undefined : `HTTP ${resp.status}` };
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
    redirect: 'manual'
  });
  if (!resp.ok) return [];
  const data = (await resp.json()) as DohResponse;
  return (data.Answer ?? [])
    .map((a) => (a.data ?? '').replace(/^"|"$/g, '').replace(/"\s*"/g, ''))
    .filter(Boolean);
}

/**
 * Probes HTTPS/TLS reachability for a monitored domain (without following redirects).
 */
export async function probeDomainHttpsTls(
  domain: string,
  fetchFn: typeof fetch = fetch
): Promise<{ tlsStatus: 'ok' | 'error'; tlsDetail: string }> {
  try {
    const resp = await fetchFn(`https://${domain}/`, {
      method: 'HEAD',
      redirect: 'manual'
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
  const norm = domain.trim().toLowerCase().replace(/\.$/, '');
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
