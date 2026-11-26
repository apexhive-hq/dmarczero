export type MailProviderCategory = 'workspace' | 'transactional' | 'relay' | 'unknown';

export interface MailProviderMatch {
  providerId: string;
  provider: string;
  category: MailProviderCategory;
  matchedBy: 'cidr' | 'hostname' | 'unknown';
}

interface ProviderDefinition {
  providerId: string;
  provider: string;
  category: MailProviderCategory;
  ipv4Cidrs: readonly string[];
  ipv6Cidrs: readonly string[];
  hostnameSuffixes: readonly string[];
}

const PROVIDERS: readonly ProviderDefinition[] = [
  {
    providerId: 'google-workspace',
    provider: 'Google Workspace',
    category: 'workspace',
    ipv4Cidrs: [
      '209.85.128.0/17',
      '74.125.0.0/16',
      '64.233.160.0/19',
      '66.102.0.0/20',
      '66.249.80.0/20',
      '72.14.192.0/18',
      '108.177.8.0/21',
      '172.217.0.0/19',
      '173.194.0.0/16'
    ],
    ipv6Cidrs: ['2607:f8b0:4000::/36', '2a00:1450:4000::/36'],
    hostnameSuffixes: ['google.com', 'googlemail.com', 'gmail.com', 'smtp-out.google.com']
  },
  {
    providerId: 'microsoft-365',
    provider: 'Microsoft 365',
    category: 'workspace',
    ipv4Cidrs: [
      '40.92.0.0/15',
      '40.107.0.0/16',
      '52.100.0.0/14',
      '104.47.0.0/17',
      '207.46.0.0/16'
    ],
    ipv6Cidrs: ['2a01:111:f400::/48', '2a01:111:f403::/48'],
    hostnameSuffixes: ['protection.outlook.com', 'outlook.com', 'hotmail.com']
  },
  {
    providerId: 'sendgrid',
    provider: 'SendGrid',
    category: 'transactional',
    ipv4Cidrs: [
      '167.89.0.0/17',
      '168.245.0.0/16',
      '149.72.0.0/16',
      '198.21.0.0/21',
      '198.37.144.0/20',
      '50.31.32.0/19'
    ],
    ipv6Cidrs: [],
    hostnameSuffixes: ['sendgrid.net', 'sendgrid.com']
  },
  {
    providerId: 'amazon-ses',
    provider: 'Amazon SES',
    category: 'transactional',
    ipv4Cidrs: [
      '54.240.0.0/18',
      '23.249.208.0/20',
      '23.251.224.0/19',
      '69.169.224.0/20',
      '76.223.128.0/19',
      '199.127.232.0/22',
      '199.255.192.0/22',
      '216.221.160.0/19'
    ],
    ipv6Cidrs: ['2600:1f00::/24'],
    hostnameSuffixes: ['amazonses.com', 'ses.amazonaws.com']
  },
  {
    providerId: 'mailgun',
    provider: 'Mailgun',
    category: 'transactional',
    ipv4Cidrs: [
      '198.61.254.0/24',
      '192.237.158.0/24',
      '166.78.68.0/22',
      '184.173.153.0/24',
      '159.135.224.0/20',
      '69.72.32.0/19',
      '143.55.224.0/20'
    ],
    ipv6Cidrs: [],
    hostnameSuffixes: ['mailgun.org', 'mailgun.net', 'mailgun.com']
  },
  {
    providerId: 'postmark',
    provider: 'Postmark',
    category: 'transactional',
    ipv4Cidrs: ['50.31.156.0/24', '50.31.205.0/24', '104.245.209.192/26'],
    ipv6Cidrs: [],
    hostnameSuffixes: ['mtasv.net', 'postmarkapp.com']
  },
  {
    providerId: 'cloudflare-email',
    provider: 'Cloudflare Email',
    category: 'relay',
    ipv4Cidrs: [
      '104.30.0.0/19',
      '172.68.0.0/16',
      '162.158.0.0/15',
      '173.245.48.0/20',
      '103.21.244.0/22',
      '103.22.200.0/22'
    ],
    ipv6Cidrs: ['2405:8100::/32', '2606:4700::/32'],
    hostnameSuffixes: ['mx.cloudflare.net', 'cloudflare.net', 'cloudflare.com']
  }
];

function parseIpv4(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    value = ((value << 8) | n) >>> 0;
  }
  return value;
}

function ipv4InCidr(ip: string, cidr: string): boolean {
  const ipNum = parseIpv4(ip);
  if (ipNum === null) return false;
  const [netStr, prefixStr] = cidr.split('/');
  if (!netStr || !prefixStr) return false;
  const netNum = parseIpv4(netStr);
  const prefix = Number(prefixStr);
  if (netNum === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}

function parseIpv6(ip: string): bigint | null {
  const clean = ip.trim().toLowerCase().split('%')[0] ?? '';
  if (!clean.includes(':')) return null;
  const halves = clean.split('::');
  if (halves.length > 2) return null;

  const parseGroups = (segment: string): number[] | null => {
    if (segment === '') return [];
    const parts = segment.split(':');
    const out: number[] = [];
    for (const part of parts) {
      if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
      out.push(Number.parseInt(part, 16));
    }
    return out;
  };

  const left = parseGroups(halves[0] ?? '');
  const right = halves.length === 2 ? parseGroups(halves[1] ?? '') : [];
  if (left === null || right === null) return null;

  const totalGroups = left.length + right.length;
  if (halves.length === 1 && totalGroups !== 8) return null;
  if (halves.length === 2 && totalGroups >= 8) return null;

  const missing = halves.length === 2 ? 8 - totalGroups : 0;
  const all = [...left, ...Array<number>(missing).fill(0), ...right];
  if (all.length !== 8) return null;

  let value = 0n;
  for (const g of all) {
    value = (value << 16n) | BigInt(g);
  }
  return value;
}

function ipv6InCidr(ip: string, cidr: string): boolean {
  const ipVal = parseIpv6(ip);
  if (ipVal === null) return false;
  const [netStr, prefixStr] = cidr.split('/');
  if (!netStr || !prefixStr) return false;
  const netVal = parseIpv6(netStr);
  const prefix = Number(prefixStr);
  if (netVal === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  return (ipVal >> shift) === (netVal >> shift);
}

function hostMatchesSuffix(host: string, suffix: string): boolean {
  const normHost = host.trim().toLowerCase().replace(/\.$/, '');
  const normSuffix = suffix.toLowerCase();
  return normHost === normSuffix || normHost.endsWith(`.${normSuffix}`);
}

/**
 * Matches an RUA sending source IP (IPv4/IPv6 CIDR) or verified hostname hints
 * against well-known mail providers completely offline with zero external lookups.
 */
export function matchMailProvider(sourceIp: string, hostnameHints: readonly string[] = []): MailProviderMatch {
  const cleanIp = sourceIp.trim();
  const isV6 = cleanIp.includes(':');

  for (const def of PROVIDERS) {
    if (!isV6) {
      for (const cidr of def.ipv4Cidrs) {
        if (ipv4InCidr(cleanIp, cidr)) {
          return {
            providerId: def.providerId,
            provider: def.provider,
            category: def.category,
            matchedBy: 'cidr'
          };
        }
      }
    } else {
      for (const cidr of def.ipv6Cidrs) {
        if (ipv6InCidr(cleanIp, cidr)) {
          return {
            providerId: def.providerId,
            provider: def.provider,
            category: def.category,
            matchedBy: 'cidr'
          };
        }
      }
    }
  }

  for (const rawHint of hostnameHints) {
    const hint = rawHint.trim().toLowerCase();
    if (!hint) continue;
    for (const def of PROVIDERS) {
      if (def.hostnameSuffixes.some((s) => hostMatchesSuffix(hint, s))) {
        return {
          providerId: def.providerId,
          provider: def.provider,
          category: def.category,
          matchedBy: 'hostname'
        };
      }
    }
  }

  return {
    providerId: 'unknown',
    provider: 'Unknown / Unattributed',
    category: 'unknown',
    matchedBy: 'unknown'
  };
}
