import tls from 'node:tls';
import net from 'node:net';

export type TlsStatus = 'ok' | 'warning' | 'critical' | 'expired' | 'error';

export interface TlsIssuerLink {
  subject: string;
  issuer: string;
  validTo: string;
  fingerprint256: string;
}

export interface TlsAuditResult {
  host: string;
  port: number;
  servername: string;
  checkedAt: string;
  reachable: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  serialNumber: string | null;
  fingerprint256: string | null;
  issuerChain: TlsIssuerLink[];
  status: TlsStatus;
  error?: string;
}

export interface TlsAuditOptions {
  port?: number;
  servername?: string;
  timeoutMs?: number;
  startTls?: boolean;
  now?: Date;
}

function formatDn(dn: tls.Certificate | undefined): string {
  if (!dn) return '';
  const record = dn as unknown as Record<string, string | string[] | undefined>;
  const parts: string[] = [];
  for (const key of ['CN', 'O', 'OU', 'C']) {
    const val = record[key];
    if (typeof val === 'string' && val) parts.push(`${key}=${val}`);
    else if (Array.isArray(val) && val.length > 0) parts.push(`${key}=${val.join(',')}`);
  }
  return parts.join(', ');
}

function classifyDaysRemaining(daysRemaining: number): TlsStatus {
  if (daysRemaining < 0) return 'expired';
  if (daysRemaining < 14) return 'critical';
  if (daysRemaining < 30) return 'warning';
  return 'ok';
}

function extractChain(cert: tls.DetailedPeerCertificate): TlsIssuerLink[] {
  const chain: TlsIssuerLink[] = [];
  const seen = new Set<string>();
  let current: tls.DetailedPeerCertificate | undefined = cert;

  while (current && current.fingerprint256 && !seen.has(current.fingerprint256) && chain.length < 10) {
    seen.add(current.fingerprint256);
    chain.push({
      subject: formatDn(current.subject),
      issuer: formatDn(current.issuer),
      validTo: current.valid_to ?? '',
      fingerprint256: current.fingerprint256
    });
    if (!current.issuerCertificate || current.issuerCertificate === current) break;
    current = current.issuerCertificate;
  }

  return chain;
}

async function openStartTlsSocket(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise<net.Socket>((resolve, reject) => {
    const sock = net.createConnection({ host, port });
    sock.setTimeout(timeoutMs);
    let stage = 0;
    let buf = '';

    const cleanup = () => {
      sock.removeAllListeners('data');
      sock.removeAllListeners('error');
      sock.removeAllListeners('timeout');
    };

    sock.on('timeout', () => {
      cleanup();
      sock.destroy();
      reject(new Error(`STARTTLS timeout after ${timeoutMs}ms on ${host}:${port}`));
    });

    sock.on('error', (err) => {
      cleanup();
      reject(err);
    });

    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (!buf.includes('\n')) return;
      const lines = buf.split('\r\n').filter(Boolean);
      const last = lines[lines.length - 1] ?? '';
      // Wait for final line of multi-line SMTP response (code followed by space)
      if (!/^\d{3} /.test(last)) return;
      buf = '';

      if (stage === 0 && last.startsWith('220 ')) {
        stage = 1;
        sock.write(`EHLO dmarczero.local\r\n`);
      } else if (stage === 1 && last.startsWith('250 ')) {
        stage = 2;
        sock.write(`STARTTLS\r\n`);
      } else if (stage === 2 && last.startsWith('220 ')) {
        cleanup();
        resolve(sock);
      } else {
        cleanup();
        sock.destroy();
        reject(new Error(`Unexpected SMTP STARTTLS response: ${last}`));
      }
    });
  });
}

export async function auditTls(host: string, options: TlsAuditOptions = {}): Promise<TlsAuditResult> {
  const port = options.port ?? 443;
  const servername = options.servername ?? (net.isIP(host) ? '' : host);
  const timeoutMs = options.timeoutMs ?? 8000;
  const useStartTls = options.startTls ?? port === 587;
  const now = options.now ?? new Date();
  const checkedAt = now.toISOString();

  let underlyingSocket: net.Socket | undefined;
  try {
    if (useStartTls) {
      underlyingSocket = await openStartTlsSocket(host, port, timeoutMs);
    }

    const result = await new Promise<TlsAuditResult>((resolve, reject) => {
      const connectOpts: tls.ConnectionOptions = {
        rejectUnauthorized: false,
        timeout: timeoutMs
      };
      if (underlyingSocket) {
        connectOpts.socket = underlyingSocket;
      } else {
        connectOpts.host = host;
        connectOpts.port = port;
      }
      if (servername) {
        connectOpts.servername = servername;
      }

      const socket = tls.connect(connectOpts, () => {
        try {
          const peer = socket.getPeerCertificate(true);
          if (!peer || Object.keys(peer).length === 0) {
            socket.end();
            reject(new Error(`No peer certificate presented by ${host}:${port}`));
            return;
          }

          const validToDate = new Date(peer.valid_to);
          const validFromDate = new Date(peer.valid_from);
          const msRemaining = validToDate.getTime() - now.getTime();
          const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
          const status = classifyDaysRemaining(daysRemaining);
          const chain = extractChain(peer);

          const out: TlsAuditResult = {
            host,
            port,
            servername: servername || host,
            checkedAt,
            reachable: true,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
            protocol: socket.getProtocol(),
            subject: formatDn(peer.subject),
            issuer: formatDn(peer.issuer),
            validFrom: Number.isNaN(validFromDate.getTime()) ? peer.valid_from : validFromDate.toISOString(),
            validTo: Number.isNaN(validToDate.getTime()) ? peer.valid_to : validToDate.toISOString(),
            daysRemaining,
            serialNumber: peer.serialNumber ?? null,
            fingerprint256: peer.fingerprint256 ?? null,
            issuerChain: chain,
            status
          };

          socket.end();
          resolve(out);
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      });

      socket.setTimeout(timeoutMs, () => {
        socket.destroy();
        reject(new Error(`TLS handshake timeout after ${timeoutMs}ms on ${host}:${port}`));
      });

      socket.on('error', (err) => {
        socket.destroy();
        reject(err);
      });
    });

    return result;
  } catch (err: unknown) {
    if (underlyingSocket && !underlyingSocket.destroyed) {
      underlyingSocket.destroy();
    }
    const msg = err instanceof Error ? err.message : String(err);
    return {
      host,
      port,
      servername: servername || host,
      checkedAt,
      reachable: false,
      authorized: false,
      authorizationError: null,
      protocol: null,
      subject: null,
      issuer: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      serialNumber: null,
      fingerprint256: null,
      issuerChain: [],
      status: 'error',
      error: msg
    };
  }
}
