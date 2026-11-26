import type { DnsAuditReport } from './dns-audit.js';
import type { RuaDirectoryResult } from './rua-parser.js';
import type { TlsAuditResult } from './tls-audit.js';

export interface HtmlReportInput {
  title?: string;
  generatedAt?: string;
  dns?: DnsAuditReport | null;
  tls?: TlsAuditResult | null;
  rua?: RuaDirectoryResult | null;
}

export function escapeHtml(input: unknown): string {
  return String(input ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function badgeClass(status: string): string {
  const s = status.toLowerCase();
  if (s === 'ok' || s === 'pass' || s === 'reject') return 'badge-ok';
  if (s === 'warn' || s === 'warning' || s === 'quarantine' || s === 'none') return 'badge-warn';
  return 'badge-err';
}

/**
 * Generates a completely self-contained, zero-CDN, XSS-safe static HTML report.
 * Uses pure server-side HTML escaping with zero inline unsafe DOM sinks.
 */
export function generateHtmlReport(input: HtmlReportInput): string {
  const title = input.title ?? (input.dns ? `DMARCZero Security Report — ${input.dns.domain}` : 'DMARCZero RUA Security Report');
  const generatedAt = input.generatedAt ?? new Date().toISOString();

  const sections: string[] = [];

  if (input.dns) {
    const d = input.dns;
    const findingRows = d.findings.length > 0
      ? d.findings.map((f) => `<tr><td><span class="badge ${badgeClass(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span></td><td><code>${escapeHtml(f.code)}</code></td><td>${escapeHtml(f.message)}</td></tr>`).join('\n')
      : '<tr><td colspan="3">No issues detected.</td></tr>';

    const dkimRows = d.dkim.filter((k) => k.present).map((k) =>
      `<tr><td><code>${escapeHtml(k.selector)}</code></td><td>${escapeHtml(k.keyType ?? '-')}</td><td>${escapeHtml(k.keyBits ?? '-')}</td><td><span class="badge ${badgeClass(k.status)}">${escapeHtml(k.revoked ? 'REVOKED' : k.status.toUpperCase())}</span></td></tr>`
    ).join('\n') || '<tr><td colspan="4">No active DKIM selectors found.</td></tr>';

    sections.push(`
      <section class="card">
        <h2>DNS Authentication Audit: ${escapeHtml(d.domain)}</h2>
        <div class="kpi-grid">
          <div class="kpi"><div class="kpi-label">Health Score</div><div class="kpi-val">${escapeHtml(d.score)} / 100</div></div>
          <div class="kpi"><div class="kpi-label">SPF Lookups</div><div class="kpi-val">${escapeHtml(d.spf.lookupCount)} / ${escapeHtml(d.spf.maxLookups)}</div></div>
          <div class="kpi"><div class="kpi-label">DMARC Policy</div><div class="kpi-val">${escapeHtml(d.dmarc.policy ?? 'MISSING')}</div></div>
          <div class="kpi"><div class="kpi-label">MTA-STS / CAA</div><div class="kpi-val">${escapeHtml(d.mtaSts.present ? 'STS OK' : 'No STS')} · ${escapeHtml(d.caa.present ? 'CAA OK' : 'No CAA')}</div></div>
        </div>
        <h3>DKIM Selectors</h3>
        <table><thead><tr><th>Selector</th><th>Key Type</th><th>Bits</th><th>Status</th></tr></thead><tbody>${dkimRows}</tbody></table>
        <h3>Findings</h3>
        <table><thead><tr><th>Severity</th><th>Code</th><th>Detail</th></tr></thead><tbody>${findingRows}</tbody></table>
      </section>
    `);
  }

  if (input.tls) {
    const t = input.tls;
    sections.push(`
      <section class="card">
        <h2>SSL/TLS Certificate Monitor: ${escapeHtml(t.host)}:${escapeHtml(t.port)}</h2>
        <div class="kpi-grid">
          <div class="kpi"><div class="kpi-label">Status</div><div class="kpi-val"><span class="badge ${badgeClass(t.status)}">${escapeHtml(t.status.toUpperCase())}</span></div></div>
          <div class="kpi"><div class="kpi-label">Days Remaining</div><div class="kpi-val">${escapeHtml(t.daysRemaining ?? 'N/A')}</div></div>
          <div class="kpi"><div class="kpi-label">Protocol</div><div class="kpi-val">${escapeHtml(t.protocol ?? 'N/A')}</div></div>
          <div class="kpi"><div class="kpi-label">Valid Until</div><div class="kpi-val">${escapeHtml(t.validTo ?? 'N/A')}</div></div>
        </div>
        <p class="meta">Subject: <code>${escapeHtml(t.subject ?? 'N/A')}</code> · Issuer: <code>${escapeHtml(t.issuer ?? 'N/A')}</code></p>
      </section>
    `);
  }

  if (input.rua) {
    const r = input.rua;
    const allSources = r.reports.flatMap((rep) => rep.sources);
    const sourceRows = allSources.length > 0
      ? allSources.map((s) => `
          <tr>
            <td><code>${escapeHtml(s.sourceIp)}</code></td>
            <td>${escapeHtml(s.provider || 'Unknown / Unattributed')}</td>
            <td>${escapeHtml(s.headerFrom)}</td>
            <td>${escapeHtml(s.totalCount)}</td>
            <td>${escapeHtml(s.dmarcPass)}</td>
            <td>${escapeHtml(s.dmarcFail)}</td>
            <td><span class="badge ${s.suspicious ? 'badge-err' : 'badge-ok'}">${s.suspicious ? 'SUSPICIOUS' : 'OK'}</span></td>
          </tr>`).join('\n')
      : '<tr><td colspan="7">No RUA source records found.</td></tr>';

    const rejectedBlock = r.rejectedFiles.length > 0
      ? `<h3>Rejected Files (Privacy / Safety Firewall)</h3><ul>${r.rejectedFiles.map((rf) => `<li><code>${escapeHtml(rf.file)}</code>: ${escapeHtml(rf.reason)}</li>`).join('')}</ul>`
      : '';

    sections.push(`
      <section class="card">
        <h2>DMARC RUA Aggregate Summary</h2>
        <div class="kpi-grid">
          <div class="kpi"><div class="kpi-label">Reports Parsed</div><div class="kpi-val">${escapeHtml(r.reports.length)}</div></div>
          <div class="kpi"><div class="kpi-label">Total Messages</div><div class="kpi-val">${escapeHtml(r.totalMessages)}</div></div>
          <div class="kpi"><div class="kpi-label">DMARC Pass Rate</div><div class="kpi-val">${escapeHtml(r.passRate)}%</div></div>
          <div class="kpi"><div class="kpi-label">Suspicious Sources</div><div class="kpi-val">${escapeHtml(r.suspiciousSources.length)}</div></div>
        </div>
        <h3>Sending Sources</h3>
        <table>
          <thead><tr><th>Source IP</th><th>Provider</th><th>Header-From</th><th>Total</th><th>DMARC Pass</th><th>DMARC Fail</th><th>Risk</th></tr></thead>
          <tbody>${sourceRows}</tbody>
        </table>
        ${rejectedBlock}
      </section>
    `);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --border: #334155; --ok: #10b981; --warn: #f59e0b; --err: #ef4444; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; padding: 24px; }
    .container { max-width: 1024px; margin: 0 auto; }
    header { margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }
    header h1 { margin: 0 0 6px 0; font-size: 1.6rem; }
    .meta { color: var(--muted); font-size: 0.9rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
    h2 { margin-top: 0; font-size: 1.2rem; }
    h3 { font-size: 1rem; margin-top: 18px; color: var(--muted); }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 12px 0; }
    .kpi { background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 12px; }
    .kpi-label { font-size: 0.8rem; color: var(--muted); }
    .kpi-val { font-size: 1.25rem; font-weight: 700; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9rem; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    code { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.85em; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
    .badge-ok { background: rgba(16,185,129,0.2); color: #34d399; }
    .badge-warn { background: rgba(245,158,11,0.2); color: #fbbf24; }
    .badge-err { background: rgba(239,68,68,0.2); color: #f87171; }
    footer { margin-top: 32px; color: var(--muted); font-size: 0.82rem; border-top: 1px solid var(--border); padding-top: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>${escapeHtml(title)}</h1>
      <div class="meta">Generated by DMARCZero (ApexHive Labs) · ${escapeHtml(generatedAt)} · Zero-CDN Offline Report</div>
    </header>
    ${sections.join('\n')}
    <footer>
      DMARCZero by ApexHive Labs (apexhive.hq@proton.me) · Solo 0 USDC Forever · Team Founder Early-Bird 99 USDC · Enterprise Founder Early-Bird 499 USDC<br />
      Voluntary Base USDC Tip: <code>0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206</code>
    </footer>
  </div>
</body>
</html>
`;
}
