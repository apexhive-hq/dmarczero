#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { auditDns, DEFAULT_DKIM_SELECTORS, type DnsResolver } from './dns-audit.js';
import { auditTls } from './tls-audit.js';
import { createSnapshot, diffSnapshots, loadSnapshot, saveSnapshot } from './diff.js';
import { parseRuaPath } from './rua-parser.js';
import { generateHtmlReport } from './report-html.js';

export interface CliRuntime {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
  resolver?: DnsResolver;
  color?: boolean;
}

function makeColorizer(enabled: boolean) {
  const wrap = (code: string, text: string) => (enabled ? `\x1b[${code}m${text}\x1b[0m` : text);
  return {
    bold: (s: string) => wrap('1', s),
    dim: (s: string) => wrap('2', s),
    green: (s: string) => wrap('32', s),
    yellow: (s: string) => wrap('33', s),
    red: (s: string) => wrap('31', s),
    cyan: (s: string) => wrap('36', s)
  };
}

function formatTable(headers: string[], rows: string[][]): string[] {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length))
  );
  const padRow = (cols: string[]) =>
    cols.map((c, i) => (c ?? '').padEnd(widths[i] ?? 0)).join('  ');
  const sep = widths.map((w) => '-'.repeat(w)).join('  ');
  return [padRow(headers), sep, ...rows.map(padRow)];
}

function parseFlags(args: string[]): { positional: string[]; flags: Map<string, string | boolean> } {
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < args.length; i++) {
    const token = args[i] ?? '';
    if (token.startsWith('--')) {
      const eqIdx = token.indexOf('=');
      if (eqIdx !== -1) {
        flags.set(token.slice(2, eqIdx), token.slice(eqIdx + 1));
      } else {
        const key = token.slice(2);
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
          flags.set(key, next);
          i += 1;
        } else {
          flags.set(key, true);
        }
      }
    } else {
      positional.push(token);
    }
  }

  return { positional, flags };
}

function printHelp(out: (line: string) => void): void {
  out([
    'DMARCZero v1.0.0 — DNS / DMARC / TLS Anti-Drift Guard & RUA Aggregate Analyzer (MIT)',
    '',
    'Usage:',
    '  dmarczero check <domain> [--selectors s1,s2] [--port 443] [--no-tls] [--json]',
    '  dmarczero snapshot <domain> [--out dmarczero.snapshot.json] [--selectors s1,s2] [--no-tls]',
    '  dmarczero diff <domain> [--snapshot dmarczero.snapshot.json] [--fail-on-drift] [--no-tls] [--json]',
    '  dmarczero parse-rua <file_or_dir> [--json]',
    '  dmarczero report <file_or_dir> [--out dmarc-report.html] [--title "..."] [--footer "..."]'
  ].join('\n'));
}

export async function runCli(argv: string[], runtime?: Partial<CliRuntime>): Promise<number> {
  const stdout = runtime?.stdout ?? ((s: string) => process.stdout.write(`${s}\n`));
  const stderr = runtime?.stderr ?? ((s: string) => process.stderr.write(`${s}\n`));
  const colorEnabled = runtime?.color ?? (Boolean(process.stdout.isTTY) && !process.env.NO_COLOR);
  const c = makeColorizer(colorEnabled);

  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
    printHelp(stdout);
    return 0;
  }

  const { positional, flags } = parseFlags(rest);
  const asJson = flags.get('json') === true;
  const selectorsArg = typeof flags.get('selectors') === 'string'
    ? String(flags.get('selectors')).split(',').map((s) => s.trim()).filter(Boolean)
    : DEFAULT_DKIM_SELECTORS;
  const skipTls = flags.get('no-tls') === true;
  const port = typeof flags.get('port') === 'string' ? Number.parseInt(String(flags.get('port')), 10) : 443;

  const colorStatus = (status: string): string => {
    const u = status.toUpperCase();
    if (u === 'OK' || u === 'PASS') return c.green(u);
    if (u === 'WARN' || u === 'WARNING') return c.yellow(u);
    return c.red(u);
  };

  try {
    if (cmd === 'check') {
      const domain = positional[0];
      if (!domain) {
        stderr('Error: missing <domain> argument for check');
        return 2;
      }
      const dns = await auditDns(domain, { selectors: selectorsArg, resolver: runtime?.resolver });
      const tls = skipTls ? null : await auditTls(domain, { port });

      if (asJson) {
        stdout(JSON.stringify({ dns, tls }, null, 2));
      } else {
        stdout(c.bold(`DMARCZero Audit: ${dns.domain} (Score: ${dns.score}/100)`));
        stdout(`  SPF:   ${dns.spf.present ? `${dns.spf.lookupCount}/${dns.spf.maxLookups} lookups (${colorStatus(dns.spf.status)})` : c.red('MISSING')}`);
        stdout(`  DMARC: ${dns.dmarc.present ? `p=${dns.dmarc.policy ?? 'invalid'} pct=${dns.dmarc.pct}% (${colorStatus(dns.dmarc.status)})` : c.red('MISSING')}`);
        const activeDkim = dns.dkim.filter((d) => d.present);
        stdout(`  DKIM:  ${activeDkim.length > 0 ? activeDkim.map((d) => `${d.selector}(${d.keyBits ?? '?'}b)`).join(', ') : c.yellow('none found')}`);
        stdout(`  STS:   ${dns.mtaSts.present ? c.green('present') : c.yellow('missing')} | TLS-RPT: ${dns.tlsRpt.present ? c.green('present') : c.yellow('missing')} | CAA: ${dns.caa.present ? c.green(`${dns.caa.records.length} record(s)`) : c.yellow('missing')}`);
        if (tls) {
          if (tls.reachable) {
            const trustStr = tls.authorized
              ? c.green('trusted')
              : c.red(`UNTRUSTED: ${tls.authorizationError ?? 'verification failed'}`);
            stdout(`  TLS:   ${tls.daysRemaining}d remaining, ${trustStr} (${colorStatus(tls.status)})`);
          } else {
            stdout(`  TLS:   ${c.red(`ERROR: ${tls.error ?? 'unreachable'}`)}`);
          }
        }
        if (dns.findings.length > 0) {
          stdout('  Findings:');
          for (const f of dns.findings) {
            stdout(`    - [${colorStatus(f.severity)}] ${f.code}: ${f.message}`);
          }
        }
      }
      return 0;
    }

    if (cmd === 'snapshot') {
      const domain = positional[0];
      if (!domain) {
        stderr('Error: missing <domain> argument for snapshot');
        return 2;
      }
      const outPath = typeof flags.get('out') === 'string' ? String(flags.get('out')) : 'dmarczero.snapshot.json';
      const dns = await auditDns(domain, { selectors: selectorsArg, resolver: runtime?.resolver });
      const tls = skipTls ? null : await auditTls(domain, { port });
      const snap = createSnapshot(dns, tls);
      await saveSnapshot(outPath, snap);
      stdout(c.green(`Saved snapshot for ${dns.domain} to ${outPath}`));
      return 0;
    }

    if (cmd === 'diff') {
      const domain = positional[0];
      if (!domain) {
        stderr('Error: missing <domain> argument for diff');
        return 2;
      }
      const snapPath = typeof flags.get('snapshot') === 'string' ? String(flags.get('snapshot')) : 'dmarczero.snapshot.json';
      const failOnDrift = flags.get('fail-on-drift') === true;
      const baseline = await loadSnapshot(snapPath);
      const dns = await auditDns(domain, { selectors: selectorsArg, resolver: runtime?.resolver });
      const tls = skipTls ? null : await auditTls(domain, { port });
      const current = createSnapshot(dns, tls);
      const drift = diffSnapshots(baseline, current);

      if (asJson) {
        stdout(JSON.stringify(drift, null, 2));
      } else if (!drift.hasDrift) {
        stdout(c.green(`No drift detected for ${drift.domain}`));
      } else {
        stdout(c.red(`DRIFT DETECTED for ${drift.domain} (${drift.changes.length} change(s)):`));
        for (const ch of drift.changes) {
          stdout(`  - [${colorStatus(ch.severity)}] ${ch.field}: ${ch.message}`);
          stdout(`      before: ${ch.before}`);
          stdout(`      after:  ${ch.after}`);
        }
      }
      return failOnDrift && drift.hasDrift ? 1 : 0;
    }

    if (cmd === 'parse-rua') {
      const target = positional[0];
      if (!target) {
        stderr('Error: missing <file_or_dir> argument for parse-rua');
        return 2;
      }
      const result = await parseRuaPath(target);
      if (asJson) {
        stdout(JSON.stringify(result, null, 2));
      } else {
        const rateStr = result.passRate >= 95
          ? c.green(`${result.passRate}%`)
          : result.passRate >= 80
            ? c.yellow(`${result.passRate}%`)
            : c.red(`${result.passRate}%`);
        stdout(c.bold(`DMARCZero RUA Summary (${result.reports.length} report(s), ${result.rejectedFiles.length} rejected)`));
        stdout(`  Total Messages: ${result.totalMessages} | DMARC Pass: ${c.green(String(result.dmarcPass))} (${rateStr}) | Fail: ${result.dmarcFail > 0 ? c.red(String(result.dmarcFail)) : '0'}`);
        const allSources = result.reports.flatMap((r) => r.sources);
        if (allSources.length > 0) {
          stdout('');
          const tableLines = formatTable(
            ['Source IP', 'Provider', 'Header-From', 'Total', 'Pass', 'Fail', 'Risk'],
            allSources.map((s) => [
              s.sourceIp,
              s.provider,
              s.headerFrom,
              String(s.totalCount),
              String(s.dmarcPass),
              String(s.dmarcFail),
              s.suspicious ? 'SUSPICIOUS' : 'OK'
            ])
          );
          for (const line of tableLines) {
            stdout(`  ${line.endsWith('SUSPICIOUS') ? c.red(line) : line}`);
          }
        }
        if (result.rejectedFiles.length > 0) {
          stdout('');
          stdout(c.yellow('  Rejected Files (Privacy / Safety Firewall):'));
          for (const rf of result.rejectedFiles) {
            stdout(`    - ${rf.file}: ${rf.reason}`);
          }
        }
      }
      return 0;
    }

    if (cmd === 'report') {
      const target = positional[0];
      if (!target) {
        stderr('Error: missing <file_or_dir> argument for report');
        return 2;
      }
      const outPath = typeof flags.get('out') === 'string' ? String(flags.get('out')) : 'dmarc-report.html';
      const title = typeof flags.get('title') === 'string' ? String(flags.get('title')) : undefined;
      const footerText = typeof flags.get('footer') === 'string' ? String(flags.get('footer')) : undefined;
      const rua = await parseRuaPath(target);
      const html = generateHtmlReport({ rua, title, footerText });
      await writeFile(outPath, html, 'utf8');
      stdout(c.green(`Generated zero-CDN HTML report at ${outPath}`));
      return 0;
    }

    stderr(`Unknown command: ${cmd}`);
    return 2;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    stderr(`Error: ${msg}`);
    return 1;
  }
}

function isExecutedDirectly(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isExecutedDirectly()) {
  runCli(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
