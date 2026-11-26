# DMARCZero

**Zero-dependency Node.js DNS / DMARC / TLS anti-drift guard and streaming aggregate (`RUA`) analyzer (strictly rejects `RUF` forensic reports).**

100% free and open-source under the **MIT License**, built for **Node.js >= 20.0.0** (CLI/core) and self-hosted **Cloudflare Email Workers** (`Node.js >= 22.13.0` for local Wrangler/SQLite tests).

## Why DMARCZero?

After Google and Yahoo enforced bulk sender authentication, teams and agencies often face two extremes:
- Commercial SaaS platforms with recurring per-domain fees.
- Heavy self-hosted stacks like `parsedmarc` requiring Elasticsearch + Kibana clusters.

DMARCZero runs with **zero runtime dependencies** and **zero C++ native addons**, paired with a self-hosted **Cloudflare Worker** package so your DMARC aggregate (`RUA`) reports stay inside your own infrastructure.

## Architecture

```text
+-------------------------------------------------------------------+
|                     Local CLI / GitHub Actions                    |
|  dmarczero check | snapshot | diff | parse-rua | report           |
|  Node.js built-ins: dns/promises, tls, zlib, crypto, test         |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|             Self-Hosted Cloudflare Worker (BYO Free Tier)         |
|  Email Workers (email()) ---> RUA .xml/.gz/.zip Parser (No RUF)   |
|         |                                  |                      |
|         v                                  v                      |
|  SQLite Durable Object              Cron Drift Sentinel           |
|  (RUA stats + DNS/TLS baselines)    (DNS/TLS -> SSRF-Safe Alerts) |
|         |                                                         |
|         v                                                         |
|  Fail-Closed Admin-Authenticated Zero-CDN Web Dashboard           |
+-------------------------------------------------------------------+
```

## Quickstart (Local CLI)

Requires **Node.js >= 20.0.0** and **pnpm**.

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build

# 1. Audit DNS (SPF 10-lookup recursion, DMARC, DKIM, MTA-STS, TLS-RPT, CAA) & TLS cert trust/expiry
node dist/cli.js check example.com --selectors google,selector1,default

# 2. Save baseline snapshot for anti-drift CI guard
node dist/cli.js snapshot example.com --out dmarczero.snapshot.json

# 3. Detect accidental DNS/TLS drift in CI (exits non-zero on drift)
node dist/cli.js diff example.com --snapshot dmarczero.snapshot.json --fail-on-drift

# 4. Stream-parse DMARC RUA aggregate reports (.xml, .xml.gz, .zip — strictly rejects RUF PII reports)
node dist/cli.js parse-rua ./rua-reports/ --json

# 5. Generate standalone zero-CDN XSS-safe HTML security report (supports white-label title/footer)
node dist/cli.js report ./rua-reports/ --out dmarc-report.html --title "Client DMARC Report" --footer "SecOps Team"
```

## BYO Cloudflare Worker Deployment (Self-Hosted)

Requires **Node.js >= 22.13.0** and **pnpm**.

```bash
cd cloudflare-worker
pnpm install --frozen-lockfile --ignore-scripts
pnpm run typecheck
pnpm test

# Configure admin auth and optional domain/webhook settings via Wrangler:
# wrangler secret put DASHBOARD_ADMIN_TOKEN
# wrangler secret put ALERT_WEBHOOK_URL
# wrangler secret put TELEGRAM_CHAT_ID
pnpm exec wrangler deploy
```

1. Set `DASHBOARD_ADMIN_TOKEN` via `wrangler secret put DASHBOARD_ADMIN_TOKEN`. The dashboard (`GET /`) and `/api/summary` fail closed (`503`) if unconfigured and require either `Authorization: Bearer <token>` or an `HttpOnly` HMAC session cookie (`401` otherwise).
2. Enable **Cloudflare Email Routing** for your domain and route `dmarc@yourdomain.com` to the deployed `dmarczero-worker`.
3. Add `rua=mailto:dmarc@yourdomain.com` to your `_dmarc.yourdomain.com` TXT record.
4. Configure `MONITORED_DOMAINS` (strict FQDNs) to enable RUA ingestion (fail-closed by default unless `ALLOW_UNLISTED_DOMAINS="true"` is explicitly set) and daily Cron DNS/TLS drift alerts.
5. Optional: set `WEBHOOK_ALLOWLIST` (comma-separated HTTPS hostnames) to allow outbound alert webhooks beyond the default Discord/Slack/Telegram allowlist.

## Privacy & Security Guarantees

- **Zero RUF / PII Ingestion**: Strictly rejects forensic `RUF` reports containing email content (including across all entries of multi-file ZIPs and nested MIME parts).
- **Zero Telemetry**: Never phones home or sends domain/report data to external servers.
- **Offline Mail-Provider Attribution**: Attributes sending IPs across Google Workspace, Microsoft 365, SendGrid, Amazon SES, Mailgun, Postmark, and Cloudflare Email completely offline with zero external lookups.
- **TLS Trust Verification**: Inspects certificate metadata while verifying `socket.authorized` and `authorizationError`; untrusted, self-signed, or hostname-mismatched certificates never receive an `'ok'` status.
- **XSS-Free Rendering & White-Label Export**: HTML reports and the Worker dashboard use zero CDNs and safe text-escaped rendering (zero `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, or `document.write`), plus strict CSP (`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.
- **SSRF-Protected Webhooks & Domain Validation**: Outbound alerts require HTTPS, allowlisted hosts (`discord.com`, `discordapp.com`, `api.telegram.org` with `TELEGRAM_CHAT_ID`, `hooks.slack.com`), private/loopback/IPv4/IPv6 blocking, `AbortSignal.timeout(...)`, and `redirect: 'manual'`. `MONITORED_DOMAINS` is validated as strict FQDNs.

## License

[MIT License](./LICENSE) — Copyright (c) 2026 ApexHive Labs.
