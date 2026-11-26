# DMARCZero

**Zero-Elasticsearch, Zero-Native-Dependency DNS / DMARC / SSL Anti-Drift Guard & Streaming RUA Analyzer**

Built by **ApexHive Labs** (`apexhive.hq@proton.me`) for Node.js 24+ and self-hosted Cloudflare Email Workers.

## Why DMARCZero?

After Google and Yahoo enforced bulk sender authentication, teams and agencies face two painful extremes:
- Commercial SaaS platforms charge steep recurring per-domain fees ($72–$240+/month).
- Open-source `parsedmarc` requires running heavy Elasticsearch + Kibana clusters that frequently OOM on small servers.

DMARCZero runs natively on **Node.js >= 24.0.0** with **zero runtime dependencies** and **zero C++ native addons**, paired with a 1-minute **Bring-Your-Own Cloudflare Worker** package so your DMARC aggregate reports never touch third-party servers.

## Architecture

```text
+-------------------------------------------------------------------+
|                     Local CLI / GitHub Actions                    |
|  dmarczero check | snapshot | diff | parse-rua | report           |
|  Node.js 24 built-ins: dns/promises, tls, zlib, crypto, test      |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|             Self-Hosted Cloudflare Worker (BYO Free Tier)         |
|  Email Workers (email()) ---> RUA .xml/.gz/.zip Parser (No RUF)   |
|         |                                  |                      |
|         v                                  v                      |
|  SQLite Durable Object              Cron Drift Sentinel           |
|  (RUA stats + Replay Lock)          (DNS/SSL -> SSRF-Safe Alerts) |
|         |                                                         |
|         v                                                         |
|  Zero-CDN XSS-Safe Web Dashboard + Base USDC License Verifier     |
+-------------------------------------------------------------------+
```

## Quickstart (Local CLI)

Requires **Node.js >= 24.0.0** and **pnpm**.

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build

# 1. Audit DNS (SPF 10-lookup recursion, DMARC, DKIM, MTA-STS, TLS-RPT, CAA) & SSL expiry
node dist/cli.js check example.com --selectors google,selector1,default

# 2. Save baseline snapshot for anti-drift CI guard
node dist/cli.js snapshot example.com --out dmarczero.snapshot.json

# 3. Detect accidental DNS/SSL drift in CI (exits non-zero on drift)
node dist/cli.js diff example.com --snapshot dmarczero.snapshot.json --fail-on-drift

# 4. Stream-parse DMARC RUA reports (.xml, .xml.gz, .zip — strictly rejects RUF PII reports)
node dist/cli.js parse-rua ./rua-reports/ --json

# 5. Generate standalone zero-CDN XSS-safe HTML security report
node dist/cli.js report ./rua-reports/ --out dmarc-report.html

# 6. Verify an optional Ed25519 Team/Enterprise commercial license certificate
node dist/cli.js verify-license ./license.json
```

## BYO Cloudflare Worker Deployment (1-Minute Self-Host)

```bash
cd cloudflare-worker
pnpm install --frozen-lockfile --ignore-scripts
pnpm run typecheck
pnpm test

# Configure your domains and optional webhook secrets via Wrangler:
# wrangler secret put ALERT_WEBHOOK_URL
# wrangler secret put ALLOWED_ORIGINS
pnpm exec wrangler deploy
```

1. Enable **Cloudflare Email Routing** for your domain and route `dmarc@yourdomain.com` to the deployed `dmarczero-worker`.
2. Add `rua=mailto:dmarc@yourdomain.com` to your `_dmarc.yourdomain.com` TXT record.
3. Enjoy 24/7 RUA ingestion + daily Cron DNS/SSL drift alerts directly in your own Cloudflare account.

## Privacy & Security Guarantees

- **Zero RUF / PII Ingestion**: Strictly rejects forensic `RUF` reports containing email content.
- **Zero Telemetry**: Never phones home or sends domain/report data to external servers.
- **Offline Mail-Provider Attribution**: Attributes sending IPs across Google Workspace, Microsoft 365, SendGrid, Amazon SES, Mailgun, Postmark, and Cloudflare Email completely offline with zero external lookups.
- **XSS-Free Rendering & White-Label Export**: HTML reports and the Worker dashboard (including one-click **Export White-Label Client HTML Report**) use zero CDNs and safe text-escaped rendering (zero `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, or `document.write`).
- **SSRF-Protected Webhooks**: Outbound alerts require HTTPS, allowlisted hosts (`discord.com`, `discordapp.com`, `api.telegram.org`, `hooks.slack.com`), private IP blocking, and `redirect: 'manual'`.
- **On-Chain Base USDC Verification**: Worker commercial licensing verifies live Base Mainnet (`eip155:8453`) USDC Transfer receipts, EOA (`EIP-191`) + Smart Wallet (`ERC-1271` / `EIP-6492`) challenge proofs, SQLite `DmarcStoreDO` anti-replay locks, and issues real Ed25519 certificates (`POST /api/license/challenge` + `POST /api/license/verify`).

## Licensing (Solo-Free Full-Open Dual License)

DMARCZero is licensed under the **ApexHive Dual Source-Available License** and ships with **100% of features unlocked** for every user—no HWID binding, no trial timers, and no locked CLI or self-hosted features.

| Tier | Eligibility | Price |
| :--- | :--- | :--- |
| **Solo** | 1 natural person (personal / single-person use) | **0 USDC** (Permanently Free, 100% Full Features) |
| **Team** | 2–99 people / MSP multi-domain commercial use | **Founder Early-Bird 99 USDC** |
| **Enterprise** | 100+ people / white-label deployment | **Founder Early-Bird 499 USDC** |

- Commercial license inquiries: `apexhive.hq@proton.me`
- Voluntary Base USDC tip address (for Solo users who want to support development):
  `0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206`
