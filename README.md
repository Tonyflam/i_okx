# Preflight ✈️

**Pass OKX.AI review the first time. Audit any agent-service endpoint in 30 seconds.**

**Live:** https://preflight-production-2f9c.up.railway.app — landing UI for browsers, JSON manifest for agents (content-negotiated on `Accept`).

Preflight is an Agent Service Provider (ASP) for [OKX.AI](https://www.okx.ai) that audits *other* agent services. Give it an endpoint URL; it returns a graded conformance report — protocol compliance, field-by-field x402 v2 payment-challenge validation, reliability, robustness, security posture, and listing-price consistency — with a prioritized fix list and a live status badge. Reports render as JSON, Markdown, or a shareable HTML page.

## Why

- OKX.AI requires every ASP endpoint to pass internal review: *"a non-compliant endpoint won't pass review"* ([A2MCP guide](https://web3.okx.com/onchainos/dev-docs/okxai/howtomcp)). The only sanctioned self-check is `curl -i`.
- Marketplace reviews document x402 validation **false positives** across live ASPs.
- Buyers (human or agent) have no independent signal that an endpoint is up, spec-compliant, and priced as listed before they pay it.

Preflight closes all three gaps with a deterministic rubric — **no LLM in the verdict path**, so it never hallucinates a compliance result.

## Proof it works on production endpoints

Run against a live official OKX.AI production gateway, Preflight correctly parses its base64 header-carried x402 challenge (a pattern body-only validators misreport), verifies the 0.001 USDT declared price matches the challenge amount, and catches a genuine spec violation (`resource.url` served as `http://`).

Try it yourself against the built-in intentionally broken fixture:

```bash
curl -s -X POST https://preflight-production-2f9c.up.railway.app/audit \
  -H 'content-type: application/json' \
  -d '{"url": "https://preflight-production-2f9c.up.railway.app/demo/broken-x402"}'
# → verdict WILL FAIL REVIEW, grade F, with an exact fix per finding
```

## Quickstart

```bash
pip install -e '.[dev]'
cp .env.example .env
uvicorn preflight.main:app --port 8000
```

Quick check (free service):

```bash
curl -s -X POST http://localhost:8000/check \
  -H 'content-type: application/json' \
  -d '{"url": "https://your-endpoint.example.com/api/service"}'
```

Deep audit (paid via x402 when configured; includes listing-consistency check):

```bash
curl -s -X POST http://localhost:8000/audit \
  -H 'content-type: application/json' \
  -d '{"url": "https://your-endpoint.example.com/api/service", "declared_price": "0.05"}'
```

Every audit returns a `report_url` (JSON or `?format=md`) and a `badge_url` — a live SVG shield you can embed:

```markdown
![Preflight](https://your-preflight-host/audit/<report_id>/badge.svg)
```

## What gets checked

| Category | Examples |
|---|---|
| Reachability | DNS/TLS, latency (3 samples), redirects, auth walls, response size |
| Protocol | free endpoints: HTTP 200 + machine-readable result; no HTML error pages |
| Payment (x402 v2) | version, challenge carrier (body **or** base64 `PAYMENT-REQUIRED` header), `accepts[]`, `scheme=exact`, `network=eip155:196`, USDT0 asset, amount units, `payTo` address, timeouts, `resource.url` |
| Robustness | malformed-input handling, method discipline, repeat-call consistency |
| Security | stack-trace/error leakage, HSTS, version disclosure |
| Consistency | declared listing price vs. on-chain challenge amount |

Verdicts: **READY** · **AT RISK** · **WILL FAIL REVIEW** — with a fix per finding.

## API

| Route | Price | Purpose |
|---|---|---|
| `GET /` | free | landing page (browsers) / service manifest (agents) |
| `POST /check` | free | quick verdict (single probe) |
| `POST /audit` | 0.05 USDT via x402 (free until payments enabled) | full graded report |
| `GET /audit/{id}` | free | stored report (`?format=md` markdown, `?format=html` shareable page) |
| `GET /audit/{id}/badge.svg` | free | live status badge |
| `POST /self-audit` | free | Preflight audits its own manifest (dogfood) |
| `GET /demo/broken-x402` | free | intentionally broken x402 endpoint for demos/testing |
| `GET /healthz` | free | liveness |

## Security model

Preflight fetches caller-supplied URLs, so it is designed fail-closed against SSRF:

- HTTPS-only targets (HTTP allowed only via an explicit dev flag)
- Rejects credentials-in-URL, IP literals and hostnames resolving to private/loopback/link-local/reserved ranges (all records must be public)
- Never follows redirects; 512 KB response cap; 10 s request / 30 s audit budget
- Per-IP rate limiting; report data contains no PII; secrets via env only, never logged
- Known residual risk: DNS rebinding between validation and request (documented; mitigated by re-resolution, short timeouts, no redirects)

## Payments (x402)

The deep-audit route is gated with the official OKX Payment SDK when configured:

```bash
pip install -e '.[payments]'
# set in .env: PREFLIGHT_PAYMENTS_ENABLED=true, PREFLIGHT_PAY_TO_ADDRESS,
# PREFLIGHT_OKX_API_KEY / SECRET_KEY / PASSPHRASE  (https://web3.okx.com/onchainos/dev-portal)
```

Without credentials the service runs in free mode — still a compliant A2MCP listing.

## Deploy

Production runs on Railway ([railway.json](railway.json) included — Dockerfile build, `/healthz` health check, volume at `/data`):

```bash
railway up --ci
# required env: PREFLIGHT_DB_PATH=/data/preflight.db, RAILWAY_RUN_UID=0 (non-root image + volume)
# PREFLIGHT_PUBLIC_BASE_URL is inferred automatically from RAILWAY_PUBLIC_DOMAIN
```

Or any host with public HTTPS:

```bash
docker build -t preflight .
docker run -p 8000:8000 -e PREFLIGHT_PUBLIC_BASE_URL=https://your-domain preflight
```

Self-check before listing (per OKX docs): `curl -i https://your-domain/check` → expect 405/422 on GET, 200 on a valid POST; `curl -i -X POST https://your-domain/audit` → expect 402 once payments are enabled.

## Listing on OKX.AI (runbook)

1. `npx skills add okx/onchainos-skills --yes -g` in your agent, log in to Agentic Wallet with your email.
2. Prompt: `Help me register an A2MCP ASP on OKX.AI using Onchain OS` — supply name **Preflight**, the description above, price (0 for `/check`, 0.05 for `/audit`), endpoint URLs.
3. Prompt: `Help me list my ASP on OKX.AI using Onchain OS` — review completes within 24 h.

## Tests

```bash
python -m pytest -q   # 70 tests: SSRF guard, x402 validator, scoring, engine (mocked HTTP), API, rate limiting
```
