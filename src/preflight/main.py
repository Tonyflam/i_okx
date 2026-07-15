"""Preflight HTTP API.

Routes:
- GET  /            service manifest (free; also serves as the self-audit target)
- GET  /healthz     liveness
- GET|POST /check   quick conformance check (free service on OKX.AI; bare call → usage)
- GET|POST /audit   deep audit (x402-paid when configured; bare call → usage in free mode)
- GET  /audit/{id}  stored report (?format=md for markdown)
- GET  /audit/{id}/badge.svg  live status badge
- POST /self-audit  dogfood: Preflight audits its own manifest endpoint
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field, ValidationError

from . import __version__
from .config import Settings
from .engine import run_audit
from .models import AuditReport, Severity
from .ratelimit import RateLimiter
from .render import badge_svg, report_markdown
from .store import ReportStore
from .ui import LANDING_HTML, report_html

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("preflight.api")


class CheckRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048, description="Public HTTPS endpoint to audit")


class AuditRequest(CheckRequest):
    declared_price: str | None = Field(
        default=None,
        max_length=32,
        description='Price you will declare on your OKX.AI listing, e.g. "0.05" (USDT)',
    )


def _condensed(report: AuditReport, base_url: str) -> dict:
    interesting = [
        finding
        for finding in report.findings
        if finding.severity in (Severity.CRITICAL, Severity.FAIL, Severity.WARN)
    ][:6]
    return {
        "report_id": report.report_id,
        "verdict": report.verdict,
        "grade": report.grade,
        "score": report.score,
        "endpoint_kind": report.endpoint_kind,
        "summary": report.summary,
        "top_issues": [
            {"check": finding.check_id, "severity": finding.severity.value, "title": finding.title, "fix": finding.fix}
            for finding in interesting
        ],
        "report_url": f"{base_url}/audit/{report.report_id}",
        "badge_url": f"{base_url}/audit/{report.report_id}/badge.svg",
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.store = ReportStore(settings.db_path)
        app.state.limiter = RateLimiter(settings.rate_limit_per_minute)
        if not hasattr(app.state, "resolver"):
            app.state.resolver = None  # tests may inject a stub DNS resolver
        yield

    app = FastAPI(
        title="Preflight",
        version=__version__,
        description="Conformance auditor for agent service endpoints (OKX.AI ASPs).",
        lifespan=lifespan,
    )

    from .payments import build_payment_middleware

    payment = build_payment_middleware(settings)
    if payment is not None:
        middleware_cls, kwargs = payment
        app.add_middleware(middleware_cls, **kwargs)

    def _client_key(request: Request) -> str:
        # Behind Railway's edge proxy the socket peer is the proxy, and the
        # rightmost X-Forwarded-For entry is the address the edge actually
        # accepted the connection from (unspoofable by the client). Some
        # proxies append it as ip:port with an ephemeral port — strip it so
        # one client maps to one key.
        forwarded = request.headers.get("x-forwarded-for", "")
        key = forwarded.rsplit(",", 1)[-1].strip() if forwarded else (
            request.client.host if request.client else "unknown"
        )
        if key.startswith("["):  # [ipv6]:port
            key = key[1:].split("]", 1)[0]
        elif key.count(":") == 1:  # ipv4:port
            key = key.split(":", 1)[0]
        return key

    def _enforce_rate_limit(request: Request) -> None:
        if not app.state.limiter.allow(_client_key(request)):
            raise HTTPException(status_code=429, detail="Rate limit exceeded; try again in a minute.")

    @app.get("/")
    async def root(request: Request) -> Response:
        if "text/html" in request.headers.get("accept", ""):
            return Response(LANDING_HTML, media_type="text/html; charset=utf-8")
        return Response(
            _manifest_json(), media_type="application/json", headers={"vary": "accept"}
        )

    def _manifest_payload() -> dict:
        return {
            "name": "Preflight",
            "tagline": "Pass OKX.AI review the first time. Audit any agent endpoint in 30 seconds.",
            "version": __version__,
            "services": {
                "check": {
                    "method": "GET or POST",
                    "path": "/check",
                    "price": "free",
                    "input": {"url": "https://your-endpoint.example.com/api"},
                    "output": "verdict, grade, top issues",
                },
                "audit": {
                    "method": "GET or POST",
                    "path": "/audit",
                    "price": settings.audit_price_usd if settings.payments_enabled else "free (launch)",
                    "input": {"url": "…", "declared_price": "0.05 (optional)"},
                    "output": "full graded report: protocol, x402 challenge, reliability, robustness, security, listing consistency",
                },
            },
            "demo": {
                "broken_endpoint": f"{settings.public_base_url.rstrip('/')}/demo/broken-x402",
                "note": "deliberately non-compliant x402 endpoint for trying Preflight",
            },
            "docs": "https://github.com/Tonyflam/i_okx#readme",
        }

    def _manifest_json() -> str:
        return json.dumps(_manifest_payload(), ensure_ascii=False)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "reports_stored": app.state.store.count()}

    async def _run_and_store(url: str, *, quick: bool, declared_price: str | None) -> AuditReport:
        report = await run_audit(
            url,
            settings=settings,
            quick=quick,
            declared_price=declared_price,
            resolver=app.state.resolver,
        )
        await asyncio.to_thread(app.state.store.save, report)
        return report

    def _usage_payload(service: str) -> dict:
        """HTTP 200 usage description for parameter-less calls.

        A2MCP compliance: a free endpoint must answer a bare probe with 200 and
        a direct result — never 405/422. This payload doubles as the machine-
        readable how-to-call contract for agent buyers.
        """
        base = settings.public_base_url.rstrip("/")
        price = (
            settings.audit_price_usd
            if (service == "audit" and settings.payments_enabled)
            else "free"
        )
        fields: dict = {"url": "required — public HTTPS endpoint to audit"}
        if service == "audit":
            fields["declared_price"] = (
                'optional — USDT price declared on your OKX.AI listing, e.g. "0.05"'
            )
        return {
            "service": f"Preflight /{service}",
            "status": "ok",
            "price": price,
            "input": fields,
            "how_to_call": {
                "GET": f"{base}/{service}?url=https://target.example.com/api",
                "POST": {
                    "url": f"{base}/{service}",
                    "body": {"url": "https://target.example.com/api"},
                },
            },
            "manifest": f"{base}/",
        }

    async def _request_payload(request: Request) -> dict | None:
        """Extract parameters from GET query or POST JSON body; None if absent."""
        if request.method == "GET":
            params = dict(request.query_params)
            return params or None
        raw = await request.body()
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _validated(model: type[BaseModel], data: dict) -> BaseModel:
        try:
            return model.model_validate(
                {key: value for key, value in data.items() if key in model.model_fields}
            )
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors(include_url=False)) from exc

    @app.api_route("/check", methods=["GET", "POST"])
    async def check(request: Request) -> dict:
        data = await _request_payload(request)
        if not data or "url" not in data:
            return _usage_payload("check")
        body = _validated(CheckRequest, data)
        _enforce_rate_limit(request)
        report = await _run_and_store(body.url, quick=True, declared_price=None)
        return _condensed(report, settings.public_base_url.rstrip("/"))

    @app.api_route("/audit", methods=["GET", "POST"])
    async def audit(request: Request) -> dict:
        data = await _request_payload(request)
        if not data or "url" not in data:
            return _usage_payload("audit")
        body = _validated(AuditRequest, data)
        _enforce_rate_limit(request)
        report = await _run_and_store(body.url, quick=False, declared_price=body.declared_price)
        payload = report.model_dump(mode="json")
        payload["report_url"] = f"{settings.public_base_url.rstrip('/')}/audit/{report.report_id}"
        payload["badge_url"] = f"{settings.public_base_url.rstrip('/')}/audit/{report.report_id}/badge.svg"
        return payload

    @app.get("/audit/{report_id}")
    async def get_report(report_id: str, format: str = "json") -> Response:
        report = await asyncio.to_thread(app.state.store.get, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found")
        if format == "md":
            return Response(report_markdown(report), media_type="text/markdown; charset=utf-8")
        if format == "html":
            return Response(
                report_html(report, settings.public_base_url),
                media_type="text/html; charset=utf-8",
            )
        return Response(report.model_dump_json(indent=2), media_type="application/json")

    @app.get("/audit/{report_id}/badge.svg")
    async def get_badge(report_id: str) -> Response:
        report = await asyncio.to_thread(app.state.store.get, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return Response(
            badge_svg(report),
            media_type="image/svg+xml",
            headers={"cache-control": "no-cache, max-age=300"},
        )

    @app.post("/self-audit")
    async def self_audit(request: Request) -> dict:
        _enforce_rate_limit(request)
        target = settings.public_base_url.rstrip("/") + "/"
        report = await _run_and_store(target, quick=False, declared_price=None)
        return _condensed(report, settings.public_base_url.rstrip("/"))
    @app.api_route("/demo/broken-x402", methods=["GET", "POST"], include_in_schema=True)
    async def demo_broken_x402() -> Response:
        """A deliberately non-compliant x402 endpoint so anyone can see Preflight
        catch real problems without pointing it at a third party. Canned response;
        not rate limited."""
        base = settings.public_base_url.rstrip("/")
        insecure = "http://" + base.split("://", 1)[-1]
        challenge = {
            "x402Version": 1,  # wrong version (must be 2)
            "resource": {
                "url": f"{insecure}/demo/broken-x402",  # not HTTPS
                "description": "Intentionally broken demo endpoint",
                "mimeType": "application/json",
            },
            # missing accepts[] entirely — no way to pay
        }
        return Response(
            json.dumps(challenge),
            status_code=402,
            media_type="application/json",
            headers={"x-preflight-demo": "broken-x402"},
        )

    return app


app = create_app()
