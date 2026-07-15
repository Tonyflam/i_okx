"""End-to-end engine tests with mocked outbound HTTP (respx)."""

import json

import httpx
import pytest
import respx

from preflight.engine import KIND_FREE, KIND_PAID, run_audit
from preflight.models import Severity
from preflight.scoring import VERDICT_AT_RISK, VERDICT_READY, VERDICT_WILL_FAIL
from tests.conftest import PUBLIC_IP_RESOLVER, golden_challenge

TARGET = "https://asp.example.com/api/service"


def check_ids(report):
    return {finding.check_id for finding in report.findings}


@pytest.mark.anyio
async def anyio_placeholder():  # pragma: no cover
    pass


@respx.mock
@pytest.mark.asyncio
async def test_free_endpoint_ready(settings):
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(
            200,
            json={"result": "ok"},
            headers={"strict-transport-security": "max-age=63072000"},
        )
    )
    report = await run_audit(TARGET, settings=settings, resolver=PUBLIC_IP_RESOLVER)
    assert report.endpoint_kind == KIND_FREE
    assert report.verdict == VERDICT_READY
    assert report.grade in ("A", "B")
    assert report.latency is not None and len(report.latency.samples_ms) == 3


@respx.mock
@pytest.mark.asyncio
async def test_paid_endpoint_with_golden_challenge_ready(settings):
    challenge = golden_challenge(TARGET)
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(
            402,
            json=challenge,
            headers={"PAYMENT-REQUIRED": "x402"},
        )
    )
    report = await run_audit(
        TARGET, settings=settings, declared_price="0.05", resolver=PUBLIC_IP_RESOLVER
    )
    assert report.endpoint_kind == KIND_PAID
    assert report.verdict == VERDICT_READY
    assert "consistency.price" in check_ids(report)
    price_finding = next(f for f in report.findings if f.check_id == "consistency.price")
    assert price_finding.severity is Severity.PASS


@respx.mock
@pytest.mark.asyncio
async def test_price_mismatch_flagged(settings):
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(402, json=golden_challenge(TARGET))
    )
    report = await run_audit(
        TARGET, settings=settings, declared_price="0.01", resolver=PUBLIC_IP_RESOLVER
    )
    price_finding = next(f for f in report.findings if f.check_id == "consistency.price")
    assert price_finding.severity is Severity.FAIL
    assert report.verdict == VERDICT_AT_RISK


@respx.mock
@pytest.mark.asyncio
async def test_server_error_is_critical(settings):
    respx.route(host="asp.example.com").mock(return_value=httpx.Response(500, text="boom"))
    report = await run_audit(TARGET, settings=settings, quick=True, resolver=PUBLIC_IP_RESOLVER)
    assert report.verdict == VERDICT_WILL_FAIL
    assert "reach.server_error" in check_ids(report)


@respx.mock
@pytest.mark.asyncio
async def test_auth_wall_is_critical(settings):
    respx.route(host="asp.example.com").mock(return_value=httpx.Response(403, json={"detail": "no"}))
    report = await run_audit(TARGET, settings=settings, quick=True, resolver=PUBLIC_IP_RESOLVER)
    assert report.verdict == VERDICT_WILL_FAIL
    assert "reach.auth" in check_ids(report)


@respx.mock
@pytest.mark.asyncio
async def test_unreachable_endpoint(settings):
    respx.route(host="asp.example.com").mock(side_effect=httpx.ConnectError("refused"))
    report = await run_audit(TARGET, settings=settings, quick=True, resolver=PUBLIC_IP_RESOLVER)
    assert report.verdict == VERDICT_WILL_FAIL
    assert "reach.connect" in check_ids(report)


@respx.mock
@pytest.mark.asyncio
async def test_stack_trace_leak_detected(settings):
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(
            200,
            content=b'{"ok": true, "debug": "Traceback (most recent call last):..."}',
            headers={"content-type": "application/json"},
        )
    )
    report = await run_audit(TARGET, settings=settings, quick=True, resolver=PUBLIC_IP_RESOLVER)
    assert "security.leak" in check_ids(report)


@pytest.mark.asyncio
async def test_private_target_blocked_without_network(settings):
    report = await run_audit(
        "https://169.254.169.254/latest/meta-data", settings=settings, resolver=PUBLIC_IP_RESOLVER
    )
    assert report.verdict == VERDICT_WILL_FAIL
    assert "target.unsafe" in check_ids(report)
    assert report.score < 100


@respx.mock
@pytest.mark.asyncio
async def test_html_page_flagged_not_api(settings):
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(
            200, content=b"<html><body>welcome</body></html>", headers={"content-type": "text/html"}
        )
    )
    report = await run_audit(TARGET, settings=settings, quick=True, resolver=PUBLIC_IP_RESOLVER)
    assert "free.html" in check_ids(report)
    assert report.verdict == VERDICT_AT_RISK


@respx.mock
@pytest.mark.asyncio
async def test_malformed_input_5xx_flagged(settings):
    def responder(request: httpx.Request) -> httpx.Response:
        if request.content == b'{"broken":':
            return httpx.Response(500, text="crash")
        return httpx.Response(200, json={"ok": True})

    respx.route(host="asp.example.com").mock(side_effect=responder)
    report = await run_audit(TARGET, settings=settings, resolver=PUBLIC_IP_RESOLVER)
    robust = next(f for f in report.findings if f.check_id == "robust.malformed")
    assert robust.severity is Severity.FAIL


@respx.mock
@pytest.mark.asyncio
async def test_get_only_endpoint_classified_correctly(settings):
    """Regression: real endpoints (e.g. CertiK's live gateway) return 404 on POST
    but 200 on GET — the auditor must not misclassify them as broken."""

    def responder(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"ok": True, "services": []})
        return httpx.Response(404, text="not found")

    respx.route(host="asp.example.com").mock(side_effect=responder)
    report = await run_audit(TARGET, settings=settings, resolver=PUBLIC_IP_RESOLVER)
    assert report.endpoint_kind == KIND_FREE
    assert report.verdict == VERDICT_READY
    assert "reach.method_mismatch" in check_ids(report)
    assert "reach.notfound" not in check_ids(report)
