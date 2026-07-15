"""API tests: routes, persistence, badge, rate limiting."""

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from preflight.config import Settings
from preflight.main import create_app
from tests.conftest import PUBLIC_IP_RESOLVER, golden_challenge

TARGET = "https://asp.example.com/api/service"


@pytest.fixture
def client(settings) -> TestClient:
    app = create_app(settings)
    app.state.resolver = PUBLIC_IP_RESOLVER
    with TestClient(app) as test_client:
        yield test_client


def test_manifest_lists_services(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Preflight"
    assert "check" in data["services"] and "audit" in data["services"]
    assert data["demo"]["broken_endpoint"].endswith("/demo/broken-x402")


def test_root_serves_html_to_browsers(client):
    response = client.get("/", headers={"accept": "text/html,application/xhtml+xml"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Run preflight" in response.text
    # machine callers (agents, curl, the audit engine) still get JSON
    api = client.get("/", headers={"accept": "*/*"})
    assert api.headers["content-type"].startswith("application/json")


def test_demo_broken_endpoint_fails_validation(client):
    from preflight.checks.x402 import validate_x402_challenge
    from preflight.models import Severity as Sev

    for method in ("GET", "POST"):
        response = client.request(method, "/demo/broken-x402")
        assert response.status_code == 402
        challenge = response.json()
        assert challenge["x402Version"] == 1
    findings, _ = validate_x402_challenge(
        response.content, dict(response.headers), "https://preflight.example.com/demo/broken-x402"
    )
    by_check = {f.check_id: f.severity for f in findings}
    assert by_check["x402.version"] is Sev.FAIL
    assert by_check["x402.accepts"] is Sev.CRITICAL


# --- A2MCP compliance (free form): bare probes must return HTTP 200 + result ---


def test_bare_probe_returns_200_usage(client):
    """OKX marketplace probes endpoints without parameters; a compliant free
    A2MCP endpoint must answer 200 with a direct result, never 405/422."""
    for path in ("/check", "/audit"):
        for method in ("GET", "POST"):
            response = client.request(method, path)
            assert response.status_code == 200, f"{method} {path}"
            data = response.json()
            assert data["status"] == "ok"
            assert "url" in data["input"]
            assert "GET" in data["how_to_call"] and "POST" in data["how_to_call"]


def test_bare_post_with_junk_body_returns_200_usage(client):
    response = client.post("/check", content=b"\xff\xfenot json", headers={"content-type": "application/json"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@respx.mock
def test_check_via_get_query_runs_audit(client):
    respx.route(host="asp.example.com").mock(return_value=httpx.Response(200, json={"ok": 1}))
    response = client.get("/check", params={"url": TARGET})
    assert response.status_code == 200
    assert response.json()["verdict"] in {"READY", "AT RISK", "WILL FAIL REVIEW"}


def test_present_but_invalid_url_is_422(client):
    assert client.post("/check", json={"url": "x"}).status_code == 422
    assert client.get("/audit", params={"url": "y"}).status_code == 422


# --- A2MCP compliance (paid form): x402 challenge on unpaid calls ---


def test_paid_mode_emits_valid_x402_challenge(tmp_path, monkeypatch):
    """With payments configured, an unpaid GET /audit must return 402 with the
    base64 challenge in the PAYMENT-REQUIRED header — and our own validator
    must certify it (dogfood: Preflight passes Preflight)."""
    x402_schemas = pytest.importorskip("x402.schemas", reason="payments SDK not installed")
    from x402.http import okx_facilitator_client as okx_client_module

    from preflight.checks.x402 import validate_x402_challenge
    from preflight.models import Severity as Sev

    def fake_get_supported(self):
        return x402_schemas.SupportedResponse.model_validate(
            {"kinds": [{"x402Version": 2, "scheme": "exact", "network": "eip155:196"}]}
        )

    monkeypatch.setattr(
        okx_client_module.OKXFacilitatorClient, "get_supported", fake_get_supported
    )

    pay_to = "0x28cbe4a226767dbe2fd0719ed759fc211823661b"
    paid_settings = Settings(
        db_path=str(tmp_path / "paid.db"),
        public_base_url="https://preflight.example.com",
        payments_enabled=True,
        pay_to_address=pay_to,
        audit_price_usd="$0.05",
        okx_api_key="stub",
        okx_secret_key="stub",
        okx_passphrase="stub",
        _env_file=None,
    )
    app = create_app(paid_settings)
    app.state.resolver = PUBLIC_IP_RESOLVER
    with TestClient(app) as paid_client:
        response = paid_client.get("/audit")
        assert response.status_code == 402
        assert "payment-required" in {k.lower() for k in response.headers}

        findings, amounts = validate_x402_challenge(
            response.content,
            dict(response.headers),
            "https://preflight.example.com/audit",
        )
        blocking = [f for f in findings if f.severity in (Sev.CRITICAL, Sev.FAIL)]
        assert blocking == [], [f"{f.check_id}: {f.title}" for f in blocking]
        assert amounts == [50000]  # $0.05 in USDT0 min units (6 decimals)

        # free surfaces stay free in paid mode
        assert paid_client.get("/check").status_code == 200
        assert paid_client.get("/healthz").status_code == 200


def test_rate_limit_keys_on_forwarded_client(tmp_path):
    """Behind Railway's edge, the rightmost XFF entry identifies the client."""
    settings = Settings(
        db_path=str(tmp_path / "xff.db"),
        rate_limit_per_minute=1,
        public_base_url="https://preflight.example.com",
        _env_file=None,
    )
    app = create_app(settings)
    app.state.resolver = PUBLIC_IP_RESOLVER
    with TestClient(app) as test_client, respx.mock:
        respx.route(host="asp.example.com").mock(return_value=httpx.Response(200, json={"ok": 1}))
        first = test_client.post(
            "/check", json={"url": TARGET}, headers={"x-forwarded-for": "6.6.6.6, 1.1.1.1"}
        )
        assert first.status_code == 200
        # same rightmost hop, different (spoofed) leftmost entry → still limited
        spoofed = test_client.post(
            "/check", json={"url": TARGET}, headers={"x-forwarded-for": "9.9.9.9, 1.1.1.1"}
        )
        assert spoofed.status_code == 429
        # genuinely different client → allowed
        other = test_client.post(
            "/check", json={"url": TARGET}, headers={"x-forwarded-for": "6.6.6.6, 2.2.2.2"}
        )
        assert other.status_code == 200


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@respx.mock
def test_check_and_report_lifecycle(client):
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(402, json=golden_challenge(TARGET))
    )
    response = client.post("/check", json={"url": TARGET})
    assert response.status_code == 200
    body = response.json()
    assert body["endpoint_kind"] == "x402-paid"
    assert body["verdict"] == "READY"

    report_id = body["report_id"]
    stored = client.get(f"/audit/{report_id}")
    assert stored.status_code == 200
    assert stored.json()["target_url"] == TARGET

    markdown = client.get(f"/audit/{report_id}", params={"format": "md"})
    assert markdown.status_code == 200
    assert "Preflight audit" in markdown.text

    html_page = client.get(f"/audit/{report_id}", params={"format": "html"})
    assert html_page.status_code == 200
    assert html_page.headers["content-type"].startswith("text/html")
    assert "READY" in html_page.text and "badge.svg" in html_page.text

    badge = client.get(f"/audit/{report_id}/badge.svg")
    assert badge.status_code == 200
    assert badge.headers["content-type"].startswith("image/svg+xml")
    assert "READY" in badge.text


@respx.mock
def test_audit_full_report(client):
    respx.route(host="asp.example.com").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    response = client.post("/audit", json={"url": TARGET, "declared_price": "0.05"})
    assert response.status_code == 200
    body = response.json()
    assert body["endpoint_kind"] == "free"
    # free endpoint with declared price → listing inconsistency
    price = next(f for f in body["findings"] if f["check_id"] == "consistency.price")
    assert price["severity"] == "fail"
    assert body["report_url"].endswith(body["report_id"])


def test_unknown_report_404(client):
    assert client.get("/audit/doesnotexist").status_code == 404


def test_invalid_body_422(client):
    assert client.post("/check", json={"url": "x"}).status_code == 422
    # empty body is a bare probe -> A2MCP usage result, not an error
    assert client.post("/check", json={}).status_code == 200


@respx.mock
def test_rate_limit_trips(tmp_path):
    settings = Settings(
        db_path=str(tmp_path / "rl.db"),
        rate_limit_per_minute=2,
        public_base_url="https://preflight.example.com",
        _env_file=None,
    )
    app = create_app(settings)
    app.state.resolver = PUBLIC_IP_RESOLVER
    respx.route(host="asp.example.com").mock(return_value=httpx.Response(200, json={"ok": 1}))
    with TestClient(app) as test_client:
        assert test_client.post("/check", json={"url": TARGET}).status_code == 200
        assert test_client.post("/check", json={"url": TARGET}).status_code == 200
        assert test_client.post("/check", json={"url": TARGET}).status_code == 429
