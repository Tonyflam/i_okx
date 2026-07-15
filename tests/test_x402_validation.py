"""x402 v2 challenge validator tests: every spec violation must be named and fixable."""

import json

from preflight.checks.x402 import validate_x402_challenge
from preflight.models import Severity
from tests.conftest import golden_challenge

TARGET = "https://asp.example.com/api/service"
HEADERS = {"PAYMENT-REQUIRED": "x402", "content-type": "application/json"}


def run(challenge: dict, headers=HEADERS):
    body = json.dumps(challenge).encode()
    return validate_x402_challenge(body, headers, TARGET)


def severities_by_check(findings):
    return {finding.check_id: finding.severity for finding in findings}


def test_golden_challenge_has_no_failures():
    findings, amounts = run(golden_challenge())
    bad = [f for f in findings if f.severity in (Severity.FAIL, Severity.CRITICAL)]
    assert bad == []
    assert amounts == [50000]


def test_non_json_body_is_critical():
    findings, _ = validate_x402_challenge(b"<html>oops</html>", HEADERS, TARGET)
    assert severities_by_check(findings)["x402.parse"] is Severity.CRITICAL


def test_wrong_version_fails():
    challenge = golden_challenge()
    challenge["x402Version"] = 1
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.version"] is Severity.FAIL


def test_empty_accepts_is_critical():
    challenge = golden_challenge()
    challenge["accepts"] = []
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.accepts"] is Severity.CRITICAL


def test_wrong_scheme_fails():
    challenge = golden_challenge()
    challenge["accepts"][0]["scheme"] = "proportional"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.scheme.0"] is Severity.FAIL


def test_testnet_network_fails_review_readiness():
    challenge = golden_challenge()
    challenge["accepts"][0]["network"] = "eip155:1952"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.network.0"] is Severity.FAIL


def test_malformed_network_fails():
    challenge = golden_challenge()
    challenge["accepts"][0]["network"] = "xlayer-mainnet"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.network.0"] is Severity.FAIL


def test_unexpected_chain_warns():
    challenge = golden_challenge()
    challenge["accepts"][0]["network"] = "eip155:1"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.network.0"] is Severity.WARN


def test_wrong_asset_on_mainnet_warns():
    challenge = golden_challenge()
    challenge["accepts"][0]["asset"] = "0x" + "ab" * 20
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.asset.0"] is Severity.WARN


def test_zero_amount_fails():
    challenge = golden_challenge()
    challenge["accepts"][0]["amount"] = "0"
    findings, amounts = run(challenge)
    assert severities_by_check(findings)["x402.amount.0"] is Severity.FAIL
    assert amounts == []


def test_non_numeric_amount_fails():
    challenge = golden_challenge()
    challenge["accepts"][0]["amount"] = "abc"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.amount.0"] is Severity.FAIL


def test_invalid_payto_fails():
    challenge = golden_challenge()
    challenge["accepts"][0]["payTo"] = "0x123"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.payto.0"] is Severity.FAIL


def test_zero_address_payto_fails():
    challenge = golden_challenge()
    challenge["accepts"][0]["payTo"] = "0x" + "0" * 40
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.payto.0"] is Severity.FAIL


def test_http_resource_url_fails():
    challenge = golden_challenge()
    challenge["resource"]["url"] = "http://asp.example.com/api/service"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.resource.url"] is Severity.FAIL


def test_resource_host_mismatch_warns():
    challenge = golden_challenge()
    challenge["resource"]["url"] = "https://other.example.org/api/service"
    findings, _ = run(challenge)
    assert severities_by_check(findings)["x402.resource.url"] is Severity.WARN


def test_missing_payment_required_header_is_info_only():
    findings, _ = run(golden_challenge(), headers={"content-type": "application/json"})
    assert severities_by_check(findings)["x402.header"] is Severity.INFO


def test_every_failure_ships_a_fix():
    challenge = golden_challenge()
    challenge["accepts"][0].update(
        {"scheme": "bad", "network": "bad", "amount": "-1", "payTo": "bad"}
    )
    findings, _ = run(challenge)
    for finding in findings:
        if finding.severity in (Severity.FAIL, Severity.CRITICAL):
            assert finding.fix, f"{finding.check_id} has no fix text"


def test_challenge_carried_in_base64_header():
    """Production pattern (e.g. CertiK via OKX Payment SDK): empty JSON body,
    base64-encoded challenge in the PAYMENT-REQUIRED header. A body-only
    validator false-positives here — we must not."""
    import base64

    challenge = golden_challenge()
    headers = {
        "PAYMENT-REQUIRED": base64.b64encode(json.dumps(challenge).encode()).decode(),
        "content-type": "application/json",
    }
    findings, amounts = validate_x402_challenge(b"{}", headers, TARGET)
    bad = [f for f in findings if f.severity in (Severity.FAIL, Severity.CRITICAL)]
    assert bad == []
    assert amounts == [50000]
    carrier = next(f for f in findings if f.check_id == "x402.carrier")
    assert "header" in carrier.title


def test_header_challenge_with_http_resource_url_still_flagged():
    import base64

    challenge = golden_challenge()
    challenge["resource"]["url"] = "http://asp.example.com/api/service"
    headers = {"PAYMENT-REQUIRED": base64.b64encode(json.dumps(challenge).encode()).decode()}
    findings, _ = validate_x402_challenge(b"{}", headers, TARGET)
    assert severities_by_check(findings)["x402.resource.url"] is Severity.FAIL


def test_no_challenge_anywhere_is_critical():
    findings, _ = validate_x402_challenge(b"", {"content-type": "text/plain"}, TARGET)
    assert severities_by_check(findings)["x402.parse"] is Severity.CRITICAL
