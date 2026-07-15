"""Security-posture checks on captured responses (headers + body leakage)."""

from __future__ import annotations

from typing import Mapping

from ..models import Category, Finding, Severity

_LEAK_MARKERS = (
    b"Traceback (most recent call last)",
    b"\tat java.",
    b"goroutine ",
    b"node_modules/",
    b"Whitelabel Error Page",
    b"Fatal error:",
    b"ORA-",
    b"psycopg2.",
)


def analyze_response_security(headers: Mapping[str, str], body: bytes) -> list[Finding]:
    findings: list[Finding] = []
    lower_headers = {name.lower(): value for name, value in headers.items()}

    if "strict-transport-security" in lower_headers:
        findings.append(
            Finding(
                check_id="security.hsts",
                category=Category.SECURITY,
                severity=Severity.PASS,
                title="HSTS header present",
            )
        )
    else:
        findings.append(
            Finding(
                check_id="security.hsts",
                category=Category.SECURITY,
                severity=Severity.INFO,
                title="No Strict-Transport-Security header",
                fix="Add an HSTS header at your TLS terminator.",
            )
        )

    server = lower_headers.get("server", "")
    if any(char.isdigit() for char in server):
        findings.append(
            Finding(
                check_id="security.server_header",
                category=Category.SECURITY,
                severity=Severity.INFO,
                title="Server header discloses software version",
                detail=f"Server: {server}",
                fix="Strip version details from the Server header.",
            )
        )

    for marker in _LEAK_MARKERS:
        if marker in body:
            findings.append(
                Finding(
                    check_id="security.leak",
                    category=Category.SECURITY,
                    severity=Severity.FAIL,
                    title="Response leaks internal error details",
                    detail=f"Found marker: {marker.decode(errors='replace').strip()!r}",
                    fix="Return a generic error body; log stack traces server-side only.",
                )
            )
            break

    return findings
