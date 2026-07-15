"""Free-endpoint validation: compliant free A2MCP endpoints return HTTP 200 with the result."""

from __future__ import annotations

import json
from typing import Mapping

from ..models import Category, Finding, Severity


def validate_free_response(headers: Mapping[str, str], body: bytes) -> list[Finding]:
    findings: list[Finding] = [
        Finding(
            check_id="free.status",
            category=Category.PROTOCOL,
            severity=Severity.PASS,
            title="Endpoint returns HTTP 200 with a direct result",
        )
    ]

    content_type = ""
    for name, value in headers.items():
        if name.lower() == "content-type":
            content_type = value.lower()
            break

    stripped = body.lstrip()[:512].lower()
    if stripped.startswith((b"<!doctype html", b"<html")):
        findings.append(
            Finding(
                check_id="free.html",
                category=Category.PROTOCOL,
                severity=Severity.FAIL,
                title="Endpoint returns an HTML page, not an API result",
                detail="Agents need machine-readable results; an HTML page suggests a website or error page.",
                fix="Return the service result as JSON (or another machine-readable format).",
            )
        )
        return findings

    if not body.strip():
        findings.append(
            Finding(
                check_id="free.body",
                category=Category.PROTOCOL,
                severity=Severity.FAIL,
                title="Response body is empty",
                fix="Return the service result directly in the response body.",
            )
        )
        return findings

    if "json" in content_type:
        try:
            json.loads(body.decode("utf-8"))
            findings.append(
                Finding(
                    check_id="free.json",
                    category=Category.PROTOCOL,
                    severity=Severity.PASS,
                    title="Response is valid JSON",
                )
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            findings.append(
                Finding(
                    check_id="free.json",
                    category=Category.PROTOCOL,
                    severity=Severity.FAIL,
                    title="Content-Type claims JSON but the body does not parse",
                    fix="Return valid JSON or correct the Content-Type header.",
                )
            )
    else:
        findings.append(
            Finding(
                check_id="free.content_type",
                category=Category.PROTOCOL,
                severity=Severity.WARN,
                title="Response Content-Type is not JSON",
                detail=f"Got '{content_type or '(none)'}'.",
                fix="Serve results as application/json for maximum agent compatibility.",
            )
        )

    return findings
