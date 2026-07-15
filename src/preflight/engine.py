"""Audit engine: probes a target endpoint and produces a deterministic report.

Probe sequence (bounded by an overall time budget):
1. SSRF-safe URL validation (fail closed).
2. Baseline request (POST {} → fall back to GET on 405) → classify endpoint kind.
3. Kind-specific validation (x402 v2 challenge / free-result rules).
4. Latency sampling (full audit only).
5. Robustness probes: malformed body, alternate method (full audit only).
6. Security-posture analysis and listing-price consistency.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import httpx

from . import __version__
from .checks.free import validate_free_response
from .checks.security import analyze_response_security
from .checks.x402 import validate_x402_challenge
from .config import Settings
from .models import AuditReport, Category, Finding, LatencyStats, Severity
from .scoring import compute_score, fix_list, grade_for, summarize, verdict_for
from .ssrf import Resolver, TargetValidationError, validate_target_url

logger = logging.getLogger("preflight.engine")

USER_AGENT = f"PreflightAuditor/{__version__} (+conformance audit; contact via OKX.AI listing)"

KIND_PAID = "x402-paid"
KIND_FREE = "free"
KIND_UNKNOWN = "unknown"


class _Probe:
    """Captured response snapshot."""

    __slots__ = ("status", "headers", "body", "elapsed_ms", "truncated")

    def __init__(self, status: int, headers: httpx.Headers, body: bytes, elapsed_ms: float, truncated: bool):
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed_ms = elapsed_ms
        self.truncated = truncated


async def _request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    content: bytes | None = None,
    json_body: dict | None = None,
) -> _Probe:
    started = time.perf_counter()
    request = client.build_request(
        method,
        url,
        content=content,
        json=json_body if content is None else None,
        headers={"accept": "application/json"},
    )
    response = await client.send(request, stream=True)
    body = b""
    truncated = False
    try:
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                truncated = True
                break
    finally:
        await response.aclose()
    elapsed_ms = (time.perf_counter() - started) * 1000
    return _Probe(response.status_code, response.headers, body, elapsed_ms, truncated)


def _classification_findings(status: int) -> tuple[str, list[Finding]]:
    """Map an unexpected baseline status to endpoint kind + findings."""
    if status in (401, 403):
        return KIND_UNKNOWN, [
            Finding(
                check_id="reach.auth",
                category=Category.REACHABILITY,
                severity=Severity.CRITICAL,
                title=f"Endpoint requires authentication (HTTP {status})",
                detail="Marketplace agents cannot present custom credentials; the endpoint must be free (200) or x402-gated (402).",
                fix="Remove auth walls; gate payment with x402 instead.",
            )
        ]
    if 300 <= status < 400:
        return KIND_UNKNOWN, [
            Finding(
                check_id="reach.redirect",
                category=Category.REACHABILITY,
                severity=Severity.FAIL,
                title=f"Endpoint redirects (HTTP {status})",
                detail="Agent clients may not follow redirects; the registered URL must answer directly.",
                fix="Register the final URL, or stop redirecting.",
            )
        ]
    if status == 404:
        return KIND_UNKNOWN, [
            Finding(
                check_id="reach.notfound",
                category=Category.REACHABILITY,
                severity=Severity.CRITICAL,
                title="Endpoint returns HTTP 404",
                fix="Verify the exact path you plan to register — it does not exist on this server.",
            )
        ]
    if status >= 500:
        return KIND_UNKNOWN, [
            Finding(
                check_id="reach.server_error",
                category=Category.REACHABILITY,
                severity=Severity.CRITICAL,
                title=f"Endpoint returns a server error (HTTP {status})",
                fix="Fix the crash: a 5xx on a plain request will fail review immediately.",
            )
        ]
    return KIND_UNKNOWN, [
        Finding(
            check_id="reach.status",
            category=Category.REACHABILITY,
            severity=Severity.FAIL,
            title=f"Unexpected baseline status HTTP {status}",
            detail="Compliant endpoints return 200 (free) or 402 (x402 paid) on a plain call.",
            fix="Return 200 with the result, or a 402 x402 challenge.",
        )
    ]


def _parse_declared_price_min_units(declared_price: str) -> int | None:
    text = declared_price.strip().lstrip("$").replace("usdt", "").replace("USDT", "").strip()
    try:
        value = Decimal(text)
    except InvalidOperation:
        return None
    if value <= 0:
        return None
    return int(value * 1_000_000)


def _consistency_findings(
    declared_price: str | None, endpoint_kind: str, amounts: list[int]
) -> list[Finding]:
    if not declared_price:
        return []
    declared_units = _parse_declared_price_min_units(declared_price)
    if declared_units is None:
        return [
            Finding(
                check_id="consistency.price_input",
                category=Category.CONSISTENCY,
                severity=Severity.INFO,
                title=f"Could not parse declared price {declared_price!r}",
                fix='Pass declared_price like "0.05" or "$0.05" (USDT).',
            )
        ]
    if endpoint_kind == KIND_FREE:
        return [
            Finding(
                check_id="consistency.price",
                category=Category.CONSISTENCY,
                severity=Severity.FAIL,
                title="Listing declares a price but the endpoint is free",
                detail=f"Declared {declared_units / 1_000_000:.6f} USDT; endpoint returned 200 with no payment challenge.",
                fix="Either list the service as free (price 0) or gate it with x402.",
            )
        ]
    if endpoint_kind == KIND_PAID:
        if declared_units in amounts:
            return [
                Finding(
                    check_id="consistency.price",
                    category=Category.CONSISTENCY,
                    severity=Severity.PASS,
                    title="Declared listing price matches the challenge amount",
                )
            ]
        got = ", ".join(f"{a / 1_000_000:.6f}" for a in amounts) or "none parseable"
        return [
            Finding(
                check_id="consistency.price",
                category=Category.CONSISTENCY,
                severity=Severity.FAIL,
                title="Declared listing price does NOT match the challenge amount",
                detail=f"Listing says {declared_units / 1_000_000:.6f} USDT; challenge offers: {got} USDT.",
                fix="Make the accepts[].amount equal the price you register on OKX.AI.",
            )
        ]
    return []


def _latency_findings(samples_ms: list[float]) -> tuple[LatencyStats, list[Finding]]:
    stats = LatencyStats(
        samples_ms=[round(sample, 1) for sample in samples_ms],
        median_ms=round(statistics.median(samples_ms), 1),
        max_ms=round(max(samples_ms), 1),
    )
    if stats.median_ms > 8000:
        severity, title = Severity.FAIL, f"Endpoint is very slow (median {stats.median_ms:.0f} ms)"
    elif stats.median_ms > 3000:
        severity, title = Severity.WARN, f"Endpoint is slow (median {stats.median_ms:.0f} ms)"
    else:
        severity, title = Severity.PASS, f"Latency healthy (median {stats.median_ms:.0f} ms)"
    return stats, [
        Finding(
            check_id="reach.latency",
            category=Category.REACHABILITY,
            severity=severity,
            title=title,
            fix="Agents time out on slow tools; target < 3 s per call." if severity is not Severity.PASS else None,
        )
    ]


def _finalize(
    *,
    target_url: str,
    endpoint_kind: str,
    quick: bool,
    findings: list[Finding],
    started: float,
    latency: LatencyStats | None,
) -> AuditReport:
    score = compute_score(findings)
    grade = grade_for(score)
    verdict = verdict_for(findings)
    return AuditReport(
        report_id=uuid.uuid4().hex[:12],
        target_url=target_url,
        endpoint_kind=endpoint_kind,
        quick=quick,
        checked_at=datetime.now(timezone.utc),
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
        latency=latency,
        findings=findings,
        score=score,
        grade=grade,
        verdict=verdict,
        summary=summarize(endpoint_kind, findings, score, grade, verdict),
        fixes=fix_list(findings),
    )


async def run_audit(
    raw_url: str,
    *,
    settings: Settings,
    quick: bool = False,
    declared_price: str | None = None,
    resolver: Resolver | None = None,
) -> AuditReport:
    started = time.perf_counter()
    findings: list[Finding] = []

    try:
        target_url = validate_target_url(
            raw_url, allow_insecure=settings.allow_insecure_targets, resolver=resolver
        )
    except TargetValidationError as exc:
        findings.append(
            Finding(
                check_id="target.unsafe",
                category=Category.REACHABILITY,
                severity=Severity.CRITICAL,
                title="Target URL rejected",
                detail=str(exc),
                fix="Provide a public HTTPS endpoint on a domain (no private hosts, no embedded credentials).",
            )
        )
        return _finalize(
            target_url=raw_url.strip()[:2048],
            endpoint_kind=KIND_UNKNOWN,
            quick=quick,
            findings=findings,
            started=started,
            latency=None,
        )

    logger.info("audit start url=%s quick=%s", target_url, quick)
    endpoint_kind = KIND_UNKNOWN
    latency: LatencyStats | None = None

    timeout = httpx.Timeout(settings.request_timeout_seconds)
    try:
        async with asyncio.timeout(settings.audit_budget_seconds):
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                headers={"user-agent": USER_AGENT},
            ) as client:
                # --- Baseline probe (method-adaptive) --------------------------------
                # Real endpoints answer on different methods (e.g. CertiK's live
                # gateway returns 200 on GET but 404 on POST). Probe POST first,
                # then GET, and classify on whichever yields a compliant status —
                # this avoids the false positives seen in existing validators.
                try:
                    baseline = await _request(
                        client, "POST", target_url, max_bytes=settings.max_response_bytes, json_body={}
                    )
                    baseline_method = "POST"
                    if baseline.status not in (200, 402):
                        get_probe = await _request(
                            client, "GET", target_url, max_bytes=settings.max_response_bytes
                        )
                        if get_probe.status in (200, 402):
                            if baseline.status != 405:
                                findings.append(
                                    Finding(
                                        check_id="reach.method_mismatch",
                                        category=Category.REACHABILITY,
                                        severity=Severity.INFO,
                                        title=f"Endpoint answers on GET but returns HTTP {baseline.status} on POST",
                                        fix="Return 405 for unsupported methods so agent clients get a clear signal.",
                                    )
                                )
                            baseline = get_probe
                            baseline_method = "GET"
                except httpx.HTTPError as exc:
                    findings.append(
                        Finding(
                            check_id="reach.connect",
                            category=Category.REACHABILITY,
                            severity=Severity.CRITICAL,
                            title="Endpoint unreachable",
                            detail=f"{type(exc).__name__}: {exc}",
                            fix="Ensure the server is up, publicly routable, and serving valid TLS.",
                        )
                    )
                    return _finalize(
                        target_url=target_url,
                        endpoint_kind=endpoint_kind,
                        quick=quick,
                        findings=findings,
                        started=started,
                        latency=None,
                    )

                findings.append(
                    Finding(
                        check_id="reach.tls",
                        category=Category.REACHABILITY,
                        severity=Severity.PASS,
                        title="Connection established (TLS verified)"
                        if target_url.startswith("https")
                        else "Connection established (plain HTTP — dev mode)",
                    )
                )
                if baseline.truncated:
                    findings.append(
                        Finding(
                            check_id="reach.size",
                            category=Category.REACHABILITY,
                            severity=Severity.WARN,
                            title=f"Response exceeded {settings.max_response_bytes // 1024} KB and was truncated",
                            fix="Keep per-call responses compact; agents handle small payloads best.",
                        )
                    )

                # --- Classification + kind-specific validation ---------------------
                amounts: list[int] = []
                if baseline.status == 402:
                    endpoint_kind = KIND_PAID
                    x402_findings, amounts = validate_x402_challenge(
                        baseline.body, baseline.headers, target_url
                    )
                    findings.extend(x402_findings)
                elif baseline.status == 200:
                    endpoint_kind = KIND_FREE
                    findings.extend(validate_free_response(baseline.headers, baseline.body))
                else:
                    endpoint_kind, status_findings = _classification_findings(baseline.status)
                    findings.extend(status_findings)

                findings.extend(analyze_response_security(baseline.headers, baseline.body))

                # --- Latency sampling (full audit) ----------------------------------
                samples = [baseline.elapsed_ms]
                if not quick and endpoint_kind in (KIND_PAID, KIND_FREE):
                    for _ in range(2):
                        try:
                            extra_probe = await _request(
                                client,
                                baseline_method,
                                target_url,
                                max_bytes=settings.max_response_bytes,
                                json_body={} if baseline_method == "POST" else None,
                            )
                            samples.append(extra_probe.elapsed_ms)
                        except httpx.HTTPError:
                            findings.append(
                                Finding(
                                    check_id="reach.flaky",
                                    category=Category.REACHABILITY,
                                    severity=Severity.FAIL,
                                    title="Endpoint failed on a repeated identical request",
                                    fix="Investigate intermittent failures; agents retry and will surface flakiness.",
                                )
                            )
                            break
                latency, latency_findings = _latency_findings(samples)
                findings.extend(latency_findings)

                # --- Robustness probes (full audit) ---------------------------------
                if not quick and endpoint_kind in (KIND_PAID, KIND_FREE):
                    try:
                        malformed = await _request(
                            client,
                            "POST",
                            target_url,
                            max_bytes=settings.max_response_bytes,
                            content=b'{"broken":',
                        )
                        if malformed.status >= 500:
                            findings.append(
                                Finding(
                                    check_id="robust.malformed",
                                    category=Category.ROBUSTNESS,
                                    severity=Severity.FAIL,
                                    title=f"Malformed JSON input crashes the endpoint (HTTP {malformed.status})",
                                    fix="Validate request bodies and return 4xx on bad input.",
                                )
                            )
                        elif malformed.status == 200 and endpoint_kind == KIND_FREE:
                            findings.append(
                                Finding(
                                    check_id="robust.malformed",
                                    category=Category.ROBUSTNESS,
                                    severity=Severity.WARN,
                                    title="Malformed JSON input is silently accepted (HTTP 200)",
                                    fix="Reject invalid input with a 4xx so agents get actionable errors.",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id="robust.malformed",
                                    category=Category.ROBUSTNESS,
                                    severity=Severity.PASS,
                                    title=f"Malformed input handled gracefully (HTTP {malformed.status})",
                                )
                            )
                        findings.extend(
                            finding
                            for finding in analyze_response_security(malformed.headers, malformed.body)
                            if finding.check_id == "security.leak"
                            and finding.check_id not in {existing.check_id for existing in findings}
                        )
                    except httpx.HTTPError:
                        findings.append(
                            Finding(
                                check_id="robust.malformed",
                                category=Category.ROBUSTNESS,
                                severity=Severity.WARN,
                                title="Endpoint dropped the connection on malformed input",
                                fix="Return a 4xx response instead of closing the connection.",
                            )
                        )

                    other_method = "GET" if baseline_method == "POST" else "POST"
                    try:
                        alt = await _request(
                            client,
                            other_method,
                            target_url,
                            max_bytes=settings.max_response_bytes,
                            json_body={} if other_method == "POST" else None,
                        )
                        if alt.status >= 500:
                            findings.append(
                                Finding(
                                    check_id="robust.method",
                                    category=Category.ROBUSTNESS,
                                    severity=Severity.WARN,
                                    title=f"{other_method} on this endpoint causes a server error (HTTP {alt.status})",
                                    fix=f"Reject unsupported methods with 405, not {alt.status}.",
                                )
                            )
                        else:
                            findings.append(
                                Finding(
                                    check_id="robust.method",
                                    category=Category.ROBUSTNESS,
                                    severity=Severity.PASS,
                                    title=f"{other_method} request handled without server error (HTTP {alt.status})",
                                )
                            )
                    except httpx.HTTPError:
                        findings.append(
                            Finding(
                                check_id="robust.method",
                                category=Category.ROBUSTNESS,
                                severity=Severity.WARN,
                                title=f"Endpoint dropped the connection on {other_method}",
                                fix="Respond to unsupported methods with 405.",
                            )
                        )

                # --- Listing consistency --------------------------------------------
                findings.extend(_consistency_findings(declared_price, endpoint_kind, amounts))

    except TimeoutError:
        findings.append(
            Finding(
                check_id="reach.budget",
                category=Category.REACHABILITY,
                severity=Severity.CRITICAL,
                title=f"Audit exceeded the {settings.audit_budget_seconds:.0f}s time budget",
                detail="The endpoint is too slow to serve agent traffic reliably.",
                fix="Bring per-call latency well under 10 seconds.",
            )
        )

    report = _finalize(
        target_url=target_url,
        endpoint_kind=endpoint_kind,
        quick=quick,
        findings=findings,
        started=started,
        latency=latency,
    )
    logger.info(
        "audit done url=%s kind=%s score=%s verdict=%s duration_ms=%s",
        target_url,
        report.endpoint_kind,
        report.score,
        report.verdict,
        report.duration_ms,
    )
    return report
