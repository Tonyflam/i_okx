"""Deterministic scoring, grading, and verdicts. No LLM anywhere in this path."""

from __future__ import annotations

from .models import Finding, Severity

_PENALTY = {
    Severity.CRITICAL: 25,
    Severity.FAIL: 12,
    Severity.WARN: 4,
    Severity.INFO: 0,
    Severity.PASS: 0,
}

VERDICT_READY = "READY"
VERDICT_AT_RISK = "AT RISK"
VERDICT_WILL_FAIL = "WILL FAIL REVIEW"
VERDICT_BLOCKED = "BLOCKED"


def compute_score(findings: list[Finding]) -> int:
    score = 100
    for finding in findings:
        score -= _PENALTY[finding.severity]
    return max(score, 0)


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def verdict_for(findings: list[Finding]) -> str:
    severities = {finding.severity for finding in findings}
    if Severity.CRITICAL in severities:
        return VERDICT_WILL_FAIL
    if Severity.FAIL in severities:
        return VERDICT_AT_RISK
    return VERDICT_READY


def fix_list(findings: list[Finding]) -> list[str]:
    """Prioritized, deduplicated fixes: critical first, then fail, then warn."""
    ordered: list[str] = []
    seen: set[str] = set()
    for severity in (Severity.CRITICAL, Severity.FAIL, Severity.WARN):
        for finding in findings:
            if finding.severity is severity and finding.fix and finding.fix not in seen:
                seen.add(finding.fix)
                ordered.append(finding.fix)
    return ordered


def summarize(endpoint_kind: str, findings: list[Finding], score: int, grade: str, verdict: str) -> str:
    fails = sum(1 for f in findings if f.severity in (Severity.FAIL, Severity.CRITICAL))
    warns = sum(1 for f in findings if f.severity is Severity.WARN)
    passes = sum(1 for f in findings if f.severity is Severity.PASS)
    kind_label = {
        "x402-paid": "x402 pay-per-call endpoint",
        "free": "free endpoint",
    }.get(endpoint_kind, "endpoint (type undetermined)")
    return (
        f"{verdict}: {kind_label} scored {score}/100 (grade {grade}) — "
        f"{passes} checks passed, {warns} warnings, {fails} failures."
    )
