"""Scoring/verdict determinism tests."""

from preflight.models import Category, Finding, Severity
from preflight.scoring import (
    VERDICT_AT_RISK,
    VERDICT_READY,
    VERDICT_WILL_FAIL,
    compute_score,
    fix_list,
    grade_for,
    verdict_for,
)


def make(severity: Severity, check_id: str = "x", fix: str | None = None) -> Finding:
    return Finding(
        check_id=check_id,
        category=Category.PROTOCOL,
        severity=severity,
        title="t",
        fix=fix,
    )


def test_clean_report_scores_100_grade_a_ready():
    findings = [make(Severity.PASS), make(Severity.INFO)]
    assert compute_score(findings) == 100
    assert grade_for(100) == "A"
    assert verdict_for(findings) == VERDICT_READY


def test_penalties():
    assert compute_score([make(Severity.WARN)]) == 96
    assert compute_score([make(Severity.FAIL)]) == 88
    assert compute_score([make(Severity.CRITICAL)]) == 75
    assert compute_score([make(Severity.CRITICAL)] * 5) == 0  # floor


def test_grade_boundaries():
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(80) == "B"
    assert grade_for(79) == "C"
    assert grade_for(70) == "C"
    assert grade_for(69) == "D"
    assert grade_for(60) == "D"
    assert grade_for(59) == "F"


def test_verdicts():
    assert verdict_for([make(Severity.FAIL)]) == VERDICT_AT_RISK
    assert verdict_for([make(Severity.CRITICAL), make(Severity.FAIL)]) == VERDICT_WILL_FAIL
    assert verdict_for([make(Severity.WARN)]) == VERDICT_READY


def test_fix_list_prioritized_and_deduped():
    findings = [
        make(Severity.WARN, "w", fix="warn fix"),
        make(Severity.CRITICAL, "c", fix="critical fix"),
        make(Severity.FAIL, "f1", fix="fail fix"),
        make(Severity.FAIL, "f2", fix="fail fix"),  # duplicate
    ]
    assert fix_list(findings) == ["critical fix", "fail fix", "warn fix"]
