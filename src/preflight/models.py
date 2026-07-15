"""Report data models."""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel


class Severity(str, enum.Enum):
    PASS = "pass"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"
    CRITICAL = "critical"


class Category(str, enum.Enum):
    REACHABILITY = "reachability"
    PROTOCOL = "protocol"
    PAYMENT = "payment"
    ROBUSTNESS = "robustness"
    SECURITY = "security"
    CONSISTENCY = "consistency"


class Finding(BaseModel):
    check_id: str
    category: Category
    severity: Severity
    title: str
    detail: str = ""
    fix: str | None = None


class LatencyStats(BaseModel):
    samples_ms: list[float]
    median_ms: float
    max_ms: float


class AuditReport(BaseModel):
    report_id: str
    target_url: str
    endpoint_kind: str  # "x402-paid" | "free" | "unknown"
    quick: bool
    checked_at: datetime
    duration_ms: float
    latency: LatencyStats | None = None
    findings: list[Finding]
    score: int
    grade: str
    verdict: str
    summary: str
    fixes: list[str]
