"""SQLite persistence for audit reports (needed for shareable report URLs and badges)."""

from __future__ import annotations

import sqlite3

from .models import AuditReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    target_url TEXT NOT NULL,
    report_json TEXT NOT NULL
);
"""


class ReportStore:
    def __init__(self, db_path: str):
        self._db_path = db_path
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def save(self, report: AuditReport) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports (id, created_at, target_url, report_json) VALUES (?, ?, ?, ?)",
                (
                    report.report_id,
                    report.checked_at.isoformat(),
                    report.target_url,
                    report.model_dump_json(),
                ),
            )

    def get(self, report_id: str) -> AuditReport | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
        if row is None:
            return None
        return AuditReport.model_validate_json(row[0])

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0])
