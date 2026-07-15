"""Shared fixtures: golden x402 challenge, stub resolver, settings."""

from __future__ import annotations

import pytest

from preflight.config import Settings

PUBLIC_IP_RESOLVER = lambda host: ["93.184.216.34"]  # noqa: E731


def golden_challenge(endpoint: str = "https://asp.example.com/api/service") -> dict:
    return {
        "x402Version": 2,
        "resource": {
            "url": endpoint,
            "description": "Example paid service",
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:196",
                "asset": "0x779ded0c9e1022225f8e0630b35a9b54be713736",
                "amount": "50000",
                "payTo": "0x1234567890AbcdEF1234567890aBcdef12345678",
                "maxTimeoutSeconds": 300,
                "extra": {"name": "USD₮0", "version": "1"},
            }
        ],
    }


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        db_path=str(tmp_path / "test.db"),
        request_timeout_seconds=5.0,
        audit_budget_seconds=15.0,
        rate_limit_per_minute=100,
        public_base_url="https://preflight.example.com",
        _env_file=None,
    )
