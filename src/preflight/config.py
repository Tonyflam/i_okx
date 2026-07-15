"""Runtime configuration. All values come from environment variables (prefix PREFLIGHT_)."""

import os

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PREFLIGHT_", env_file=".env", extra="ignore")

    app_name: str = "Preflight"
    public_base_url: str = "http://localhost:8000"
    db_path: str = "preflight.db"

    @model_validator(mode="after")
    def _infer_public_base_url(self) -> "Settings":
        """On Railway, fall back to the injected public domain so report/badge
        links never leak localhost into production responses."""
        if self.public_base_url == "http://localhost:8000":
            domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
            if domain:
                self.public_base_url = f"https://{domain}"
        return self

    # Outbound probe safety
    allow_insecure_targets: bool = False  # allow http:// targets (local dev ONLY)
    request_timeout_seconds: float = 10.0
    audit_budget_seconds: float = 30.0
    max_response_bytes: int = 512 * 1024

    # Abuse protection
    rate_limit_per_minute: int = 10

    # Payments (x402). Service runs in free mode until these are configured.
    payments_enabled: bool = False
    pay_to_address: str = ""
    audit_price_usd: str = "$0.05"
    okx_api_key: str = ""
    okx_secret_key: str = ""
    okx_passphrase: str = ""
