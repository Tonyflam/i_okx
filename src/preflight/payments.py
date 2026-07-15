"""Optional x402 payment gating for the deep-audit route.

Uses the official OKX Payment SDK exactly as documented at
https://web3.okx.com/onchainos/dev-docs/payments/service-seller-sdk (Python tab).

The import is guarded so the service runs in FREE MODE when the SDK or
credentials are absent — a free endpoint is itself a compliant A2MCP listing,
which preserves review eligibility while payments are being provisioned.
Secrets come from environment variables only and are never logged.
"""

from __future__ import annotations

import logging

from .config import Settings

logger = logging.getLogger("preflight.payments")


def build_payment_middleware(settings: Settings):
    """Return (middleware_class, kwargs) to gate POST /audit, or None for free mode."""
    if not settings.payments_enabled:
        logger.info("payments disabled by configuration; /audit runs in free mode")
        return None
    if not (
        settings.pay_to_address
        and settings.okx_api_key
        and settings.okx_secret_key
        and settings.okx_passphrase
    ):
        logger.warning(
            "PREFLIGHT_PAYMENTS_ENABLED is true but credentials are incomplete; "
            "falling back to free mode"
        )
        return None
    try:
        from x402.http import (  # type: ignore[import-not-found]
            OKXAuthConfig,
            OKXFacilitatorClient,
            OKXFacilitatorConfig,
            PaymentOption,
        )
        from x402.http.middleware.fastapi import PaymentMiddlewareASGI  # type: ignore[import-not-found]
        from x402.http.types import RouteConfig  # type: ignore[import-not-found]
        from x402.mechanisms.evm.exact.server import ExactEvmScheme  # type: ignore[import-not-found]
        from x402.server import x402ResourceServer  # type: ignore[import-not-found]
    except ImportError:
        logger.warning(
            "okxweb3-app-x402 SDK not installed (pip install '.[payments]'); "
            "falling back to free mode"
        )
        return None

    facilitator = OKXFacilitatorClient(
        OKXFacilitatorConfig(
            auth=OKXAuthConfig(
                api_key=settings.okx_api_key,
                secret_key=settings.okx_secret_key,
                passphrase=settings.okx_passphrase,
            ),
            base_url="https://web3.okx.com",
            sync_settle=True,
        )
    )

    # Validate credentials up front: the middleware initializes lazily on the
    # first paid request and propagates facilitator auth errors to callers,
    # which would turn a typo'd key into a hard-down /audit. A bad credential
    # set must degrade to free mode, never to a broken endpoint.
    try:
        facilitator.get_supported()
    except Exception as exc:  # noqa: BLE001 — any facilitator failure means fallback
        logger.warning(
            "facilitator rejected credentials or is unreachable (%s); falling back to free mode",
            exc,
        )
        return None

    server = x402ResourceServer(facilitator)
    server.register("eip155:196", ExactEvmScheme())

    routes = {
        # No verb → gate every method on /audit (exact path match; report
        # routes like GET /audit/{id} stay free). The marketplace probes with
        # GET and expects the 402 challenge in the PAYMENT-REQUIRED header.
        "/audit": RouteConfig(
            accepts=[
                PaymentOption(
                    scheme="exact",
                    price=settings.audit_price_usd,
                    network="eip155:196",
                    pay_to=settings.pay_to_address,
                    max_timeout_seconds=300,
                )
            ],
            # Pin the advertised resource to the public HTTPS URL; otherwise
            # the SDK derives it from the incoming request, which can echo
            # http://host behind a proxy edge and fail challenge validation.
            resource=settings.public_base_url.rstrip("/") + "/audit",
            description="Preflight deep conformance audit of an agent service endpoint",
            mime_type="application/json",
        ),
    }
    logger.info("x402 payments enabled for /audit at %s", settings.audit_price_usd)
    return PaymentMiddlewareASGI, {"routes": routes, "server": server}
