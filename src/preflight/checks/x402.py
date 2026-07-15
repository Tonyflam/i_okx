"""x402 v2 payment-challenge validation (field-by-field, deterministic).

Spec source (accessed 2026-07-11):
https://web3.okx.com/onchainos/dev-docs/okxai/howtomcp
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import urlparse

from ..models import Category, Finding, Severity

XLAYER_MAINNET = "eip155:196"
XLAYER_TESTNET = "eip155:1952"
USDT0_XLAYER = "0x779ded0c9e1022225f8e0630b35a9b54be713736"
ZERO_ADDRESS = "0x" + "0" * 40

_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_CAIP2_EIP155_RE = re.compile(r"^eip155:\d+$")


def _finding(
    check_id: str,
    severity: Severity,
    title: str,
    detail: str = "",
    fix: str | None = None,
    category: Category = Category.PAYMENT,
) -> Finding:
    return Finding(
        check_id=check_id, category=category, severity=severity, title=title, detail=detail, fix=fix
    )


def _decode_challenge_candidate(text: str) -> Any | None:
    """Try to interpret text as JSON, or base64-encoded JSON."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import base64

        decoded = base64.b64decode(text, validate=True)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return None


def _extract_challenge(body: bytes, headers: Mapping[str, str]) -> tuple[Any | None, str]:
    """Locate the x402 challenge: the body may carry it, or the PAYMENT-REQUIRED
    header may carry it (plain or base64 JSON) — both forms occur in production
    (e.g. OKX Payment SDK deployments put the base64 challenge in the header with
    an empty JSON body). Returns (challenge, source)."""
    body_text = body.decode("utf-8", errors="replace")
    body_json = _decode_challenge_candidate(body_text)
    if isinstance(body_json, dict) and ("x402Version" in body_json or "accepts" in body_json):
        return body_json, "body"

    header_value = ""
    for name, value in headers.items():
        if name.lower() == "payment-required":
            header_value = value
            break
    header_json = _decode_challenge_candidate(header_value)
    if isinstance(header_json, dict) and ("x402Version" in header_json or "accepts" in header_json):
        return header_json, "header"

    if isinstance(body_json, dict):
        return body_json, "body"
    return None, "none"


def validate_x402_challenge(
    body: bytes,
    headers: Mapping[str, str],
    target_url: str,
) -> tuple[list[Finding], list[int]]:
    """Validate a 402 response as an x402 v2 challenge.

    Returns (findings, challenge_amounts_in_min_units).
    """
    findings: list[Finding] = []
    amounts: list[int] = []

    header_names = {name.lower() for name in headers}
    if "payment-required" in header_names:
        findings.append(
            _finding(
                "x402.header",
                Severity.PASS,
                "PAYMENT-REQUIRED header present",
            )
        )
    else:
        findings.append(
            _finding(
                "x402.header",
                Severity.INFO,
                "PAYMENT-REQUIRED header absent",
                "Spec allows signaling via the header or the body's x402Version; body-only works but the header improves client compatibility.",
                "Add a PAYMENT-REQUIRED response header to the 402 challenge.",
            )
        )

    challenge, source = _extract_challenge(body, headers)
    if challenge is None:
        findings.append(
            _finding(
                "x402.parse",
                Severity.CRITICAL,
                "No x402 challenge found in the 402 response",
                "Neither the body nor the PAYMENT-REQUIRED header carries parseable challenge JSON.",
                "Return the x402 v2 challenge as JSON in the body, or base64 JSON in the PAYMENT-REQUIRED header.",
            )
        )
        return findings, amounts
    findings.append(
        _finding("x402.carrier", Severity.PASS, f"Challenge carried in the response {source}")
    )

    if not isinstance(challenge, dict):
        findings.append(
            _finding(
                "x402.parse",
                Severity.CRITICAL,
                "402 challenge is not a JSON object",
                f"Got {type(challenge).__name__}.",
                "Return a JSON object containing x402Version, resource, and accepts.",
            )
        )
        return findings, amounts

    version = challenge.get("x402Version")
    if version == 2:
        findings.append(_finding("x402.version", Severity.PASS, "x402Version is 2"))
    else:
        findings.append(
            _finding(
                "x402.version",
                Severity.FAIL,
                "x402Version is not 2",
                f"Got {version!r}.",
                'Set "x402Version": 2 (the current standard challenge format).',
            )
        )

    resource = challenge.get("resource")
    if isinstance(resource, dict):
        resource_url = resource.get("url")
        if isinstance(resource_url, str) and resource_url:
            parsed_resource = urlparse(resource_url)
            if parsed_resource.scheme != "https":
                findings.append(
                    _finding(
                        "x402.resource.url",
                        Severity.FAIL,
                        "resource.url is not HTTPS",
                        f"Got scheme '{parsed_resource.scheme}'.",
                        "Point resource.url at your real public HTTPS endpoint.",
                    )
                )
            elif parsed_resource.hostname != urlparse(target_url).hostname:
                findings.append(
                    _finding(
                        "x402.resource.url",
                        Severity.WARN,
                        "resource.url host differs from the audited endpoint",
                        f"Challenge says '{parsed_resource.hostname}', endpoint is "
                        f"'{urlparse(target_url).hostname}'.",
                        "Make resource.url match the endpoint you register on OKX.AI.",
                    )
                )
            else:
                findings.append(
                    _finding("x402.resource.url", Severity.PASS, "resource.url is HTTPS and matches host")
                )
        else:
            findings.append(
                _finding(
                    "x402.resource.url",
                    Severity.WARN,
                    "resource.url missing",
                    "The published challenge example includes resource.url.",
                    "Add resource.url with your real public endpoint.",
                )
            )
        if not resource.get("mimeType"):
            findings.append(
                _finding(
                    "x402.resource.mime",
                    Severity.INFO,
                    "resource.mimeType missing",
                    fix='Add resource.mimeType (e.g. "application/json").',
                )
            )
    else:
        findings.append(
            _finding(
                "x402.resource",
                Severity.WARN,
                "resource object missing",
                "The published challenge example includes a resource object with url/description/mimeType.",
                "Add a resource object describing your service.",
            )
        )

    accepts = challenge.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        findings.append(
            _finding(
                "x402.accepts",
                Severity.CRITICAL,
                "accepts[] is missing or empty",
                "Without payment options, no client can pay this endpoint.",
                "Add at least one accepts[] entry with scheme/network/asset/amount/payTo.",
            )
        )
        return findings, amounts
    findings.append(
        _finding("x402.accepts", Severity.PASS, f"accepts[] present ({len(accepts)} option(s))")
    )

    for index, accept in enumerate(accepts):
        prefix = f"accepts[{index}]"
        if not isinstance(accept, dict):
            findings.append(
                _finding(
                    f"x402.accept.{index}",
                    Severity.FAIL,
                    f"{prefix} is not an object",
                    fix=f"Make {prefix} an object with scheme/network/asset/amount/payTo.",
                )
            )
            continue

        scheme = accept.get("scheme")
        if scheme == "exact":
            findings.append(_finding(f"x402.scheme.{index}", Severity.PASS, f"{prefix}.scheme is 'exact'"))
        else:
            findings.append(
                _finding(
                    f"x402.scheme.{index}",
                    Severity.FAIL,
                    f"{prefix}.scheme is not 'exact'",
                    f"Got {scheme!r}.",
                    f'Set {prefix}.scheme to "exact".',
                )
            )

        network = accept.get("network")
        if network == XLAYER_MAINNET:
            findings.append(
                _finding(f"x402.network.{index}", Severity.PASS, f"{prefix}.network is X Layer mainnet")
            )
        elif network == XLAYER_TESTNET:
            findings.append(
                _finding(
                    f"x402.network.{index}",
                    Severity.FAIL,
                    f"{prefix}.network is X Layer TESTNET",
                    "A testnet challenge will not settle for marketplace users.",
                    f'Switch {prefix}.network to "{XLAYER_MAINNET}" before listing.',
                )
            )
        elif isinstance(network, str) and _CAIP2_EIP155_RE.match(network):
            findings.append(
                _finding(
                    f"x402.network.{index}",
                    Severity.WARN,
                    f"{prefix}.network is an unexpected chain",
                    f"Got '{network}'. OKX.AI settles on X Layer ({XLAYER_MAINNET}).",
                    f'Use "{XLAYER_MAINNET}" unless you have confirmed another settlement chain.',
                )
            )
        else:
            findings.append(
                _finding(
                    f"x402.network.{index}",
                    Severity.FAIL,
                    f"{prefix}.network is malformed",
                    f"Got {network!r}; expected CAIP-2 form 'eip155:<chain-id>'.",
                    f'Set {prefix}.network to "{XLAYER_MAINNET}".',
                )
            )

        asset = accept.get("asset")
        if isinstance(asset, str) and asset.lower() == USDT0_XLAYER:
            findings.append(
                _finding(f"x402.asset.{index}", Severity.PASS, f"{prefix}.asset is USDT0 on X Layer")
            )
        elif network == XLAYER_MAINNET:
            findings.append(
                _finding(
                    f"x402.asset.{index}",
                    Severity.WARN,
                    f"{prefix}.asset is not the official X Layer settlement stablecoin",
                    f"Got {asset!r}; official USDT0 is {USDT0_XLAYER}.",
                    f"Use USDT0 ({USDT0_XLAYER}) unless another asset is explicitly supported.",
                )
            )
        else:
            findings.append(
                _finding(
                    f"x402.asset.{index}",
                    Severity.INFO,
                    f"{prefix}.asset not verified for network {network!r}",
                )
            )

        amount_raw = accept.get("amount")
        amount_value: int | None = None
        if isinstance(amount_raw, str) and amount_raw.isdigit():
            amount_value = int(amount_raw)
        elif isinstance(amount_raw, int) and not isinstance(amount_raw, bool):
            amount_value = amount_raw
        if amount_value is not None and amount_value > 0:
            amounts.append(amount_value)
            findings.append(
                _finding(
                    f"x402.amount.{index}",
                    Severity.PASS,
                    f"{prefix}.amount is {amount_value} min units "
                    f"(~{amount_value / 1_000_000:.6f} USDT at 6 decimals)",
                )
            )
        else:
            findings.append(
                _finding(
                    f"x402.amount.{index}",
                    Severity.FAIL,
                    f"{prefix}.amount is missing or not a positive integer",
                    f"Got {amount_raw!r}.",
                    f'Set {prefix}.amount to the price in minimum units (decimals=6; 10000 = 0.01 USDT).',
                )
            )

        pay_to = accept.get("payTo")
        if isinstance(pay_to, str) and _EVM_ADDRESS_RE.match(pay_to) and pay_to.lower() != ZERO_ADDRESS:
            findings.append(
                _finding(f"x402.payto.{index}", Severity.PASS, f"{prefix}.payTo is a valid EVM address")
            )
        else:
            findings.append(
                _finding(
                    f"x402.payto.{index}",
                    Severity.FAIL,
                    f"{prefix}.payTo is missing or invalid",
                    f"Got {pay_to!r}.",
                    f"Set {prefix}.payTo to your real X Layer receiving wallet (0x + 40 hex chars).",
                )
            )

        timeout_raw = accept.get("maxTimeoutSeconds")
        if isinstance(timeout_raw, int) and not isinstance(timeout_raw, bool) and 1 <= timeout_raw <= 3600:
            findings.append(
                _finding(
                    f"x402.timeout.{index}",
                    Severity.PASS,
                    f"{prefix}.maxTimeoutSeconds is sane ({timeout_raw}s)",
                )
            )
        else:
            findings.append(
                _finding(
                    f"x402.timeout.{index}",
                    Severity.WARN,
                    f"{prefix}.maxTimeoutSeconds is missing or out of range",
                    f"Got {timeout_raw!r}.",
                    f"Set {prefix}.maxTimeoutSeconds between 1 and 3600 (example uses 300).",
                )
            )

        extra = accept.get("extra")
        if not (isinstance(extra, dict) and extra.get("name")):
            findings.append(
                _finding(
                    f"x402.extra.{index}",
                    Severity.INFO,
                    f"{prefix}.extra token config missing",
                    fix='Add extra: { "name": "USD₮0", "version": "1" } per the published example.',
                )
            )

    return findings, amounts
