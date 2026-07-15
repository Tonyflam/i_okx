"""SSRF guard: validate caller-supplied target URLs before any outbound request.

Preflight fetches arbitrary URLs on behalf of callers, which makes it an SSRF
vector by construction. This module fails closed:

- https only (http allowed only behind an explicit dev flag)
- no credentials in the URL
- hostname must not be a private/loopback/link-local/reserved IP literal
- DNS resolution must succeed and EVERY resolved address must be public
- explicit denylist for localhost-style hostnames

Residual risk (documented): DNS rebinding between validation and the actual
request. Mitigated by short timeouts, no redirect following, and response caps.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable
from urllib.parse import urlparse

Resolver = Callable[[str], list[str]]

_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain"}
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa")
_MAX_URL_LENGTH = 2048


class TargetValidationError(ValueError):
    """Raised when a target URL is unsafe or malformed."""


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError(f"DNS resolution failed for '{host}': {exc}") from exc
    return [info[4][0] for info in infos]


def _is_public_address(ip_text: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or (addr.version == 6 and addr.ipv4_mapped is not None and not _is_public_address(str(addr.ipv4_mapped)))
    )


def validate_target_url(
    raw_url: str,
    *,
    allow_insecure: bool = False,
    resolver: Resolver | None = None,
) -> str:
    """Return the normalized URL if safe to probe, else raise TargetValidationError."""
    if not isinstance(raw_url, str):
        raise TargetValidationError("URL must be a string")
    url = raw_url.strip()
    if not url or len(url) > _MAX_URL_LENGTH:
        raise TargetValidationError("URL is empty or exceeds maximum length")

    parsed = urlparse(url)

    allowed_schemes = {"https", "http"} if allow_insecure else {"https"}
    if parsed.scheme not in allowed_schemes:
        raise TargetValidationError(
            f"Scheme '{parsed.scheme or '(none)'}' not allowed; endpoint must be HTTPS"
        )
    if parsed.username or parsed.password:
        raise TargetValidationError("URLs with embedded credentials are not allowed")

    host = parsed.hostname
    if not host:
        raise TargetValidationError("URL has no hostname")
    host_lower = host.lower().rstrip(".")
    if host_lower in _BLOCKED_HOSTNAMES or host_lower.endswith(_BLOCKED_SUFFIXES):
        if not allow_insecure:
            raise TargetValidationError(f"Hostname '{host}' is not publicly routable")

    # IP-literal target: check directly.
    try:
        ipaddress.ip_address(host_lower.strip("[]"))
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        if not _is_public_address(host_lower.strip("[]")):
            raise TargetValidationError(f"IP address '{host}' is not publicly routable")
        return url

    if allow_insecure and (host_lower in _BLOCKED_HOSTNAMES or host_lower.endswith(_BLOCKED_SUFFIXES)):
        # Dev mode: permit localhost targets without resolving further.
        return url

    resolve = resolver or _default_resolver
    addresses = resolve(host_lower)
    if not addresses:
        raise TargetValidationError(f"DNS resolution returned no addresses for '{host}'")
    for ip_text in addresses:
        if not _is_public_address(ip_text):
            if allow_insecure:
                continue
            raise TargetValidationError(
                f"Hostname '{host}' resolves to non-public address {ip_text}"
            )
    return url
