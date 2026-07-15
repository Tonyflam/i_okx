"""SSRF guard tests: the auditor must never probe private infrastructure."""

import pytest

from preflight.ssrf import TargetValidationError, validate_target_url

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731
PRIVATE = lambda host: ["10.1.2.3"]  # noqa: E731


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/api",
        "https://127.0.0.1/api",
        "https://10.0.0.1/api",
        "https://192.168.1.1/api",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/api",
        "https://0.0.0.0/api",
        "ftp://example.com/file",
        "http://example.com/api",  # http disallowed by default
        "https://user:secret@example.com/api",  # embedded credentials
        "https://internal.service.local/api",
        "not-a-url",
        "",
    ],
)
def test_rejects_unsafe_urls(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, resolver=PUBLIC)


def test_rejects_hostname_resolving_to_private_ip():
    with pytest.raises(TargetValidationError):
        validate_target_url("https://evil.example.com/api", resolver=PRIVATE)


def test_rejects_empty_resolution():
    with pytest.raises(TargetValidationError):
        validate_target_url("https://nowhere.example.com/api", resolver=lambda host: [])


def test_accepts_public_https():
    url = "https://asp.example.com/api/service"
    assert validate_target_url(url, resolver=PUBLIC) == url


def test_accepts_public_ipv6():
    url = "https://[2606:2800:220:1:248:1893:25c8:1946]/api"
    assert validate_target_url(url, resolver=PUBLIC) == url


def test_allow_insecure_permits_http_localhost_for_dev():
    url = "http://localhost:8000/"
    assert validate_target_url(url, allow_insecure=True, resolver=PUBLIC) == url


def test_url_length_cap():
    with pytest.raises(TargetValidationError):
        validate_target_url("https://example.com/" + "a" * 3000, resolver=PUBLIC)
