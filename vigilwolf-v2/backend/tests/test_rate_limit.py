"""Tests for rate limiter IP resolution with TRUSTED_PROXIES."""
import importlib
from unittest.mock import MagicMock

import pytest


def _make_request(client_host="10.0.0.1", xff=None, x_real_ip=None):
    """Build a minimal Starlette Request-like object for _get_client_ip."""
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    if x_real_ip is not None:
        headers["x-real-ip"] = x_real_ip

    request = MagicMock()
    request.headers = headers
    request.client = MagicMock()
    request.client.host = client_host
    return request


# ---------------------------------------------------------------------------
# Test 1: Without TRUSTED_PROXIES, uses direct IP even when XFF is set
# ---------------------------------------------------------------------------

def test_no_trusted_proxies_uses_direct_ip():
    """When TRUSTED_PROXIES is empty, X-Forwarded-For must be ignored."""
    import middleware.rate_limit as rl_mod
    import config

    # Ensure TRUSTED_PROXIES is empty
    original = config.TRUSTED_PROXIES
    config.TRUSTED_PROXIES = []
    importlib.reload(rl_mod)

    try:
        request = _make_request(client_host="10.0.0.1", xff="1.2.3.4")
        result = rl_mod.RateLimitMiddleware._get_client_ip(request)
        assert result == "10.0.0.1", f"Expected direct IP, got {result}"
    finally:
        config.TRUSTED_PROXIES = original
        importlib.reload(rl_mod)


# ---------------------------------------------------------------------------
# Test 2: With TRUSTED_PROXIES, ignores XFF from untrusted IP
# ---------------------------------------------------------------------------

def test_trusted_proxies_ignores_xff_from_untrusted():
    """When direct IP is not in TRUSTED_PROXIES, XFF must be ignored."""
    import middleware.rate_limit as rl_mod
    import config

    original = config.TRUSTED_PROXIES
    config.TRUSTED_PROXIES = ["10.0.0.100"]
    importlib.reload(rl_mod)

    try:
        request = _make_request(client_host="10.0.0.1", xff="1.2.3.4")
        result = rl_mod.RateLimitMiddleware._get_client_ip(request)
        assert result == "10.0.0.1", f"Expected direct IP, got {result}"
    finally:
        config.TRUSTED_PROXIES = original
        importlib.reload(rl_mod)


# ---------------------------------------------------------------------------
# Test 3: With TRUSTED_PROXIES, trusts XFF from trusted proxy IP
# ---------------------------------------------------------------------------

def test_trusted_proxies_trusts_xff_from_trusted():
    """When direct IP is in TRUSTED_PROXIES, XFF first value must be used."""
    import middleware.rate_limit as rl_mod
    import config

    original = config.TRUSTED_PROXIES
    config.TRUSTED_PROXIES = ["10.0.0.100"]
    importlib.reload(rl_mod)

    try:
        request = _make_request(client_host="10.0.0.100", xff="1.2.3.4, 5.6.7.8")
        result = rl_mod.RateLimitMiddleware._get_client_ip(request)
        assert result == "1.2.3.4", f"Expected XFF first value, got {result}"
    finally:
        config.TRUSTED_PROXIES = original
        importlib.reload(rl_mod)


# ---------------------------------------------------------------------------
# Additional: X-Real-Ip fallback when XFF is absent but proxy is trusted
# ---------------------------------------------------------------------------

def test_trusted_proxies_x_real_ip_fallback():
    """When proxy is trusted and XFF is absent, X-Real-Ip should be used."""
    import middleware.rate_limit as rl_mod
    import config

    original = config.TRUSTED_PROXIES
    config.TRUSTED_PROXIES = ["10.0.0.100"]
    importlib.reload(rl_mod)

    try:
        request = _make_request(client_host="10.0.0.100", x_real_ip="9.8.7.6")
        result = rl_mod.RateLimitMiddleware._get_client_ip(request)
        assert result == "9.8.7.6", f"Expected X-Real-Ip value, got {result}"
    finally:
        config.TRUSTED_PROXIES = original
        importlib.reload(rl_mod)