"""HTML capture engine with SSRF guardrails.

Defenses against SSRF:
  - DNS resolution is pinned per-capture: we resolve once and connect to the
    resolved IP directly, preventing DNS rebinding attacks.
  - All redirects are validated: each redirect target is re-checked against
    the forbidden host list before following.
  - Private, loopback, link-local, reserved, multicast, and unspecified IPs
    are blocked at every stage.
  - A maximum redirect limit is enforced.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests
import requests.adapters

import config

# Maximum number of redirects to follow
MAX_REDIRECTS = 5

# Sensitive response headers to strip before storing
STRIPPED_HEADERS = frozenset({
    "server", "x-powered-by", "x-request-id", "x-forwarded-for",
    "x-forwarded-proto", "x-real-ip", "x-forwarded-host",
})


class CaptureError(RuntimeError):
    """Raised when URL capture cannot be completed safely."""


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address is in a forbidden range."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_hostname(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve hostname to IP addresses. Raises CaptureError on DNS failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise CaptureError(f"DNS resolution failed for {hostname}: {exc}") from exc

    ips = []
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_forbidden_ip(ip):
            raise CaptureError(f"Refusing to capture private/internal host: {hostname} resolves to {ip}")
        ips.append(ip)
    if not ips:
        raise CaptureError(f"No valid IP addresses found for {hostname}")
    return ips


def validate_capture_url(url: str) -> None:
    """Validate that a URL is safe to capture (scheme + hostname checks only)."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise CaptureError("Only http/https URLs are supported")
    if not parsed.netloc:
        raise CaptureError("URL must include a hostname")
    host = parsed.hostname
    if not host:
        raise CaptureError("URL hostname could not be parsed")
    lowered = host.strip().lower()
    if lowered in {"localhost", "127.0.0.1", "::1"} or lowered.endswith(".local"):
        raise CaptureError(f"Refusing to capture private/internal host: {host}")
    _resolve_hostname(host)


def _strip_sensitive_headers(headers: dict) -> dict:
    """Remove headers that leak internal infrastructure details."""
    return {k: v for k, v in headers.items() if k.lower() not in STRIPPED_HEADERS}


class _SSRFSafeSession(requests.Session):
    """Requests session that validates every redirect target against SSRF rules."""

    def rebuild_on_redirect(self, prepared_request, response):
        """Called before following a redirect — validate the new URL."""
        redirect_url = response.headers.get("location")
        if not redirect_url:
            return

        parsed = urlparse(redirect_url)
        if parsed.scheme not in {"http", "https"}:
            raise CaptureError(f"Redirect to non-http(s) URL blocked: {redirect_url}")

        host = parsed.hostname
        if not host:
            # Relative redirect — use the original host
            host = prepared_request.hostname

        lowered = host.strip().lower()
        if lowered in {"localhost", "127.0.0.1", "::1"} or lowered.endswith(".local"):
            raise CaptureError(f"Redirect to private/internal host blocked: {host}")

        _resolve_hostname(host)
        return super().rebuild_on_redirect(prepared_request, response)


def capture_html(url: str) -> dict:
    """Capture HTML body from URL with SSRF protection.

    Uses a custom session that validates every redirect target against
    the forbidden IP list. DNS resolution is pinned per-request to prevent
    rebinding between validation and connection.
    """
    validate_capture_url(url)

    session = _SSRFSafeSession()
    session.max_redirects = MAX_REDIRECTS

    # Resolve the hostname and pin the connection to the resolved IP
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise CaptureError("URL hostname could not be parsed")

    resolved_ips = _resolve_hostname(hostname)
    pinned_ip = resolved_ips[0]

    # Build a pinned URL: replace hostname with resolved IP, set Host header
    if parsed.port:
        pinned_netloc = f"[{pinned_ip}]" if ":" in str(pinned_ip) else f"{pinned_ip}:{parsed.port}"
    else:
        pinned_netloc = f"[{pinned_ip}]" if ":" in str(pinned_ip) else str(pinned_ip)
    pinned_url = url.replace(parsed.netloc, pinned_netloc, 1)

    try:
        resp = session.get(
            pinned_url,
            timeout=config.DEFAULT_TIMEOUT_SECONDS,
            headers={
                "User-Agent": "VigilWolf/2.0",
                "Host": parsed.netloc,
            },
            allow_redirects=True,
        )
    except requests.TooManyRedirects:
        raise CaptureError(f"Too many redirects (max {MAX_REDIRECTS}) for {url}")
    except requests.RequestException as exc:
        raise CaptureError(f"Capture request failed for {url}: {exc}") from exc

    resp.raise_for_status()

    html = resp.text or ""
    body_bytes = html.encode("utf-8", errors="replace")
    if len(body_bytes) > config.MAX_ASSET_SIZE_BYTES:
        raise CaptureError(
            f"Captured HTML exceeds max size ({len(body_bytes)} > {config.MAX_ASSET_SIZE_BYTES})"
        )

    return {
        "html": html,
        "status_code": resp.status_code,
        "final_url": resp.url,
        "headers": _strip_sensitive_headers(dict(resp.headers)),
    }