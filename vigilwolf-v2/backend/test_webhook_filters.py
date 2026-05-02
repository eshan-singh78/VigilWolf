"""Tests for the _matches_filters pure function in alert_service."""

import pytest

from services.alert_service import _matches_filters


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_payload(
    domain: str = "evil.example.com",
    score: int = 75,
    severity: str = "high",
    dominant_signals: list | None = None,
    reasons: list | None = None,
) -> dict:
    """Build a minimal webhook-style payload for testing."""
    return {
        "id": "evt_abc123",
        "event": "phishing_detected",
        "dedup_key": "phishing_detected:snap1",
        "data": {
            "domain": domain,
            "score": score,
            "severity": severity,
            "dominant_signals": dominant_signals or ["brand_match", "suspicious_tld"],
            "reasons": reasons or ["Brand impersonation detected", "Suspicious TLD .xyz"],
        },
    }


# ---------------------------------------------------------------------------
# No filters
# ---------------------------------------------------------------------------

def test_no_filters_match_everything():
    payload = _make_payload()
    assert _matches_filters(payload, {}) is True


def test_none_filters_match_everything():
    payload = _make_payload()
    assert _matches_filters(payload, None) is True


# ---------------------------------------------------------------------------
# min_score
# ---------------------------------------------------------------------------

def test_min_score_filter_pass():
    payload = _make_payload(score=80)
    assert _matches_filters(payload, {"min_score": 50}) is True


def test_min_score_filter_fail():
    payload = _make_payload(score=30)
    assert _matches_filters(payload, {"min_score": 50}) is False


# ---------------------------------------------------------------------------
# severity
# ---------------------------------------------------------------------------

def test_severity_filter_pass():
    payload = _make_payload(severity="high")
    assert _matches_filters(payload, {"severity": ["high", "critical"]}) is True


def test_severity_filter_fail():
    payload = _make_payload(severity="low")
    assert _matches_filters(payload, {"severity": ["high", "critical"]}) is False


# ---------------------------------------------------------------------------
# domains
# ---------------------------------------------------------------------------

def test_domains_filter_pass():
    payload = _make_payload(domain="evil.example.com")
    assert _matches_filters(payload, {"domains": ["example.com", "bad.org"]}) is True


def test_domains_filter_fail():
    payload = _make_payload(domain="safe.goodorg.com")
    assert _matches_filters(payload, {"domains": ["example.com", "bad.org"]}) is False


# ---------------------------------------------------------------------------
# exclude_tags
# ---------------------------------------------------------------------------

def test_exclude_tags_filter_pass():
    """No excluded tags appear in dominant_signals or reasons."""
    payload = _make_payload(
        dominant_signals=["brand_match", "suspicious_tld"],
        reasons=["Brand impersonation detected"],
    )
    assert _matches_filters(payload, {"exclude_tags": ["whitelist_tag"]}) is True


def test_exclude_tags_filter_fail():
    """An excluded tag appears in dominant_signals."""
    payload = _make_payload(
        dominant_signals=["brand_match", "whitelist_tag"],
        reasons=["Brand impersonation detected"],
    )
    assert _matches_filters(payload, {"exclude_tags": ["whitelist_tag"]}) is False


# ---------------------------------------------------------------------------
# Combined filters
# ---------------------------------------------------------------------------

def test_combined_filters():
    """Multiple filters all pass."""
    payload = _make_payload(
        domain="evil.example.com",
        score=80,
        severity="high",
        dominant_signals=["brand_match"],
        reasons=["Brand impersonation detected"],
    )
    filters = {
        "min_score": 50,
        "severity": ["high", "critical"],
        "domains": ["example.com"],
        "exclude_tags": ["whitelist_tag"],
    }
    assert _matches_filters(payload, filters) is True


def test_combined_filters_one_fails():
    """One filter fails (score too low) even though others pass."""
    payload = _make_payload(
        domain="evil.example.com",
        score=30,
        severity="high",
    )
    filters = {
        "min_score": 50,
        "severity": ["high", "critical"],
        "domains": ["example.com"],
    }
    assert _matches_filters(payload, filters) is False


# ---------------------------------------------------------------------------
# Defensive: invalid filter types
# ---------------------------------------------------------------------------

def test_invalid_filter_types():
    """Wrong types in filter values are treated as no filter (pass)."""
    payload = _make_payload(score=30, severity="low", domain="safe.org")
    filters = {
        "min_score": "not_a_number",  # string instead of int/float
        "severity": "high",           # string instead of list
        "domains": "example.com",      # string instead of list
        "exclude_tags": "whitelist",   # string instead of list
    }
    assert _matches_filters(payload, filters) is True