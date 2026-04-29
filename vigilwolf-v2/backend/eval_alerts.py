"""Alert system evaluation for VigilWolf v2.

Tests the alert pipeline's pure functions: payload building, filter matching,
HMAC signing, and dedup logic. Validates correctness without needing a live
database or HTTP server.

Usage:
    python3 eval_alerts.py
"""
import hmac
from hashlib import sha256

from services.alert_service import (
    build_webhook_payload,
    sign_payload,
    _matches_filters,
    DEDUP_WINDOW_SECONDS,
)


def test_build_payload_structure():
    """Payload has all required top-level and data-level fields."""
    payload = build_webhook_payload(
        event="phishing_detected",
        domain="phish.example.com",
        score=85,
        risk_level="high",
        severity="critical",
        dominant_signals=["login_form_detected", "brand_match"],
        snapshot_id="snap_abc123",
        reasons=["Hard signal: credential_exfil"],
        iocs=["https://evil.com/steal"],
        campaign_id="camp_001",
    )
    assert payload["event"] == "phishing_detected"
    assert payload["version"] == "1.0"
    assert "id" in payload and payload["id"].startswith("evt_")
    assert payload["dedup_key"] == "phishing_detected:snap_abc123"
    assert "timestamp" in payload
    assert payload["data"]["domain"] == "phish.example.com"
    assert payload["data"]["score"] == 85
    assert payload["data"]["risk_level"] == "high"
    assert payload["data"]["severity"] == "critical"
    assert payload["data"]["dominant_signals"] == ["login_form_detected", "brand_match"]
    assert payload["data"]["reasons"] == ["Hard signal: credential_exfil"]
    assert payload["data"]["iocs"] == ["https://evil.com/steal"]
    assert payload["data"]["campaign"] == "camp_001"
    assert payload["data"]["snapshot_id"] == "snap_abc123"
    print("PASS: test_build_payload_structure")


def test_build_payload_defaults():
    """Payload fills in defaults for optional fields."""
    payload = build_webhook_payload(
        event="phishing_detected",
        domain="test.com",
        score=50,
        risk_level="medium",
        severity="medium",
        dominant_signals=[],
        snapshot_id="snap1",
        reasons=[],
    )
    assert payload["data"]["iocs"] == []
    assert payload["data"]["campaign"] is None
    assert payload["data"]["screenshot_url"] is None
    print("PASS: test_build_payload_defaults")


def test_dedup_key_format():
    """Dedup key is event:snapshot_id for same-event suppression."""
    p1 = build_webhook_payload(
        event="phishing_detected", domain="a.com", score=80,
        risk_level="high", severity="high", dominant_signals=[],
        snapshot_id="snap_1", reasons=[],
    )
    p2 = build_webhook_payload(
        event="phishing_detected", domain="a.com", score=80,
        risk_level="high", severity="high", dominant_signals=[],
        snapshot_id="snap_1", reasons=[],
    )
    p3 = build_webhook_payload(
        event="phishing_detected", domain="a.com", score=80,
        risk_level="high", severity="high", dominant_signals=[],
        snapshot_id="snap_2", reasons=[],
    )
    assert p1["dedup_key"] == p2["dedup_key"], "Same event+snapshot should have same dedup key"
    assert p1["dedup_key"] != p3["dedup_key"], "Different snapshot should have different dedup key"
    print("PASS: test_dedup_key_format")


def test_sign_payload():
    """HMAC-SHA256 signing produces sha256=<hex> format."""
    body = b'{"test": true}'
    secret = "my-secret-key"
    sig = sign_payload(body, secret)
    assert sig.startswith("sha256=")
    hex_digest = sig.split("=", 1)[1]
    expected = hmac.new(secret.encode(), body, sha256).hexdigest()
    assert hex_digest == expected
    print("PASS: test_sign_payload")


def test_sign_payload_deterministic():
    """Same body + secret always produces the same signature."""
    body = b'{"domain": "test.com"}'
    secret = "webhook-secret"
    sig1 = sign_payload(body, secret)
    sig2 = sign_payload(body, secret)
    assert sig1 == sig2
    print("PASS: test_sign_payload_deterministic")


def test_sign_payload_different_secrets():
    """Different secrets produce different signatures."""
    body = b'{"domain": "test.com"}'
    sig1 = sign_payload(body, "secret-a")
    sig2 = sign_payload(body, "secret-b")
    assert sig1 != sig2
    print("PASS: test_sign_payload_different_secrets")


def test_filter_no_filters():
    """Empty/None filters pass everything."""
    payload = {"data": {"domain": "test.com", "score": 50, "severity": "low"}}
    assert _matches_filters(payload, None) is True
    assert _matches_filters(payload, {}) is True
    print("PASS: test_filter_no_filters")


def test_filter_min_score():
    """min_score filter rejects below threshold, passes at/above."""
    payload = {"data": {"domain": "test.com", "score": 50, "severity": "low"}}
    assert _matches_filters(payload, {"min_score": 60}) is False
    assert _matches_filters(payload, {"min_score": 50}) is True
    assert _matches_filters(payload, {"min_score": 40}) is True
    print("PASS: test_filter_min_score")


def test_filter_severity():
    """severity filter only passes listed severities."""
    payload = {"data": {"domain": "test.com", "score": 80, "severity": "high"}}
    assert _matches_filters(payload, {"severity": ["high", "critical"]}) is True
    assert _matches_filters(payload, {"severity": ["low", "medium"]}) is False
    print("PASS: test_filter_severity")


def test_filter_domains():
    """domains filter matches substrings."""
    payload = {"data": {"domain": "paypal-evil.com", "score": 90, "severity": "high"}}
    assert _matches_filters(payload, {"domains": ["paypal"]}) is True
    assert _matches_filters(payload, {"domains": ["chase"]}) is False
    print("PASS: test_filter_domains")


def test_filter_exclude_tags():
    """exclude_tags rejects payloads containing any excluded tag."""
    payload = {
        "data": {
            "domain": "test.com",
            "score": 80,
            "severity": "high",
            "dominant_signals": ["login_form_detected", "brand_match"],
            "reasons": [],
        }
    }
    assert _matches_filters(payload, {"exclude_tags": ["nrd_age"]}) is True
    assert _matches_filters(payload, {"exclude_tags": ["brand_match"]}) is False
    print("PASS: test_filter_exclude_tags")


def test_filter_exclude_tags_in_reasons():
    """exclude_tags also checks reason strings."""
    payload = {
        "data": {
            "domain": "test.com",
            "score": 80,
            "severity": "high",
            "dominant_signals": [],
            "reasons": ["Hard signal: credential_exfil"],
        }
    }
    assert _matches_filters(payload, {"exclude_tags": ["credential_exfil"]}) is False
    print("PASS: test_filter_exclude_tags_in_reasons")


def test_filter_combined():
    """Multiple filters must all pass for the payload to match."""
    payload = {"data": {"domain": "paypal-phish.com", "score": 85, "severity": "high", "dominant_signals": ["brand_match"], "reasons": []}}
    assert _matches_filters(payload, {"min_score": 80, "severity": ["high"]}) is True
    assert _matches_filters(payload, {"min_score": 80, "severity": ["low"]}) is False
    assert _matches_filters(payload, {"min_score": 90, "severity": ["high"]}) is False
    print("PASS: test_filter_combined")


def test_filter_wrong_type_skipped():
    """Wrong filter types are silently skipped (treated as no filter)."""
    payload = {"data": {"domain": "test.com", "score": 50, "severity": "low"}}
    assert _matches_filters(payload, {"min_score": "not-a-number"}) is True
    assert _matches_filters(payload, {"severity": "not-a-list"}) is True
    print("PASS: test_filter_wrong_type_skipped")


def test_dedup_window_constant():
    """Verify dedup window is set to 10 minutes."""
    assert DEDUP_WINDOW_SECONDS == 600
    print("PASS: test_dedup_window_constant")


def test_event_id_uniqueness():
    """Each payload gets a unique event ID."""
    payloads = [
        build_webhook_payload(
            event="phishing_detected", domain="test.com", score=80,
            risk_level="high", severity="high", dominant_signals=[],
            snapshot_id=f"snap_{i}", reasons=[],
        )
        for i in range(20)
    ]
    ids = [p["id"] for p in payloads]
    assert len(set(ids)) == 20, "All event IDs should be unique"
    print("PASS: test_event_id_uniqueness")


def run_all():
    """Run all alert evaluation scenarios."""
    print(f"\n{'='*60}")
    print("ALERT SYSTEM EVALUATION")
    print(f"{'='*60}\n")
    tests = [
        test_build_payload_structure,
        test_build_payload_defaults,
        test_dedup_key_format,
        test_sign_payload,
        test_sign_payload_deterministic,
        test_sign_payload_different_secrets,
        test_filter_no_filters,
        test_filter_min_score,
        test_filter_severity,
        test_filter_domains,
        test_filter_exclude_tags,
        test_filter_exclude_tags_in_reasons,
        test_filter_combined,
        test_filter_wrong_type_skipped,
        test_dedup_window_constant,
        test_event_id_uniqueness,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__} — {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_all() else 1)