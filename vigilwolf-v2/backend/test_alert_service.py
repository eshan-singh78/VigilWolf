"""Tests for the Alert Service — webhook delivery.

Only tests pure functions (build_webhook_payload, sign_payload) so that
no database or HTTP client is required.
"""
import hmac
import json
from hashlib import sha256

import pytest

from services.alert_service import build_webhook_payload, sign_payload


# ---------------------------------------------------------------------------
# build_webhook_payload
# ---------------------------------------------------------------------------

class TestBuildPayloadStructure:
    """Verify the structure and defaults of the webhook payload."""

    def test_id_starts_with_evt_prefix(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["id"].startswith("evt_"), (
            f"Expected id to start with 'evt_', got {payload['id']!r}"
        )

    def test_id_is_16_chars_total(self):
        """'evt_' (4) + 12 hex chars = 16 chars total."""
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert len(payload["id"]) == 16, (
            f"Expected id length 16, got {len(payload['id'])}"
        )

    def test_version_is_1_0(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["version"] == "1.0"

    def test_event_field(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["event"] == "phishing_detected"

    def test_dedup_key_format(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["dedup_key"] == "phishing_detected:snap-001"

    def test_timestamp_is_iso8601_utc_with_z_suffix(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        ts = payload["timestamp"]
        assert ts.endswith("Z"), f"Expected timestamp ending with Z, got {ts!r}"
        # Verify it parses as ISO 8601 (strip the Z, append +00:00)
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_data_domain(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["domain"] == "evil.example.com"

    def test_data_score(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["score"] == 85

    def test_data_risk_level(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["risk_level"] == "high"

    def test_data_severity(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["severity"] == "critical"

    def test_data_dominant_signals(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector", "brand_match"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["dominant_signals"] == ["login_detector", "brand_match"]

    def test_data_reasons(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil", "brand_match: paypal"],
        )
        assert payload["data"]["reasons"] == [
            "Hard signal: credential_exfil", "brand_match: paypal"
        ]

    def test_data_iocs_default_empty_list(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["iocs"] == []

    def test_data_iocs_when_provided(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
            iocs=["1.2.3.4", "evil-c2.example.com"],
        )
        assert payload["data"]["iocs"] == ["1.2.3.4", "evil-c2.example.com"]

    def test_data_snapshot_id(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["snapshot_id"] == "snap-001"

    def test_data_campaign_default_none(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["data"]["campaign"] is None

    def test_data_campaign_when_provided(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
            campaign_id="camp-abc123",
        )
        assert payload["data"]["campaign"] == "camp-abc123"

    def test_data_screenshot_url(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        # screenshot_url should be present (None is acceptable when not available)
        assert "screenshot_url" in payload["data"]


# ---------------------------------------------------------------------------
# sign_payload
# ---------------------------------------------------------------------------

class TestSignPayload:
    """Verify HMAC-SHA256 signing of webhook payloads."""

    def test_signature_format(self):
        body = b'{"event":"phishing_detected"}'
        secret = "my-webhook-secret"
        result = sign_payload(body, secret)
        assert result.startswith("sha256="), (
            f"Expected 'sha256=' prefix, got {result!r}"
        )

    def test_signature_matches_hmac(self):
        body = b'{"event":"phishing_detected"}'
        secret = "my-webhook-secret"
        result = sign_payload(body, secret)
        expected_digest = hmac.new(
            secret.encode(), body, sha256
        ).hexdigest()
        expected = f"sha256={expected_digest}"
        assert result == expected

    def test_signature_different_for_different_bodies(self):
        secret = "my-webhook-secret"
        sig1 = sign_payload(b'{"a":1}', secret)
        sig2 = sign_payload(b'{"a":2}', secret)
        assert sig1 != sig2

    def test_signature_different_for_different_secrets(self):
        body = b'{"event":"test"}'
        sig1 = sign_payload(body, "secret-one")
        sig2 = sign_payload(body, "secret-two")
        assert sig1 != sig2

    def test_signature_with_empty_body(self):
        secret = "my-webhook-secret"
        result = sign_payload(b"", secret)
        expected_digest = hmac.new(secret.encode(), b"", sha256).hexdigest()
        assert result == f"sha256={expected_digest}"


# ---------------------------------------------------------------------------
# dedup_key format
# ---------------------------------------------------------------------------

class TestDedupKeyFormat:
    """Verify that dedup_key follows the '{event}:{snapshot_id}' pattern."""

    def test_dedup_key_event_snapshot_id(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-abc",
            reasons=["Hard signal: credential_exfil"],
        )
        assert payload["dedup_key"] == "phishing_detected:snap-abc"

    def test_dedup_key_different_event(self):
        payload = build_webhook_payload(
            event="domain_changed",
            domain="example.com",
            score=40,
            risk_level="medium",
            severity="medium",
            dominant_signals=["html_hasher"],
            snapshot_id="snap-xyz",
            reasons=["content changed"],
        )
        assert payload["dedup_key"] == "domain_changed:snap-xyz"

    def test_dedup_key_contains_colon_separator(self):
        payload = build_webhook_payload(
            event="phishing_detected",
            domain="evil.example.com",
            score=85,
            risk_level="high",
            severity="critical",
            dominant_signals=["login_detector"],
            snapshot_id="snap-001",
            reasons=["Hard signal: credential_exfil"],
        )
        parts = payload["dedup_key"].split(":", 1)
        assert len(parts) == 2
        assert parts[0] == "phishing_detected"
        assert parts[1] == "snap-001"