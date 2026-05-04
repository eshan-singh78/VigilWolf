"""Tests for brand detection fixes (H-1, H-2, F-2)."""
from services.campaign_service import _detect_brand


def test_short_brand_dhl_detected():
    result = _detect_brand(["https://dhl-verify.evil.com/login"])
    assert result == "DHL"

def test_short_brand_ups_detected():
    result = _detect_brand(["https://ups-tracking.evil.com/"])
    assert result == "UPS"

def test_short_brand_pnc_detected():
    result = _detect_brand(["https://pnc-login.evil.com/"])
    assert result == "PNC"

def test_short_denylisted_keyword_still_filtered():
    result = _detect_brand(["https://go.evil.com/"])
    assert result is None

def test_normal_brand_still_detected():
    result = _detect_brand(["https://paypal-verify.evil.com/"])
    assert result == "PAYPAL"