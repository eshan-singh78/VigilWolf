"""Tests for brand detection fixes (H-1, H-2, F-2)."""
from services.campaign_service import _detect_brand


def test_short_brand_dhl_detected():
    result = _detect_brand(["https://dhl-verify.com/login"])
    assert result == "DHL"

def test_short_brand_ups_detected():
    result = _detect_brand(["https://ups-tracking.com/"])
    assert result == "UPS"

def test_short_brand_pnc_detected():
    result = _detect_brand(["https://pnc-login.com/"])
    assert result == "PNC"

def test_short_denylisted_keyword_still_filtered():
    result = _detect_brand(["https://go.evil.com/"])
    assert result is None

def test_normal_brand_still_detected():
    result = _detect_brand(["https://paypal-verify.com/"])
    assert result == "PAYPAL"

def test_brand_matches_sld_not_subdomain():
    result = _detect_brand(["https://login.paypal.evil.com/"])
    assert result is None

def test_brand_matches_sld_in_actual_domain():
    result = _detect_brand(["https://paypal-phish.com/"])
    assert result == "PAYPAL"

def test_brand_sld_with_two_part_tld():
    result = _detect_brand(["https://login.paypal.co.uk/"])
    assert result == "PAYPAL"

def test_legitimate_domain_not_matched():
    result = _detect_brand(["https://paypal.com/"])
    assert result is None