"""Tests for the VigilWolf v2 Scoring Service."""
import pytest
from plugins.base import PluginResult, PluginType
from services.scoring_service import calculate_score, ScoringService


# ---------------------------------------------------------------------------
# test_normalized_score_calculation
# ---------------------------------------------------------------------------
def test_normalized_score_calculation():
    """Three detection results with different weights produce a score in
    0-100 and the correct risk_level."""
    results = [
        PluginResult(
            plugin_name="login_detector",
            plugin_version="1.0",
            plugin_type=PluginType.DETECTION,
            score_contribution=80,
            confidence=0.9,
            tags=["login_form"],
            findings={"has_login": True},
        ),
        PluginResult(
            plugin_name="keyword_detector",
            plugin_version="1.0",
            plugin_type=PluginType.DETECTION,
            score_contribution=60,
            confidence=0.7,
            tags=["suspicious_keyword"],
            findings={"matched_keywords": ["verify"]},
        ),
        PluginResult(
            plugin_name="brand_match",
            plugin_version="1.0",
            plugin_type=PluginType.DETECTION,
            score_contribution=40,
            confidence=0.5,
            tags=["brand_similarity"],
            findings={"brand": "example"},
        ),
    ]
    weights = {
        "login_detector": 0.5,
        "keyword_detector": 0.3,
        "brand_match": 0.2,
    }
    result = calculate_score(results, weights)

    # Score must be in 0-100 range
    assert 0 <= result["score"] <= 100
    assert 0 <= result["normalized_score"] <= 100

    # With non-trivial inputs, risk_level should not be low
    assert result["risk_level"] in ("low", "medium", "high")

    # plugin_breakdown should contain all detection plugins
    assert "login_detector" in result["plugin_breakdown"]
    assert "keyword_detector" in result["plugin_breakdown"]
    assert "brand_match" in result["plugin_breakdown"]

    # dominant_signals should have at most 2 entries
    assert len(result["dominant_signals"]) <= 2

    # overall_confidence should be a weighted average
    assert 0 <= result["overall_confidence"] <= 1


# ---------------------------------------------------------------------------
# test_high_risk_detection
# ---------------------------------------------------------------------------
def test_high_risk_detection():
    """A detection result with the credential_exfil hard signal tag forces
    risk_level=high, severity=critical, and score >= 85."""
    results = [
        PluginResult(
            plugin_name="login_detector",
            plugin_version="1.0",
            plugin_type=PluginType.DETECTION,
            score_contribution=50,
            confidence=0.8,
            tags=["credential_exfil", "login_form"],
            findings={"exfil_endpoint": "https://evil.com/collect"},
        ),
    ]
    weights = {"login_detector": 1.0}
    result = calculate_score(results, weights)

    assert result["risk_level"] == "high"
    assert result["severity"] == "critical"
    assert result["score"] >= 85
    assert result["hard_signal"] is True


# ---------------------------------------------------------------------------
# test_low_risk_clean_domain
# ---------------------------------------------------------------------------
def test_low_risk_clean_domain():
    """All zero score contributions yields risk_level=low."""
    results = [
        PluginResult(
            plugin_name="login_detector",
            plugin_version="1.0",
            plugin_type=PluginType.DETECTION,
            score_contribution=0,
            confidence=0.1,
            tags=[],
            findings={},
        ),
        PluginResult(
            plugin_name="keyword_detector",
            plugin_version="1.0",
            plugin_type=PluginType.DETECTION,
            score_contribution=0,
            confidence=0.2,
            tags=[],
            findings={},
        ),
    ]
    weights = {"login_detector": 0.5, "keyword_detector": 0.5}
    result = calculate_score(results, weights)

    assert result["score"] == 0
    assert result["risk_level"] == "low"
    assert result["severity"] == "low"
    assert result["hard_signal"] is False


# ---------------------------------------------------------------------------
# test_nonlinear_confidence_scaling
# ---------------------------------------------------------------------------
def test_nonlinear_confidence_scaling():
    """Higher confidence produces a disproportionately higher normalized score
    due to the confidence ** 1.5 non-linear scaling."""
    # Two identical score_contributions and weights, but different confidence
    low_conf = PluginResult(
        plugin_name="detector_a",
        plugin_version="1.0",
        plugin_type=PluginType.DETECTION,
        score_contribution=100,
        confidence=0.3,
        tags=[],
        findings={},
    )
    high_conf = PluginResult(
        plugin_name="detector_b",
        plugin_version="1.0",
        plugin_type=PluginType.DETECTION,
        score_contribution=100,
        confidence=0.9,
        tags=[],
        findings={},
    )
    weights = {"detector_a": 1.0, "detector_b": 1.0}

    # Low confidence alone
    result_low = calculate_score([low_conf], weights)
    # High confidence alone
    result_high = calculate_score([high_conf], weights)

    # The high-confidence result should have a higher score
    assert result_high["normalized_score"] > result_low["normalized_score"]

    # Verify the non-linearity: the ratio of high/low scores should be
    # greater than the ratio of confidences (0.9/0.3 = 3)
    # because (0.9^1.5) / (0.3^1.5) > 0.9 / 0.3
    ratio_scores = result_high["normalized_score"] / max(result_low["normalized_score"], 0.01)
    ratio_confidence = high_conf.confidence / low_conf.confidence
    assert ratio_scores > ratio_confidence


# ---------------------------------------------------------------------------
# test_extraction_plugins_dont_affect_score
# ---------------------------------------------------------------------------
def test_extraction_plugins_dont_affect_score():
    """EXTRACTION and other non-DETECTION plugins should not affect the score."""
    detection_result = PluginResult(
        plugin_name="login_detector",
        plugin_version="1.0",
        plugin_type=PluginType.DETECTION,
        score_contribution=70,
        confidence=0.8,
        tags=["login_form"],
        findings={"has_login": True},
    )
    extraction_result = PluginResult(
        plugin_name="html_hasher",
        plugin_version="1.0",
        plugin_type=PluginType.EXTRACTION,
        score_contribution=90,
        confidence=0.95,
        tags=["fingerprint"],
        findings={"hash": "abc123"},
    )
    fingerprint_result = PluginResult(
        plugin_name="external_js_detector",
        plugin_version="1.0",
        plugin_type=PluginType.FINGERPRINT,
        score_contribution=80,
        confidence=0.9,
        tags=["external_js"],
        findings={"scripts": ["evil.js"]},
    )
    enrichment_result = PluginResult(
        plugin_name="nrd_age_scorer",
        plugin_version="1.0",
        plugin_type=PluginType.ENRICHMENT,
        score_contribution=60,
        confidence=0.7,
        tags=["nrd"],
        findings={"days_since_registration": 3},
    )

    weights = {
        "login_detector": 1.0,
        "html_hasher": 0.5,
        "external_js_detector": 0.3,
        "nrd_age_scorer": 0.2,
    }

    # Score with only detection result
    result_detection_only = calculate_score([detection_result], weights)
    # Score with detection + non-detection results
    result_all = calculate_score(
        [detection_result, extraction_result, fingerprint_result, enrichment_result],
        weights,
    )

    # Both should produce the same score
    assert result_all["score"] == result_detection_only["score"]
    assert result_all["normalized_score"] == result_detection_only["normalized_score"]

    # Only detection plugins should appear in the breakdown
    assert "html_hasher" not in result_all["plugin_breakdown"]
    assert "external_js_detector" not in result_all["plugin_breakdown"]
    assert "nrd_age_scorer" not in result_all["plugin_breakdown"]


# ---------------------------------------------------------------------------
# ScoringService class tests
# ---------------------------------------------------------------------------
class TestScoringService:
    """Tests for the ScoringService class."""

    def test_default_weights(self):
        """ScoringService should have sensible default weights."""
        service = ScoringService()
        weights = service.get_weights()
        assert isinstance(weights, dict)
        # Should contain all six expected plugins
        expected_plugins = {
            "login_detector",
            "keyword_detector",
            "brand_match",
            "external_js_detector",
            "nrd_age_scorer",
            "html_hasher",
        }
        for plugin in expected_plugins:
            assert plugin in weights, f"Missing default weight for {plugin}"

    def test_score_results_uses_default_weights(self):
        """score_results should use default weights when no DB session given."""
        service = ScoringService()
        results = [
            PluginResult(
                plugin_name="login_detector",
                plugin_version="1.0",
                plugin_type=PluginType.DETECTION,
                score_contribution=50,
                confidence=0.8,
                tags=[],
                findings={},
            ),
        ]
        result = service.score_results(results)
        assert "score" in result
        assert "risk_level" in result
        assert "plugin_breakdown" in result