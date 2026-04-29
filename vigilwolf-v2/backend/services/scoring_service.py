"""Scoring service for VigilWolf v2 analysis pipeline.

Takes PluginResult outputs from detection plugins, applies weighted scoring
with non-linear confidence scaling, normalizes to 0-100, and determines risk
level with hard-signal overrides.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from config import HIGH_RISK_REGISTRARS, RISK_THRESHOLD_HIGH, RISK_THRESHOLD_MEDIUM
from plugins.base import PluginResult, PluginType

logger = logging.getLogger(__name__)

# Tags that immediately force a high-risk / critical classification.
HARD_SIGNAL_TAGS = {"credential_exfil", "known_phishkit"}

# Default plugin weights used when no DB configuration exists.
DEFAULT_WEIGHTS: dict[str, float] = {
    "login_detector": 0.30,
    "keyword_detector": 0.25,
    "brand_match": 0.20,
    "external_js_detector": 0.10,
    "nrd_age_scorer": 0.10,
    "html_hasher": 0.05,
}


def calculate_score(
    results: list[PluginResult],
    weights: dict[str, float],
) -> dict:
    """Calculate a composite risk score from detection plugin results.

    Only DETECTION-type plugins contribute to the score.  EXTRACTION,
    ENRICHMENT, and FINGERPRINT plugins are filtered out.

    Args:
        results: List of PluginResult objects from the analysis pipeline.
        weights: Mapping of plugin_name to weight (0.0-1.0 range).

    Returns:
        Dictionary with: normalized_score, score, risk_level, severity,
        reasons, dominant_signals, plugin_breakdown, overall_confidence,
        hard_signal.
    """
    # Step 1 -- Filter to DETECTION plugins only.
    detection_results = [
        r for r in results if r.plugin_type == PluginType.DETECTION
    ]

    if not detection_results:
        return _empty_result()

    # Step 2 -- Calculate max_possible (denominator for normalization).
    #   max_possible = sum(score_contribution * weight) for every detection
    #   result that has a weight assigned.
    max_possible = 0.0
    for r in detection_results:
        w = weights.get(r.plugin_name, 0.0)
        max_possible += r.score_contribution * w

    # Step 3 -- Calculate weighted contributions with non-linear confidence
    #   scaling (confidence ** 1.5).
    total_weighted = 0.0
    plugin_breakdown: dict[str, float] = {}
    confidence_numerator = 0.0
    confidence_denominator = 0.0
    hard_signal = False
    reasons: list[str] = []

    for r in detection_results:
        w = weights.get(r.plugin_name, 0.0)
        confidence_factor = r.confidence ** 1.5
        weighted_contribution = r.score_contribution * w * confidence_factor
        total_weighted += weighted_contribution
        plugin_breakdown[r.plugin_name] = round(weighted_contribution, 2)

        # Accumulate confidence for weighted average.
        confidence_numerator += r.confidence * w
        confidence_denominator += w

        # Check for hard-signal tags.
        for tag in r.tags:
            if tag in HARD_SIGNAL_TAGS:
                hard_signal = True
                reasons.append(f"Hard signal: {tag}")

        # Collect non-zero score reasons.
        if r.score_contribution > 0 and r.tags:
            for tag in r.tags:
                if tag not in HARD_SIGNAL_TAGS:
                    reasons.append(f"{r.plugin_name}: {tag}")

    # Step 4 -- Normalize.
    if max_possible > 0:
        normalized = (total_weighted / max_possible) * 100
    else:
        normalized = 0.0

    score = min(100, round(normalized))

    # Step 5 -- Determine risk level and severity.
    risk_level: str
    severity: str

    if score >= RISK_THRESHOLD_HIGH:
        risk_level = "high"
    elif score >= RISK_THRESHOLD_MEDIUM:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Severity defaults based on risk_level.
    severity_map = {"high": "high", "medium": "medium", "low": "low"}
    severity = severity_map[risk_level]

    # Step 6 -- Hard signal override.
    if hard_signal:
        score = max(score, 85)
        risk_level = "high"
        severity = "critical"

    # Step 7 -- Dominant signals: top 2 contributing plugins.
    sorted_plugins = sorted(
        plugin_breakdown.items(), key=lambda item: item[1], reverse=True
    )
    dominant_signals = [name for name, val in sorted_plugins[:2] if val > 0]

    # Step 8 -- Overall confidence (weighted average of detection plugin
    #   confidence values).
    overall_confidence: float = (
        round(confidence_numerator / confidence_denominator, 2)
        if confidence_denominator > 0
        else 0.0
    )

    return {
        "normalized_score": round(normalized, 1),
        "score": score,
        "risk_level": risk_level,
        "severity": severity,
        "reasons": reasons,
        "dominant_signals": dominant_signals,
        "plugin_breakdown": plugin_breakdown,
        "overall_confidence": overall_confidence,
        "hard_signal": hard_signal,
    }


def _empty_result() -> dict:
    """Return a zero-score result for empty / no detection inputs."""
    return {
        "normalized_score": 0.0,
        "score": 0,
        "risk_level": "low",
        "severity": "low",
        "reasons": [],
        "dominant_signals": [],
        "plugin_breakdown": {},
        "overall_confidence": 0.0,
        "hard_signal": False,
    }


def apply_context_modifiers(score: int, ctx, reasons: list) -> dict:
    """Apply context-aware scoring modifiers based on domain age and registrar.

    Checks the SnapshotContext for domain age (< 3 days) and high-risk
    registrar membership, adding modifier points and reason strings.

    Args:
        score: The current risk score (0-100).
        ctx: A SnapshotContext instance with snapshot_record dict.
        reasons: The current list of reason strings (not modified in-place).

    Returns:
        Dictionary with: score, risk_level, severity, modifier_total,
        modifier_reasons.
    """
    modifier_total = 0
    modifier_reasons: list[str] = []

    # --- Domain age modifier ---
    first_seen = ctx.snapshot_record.get("first_seen")
    if first_seen:
        try:
            if isinstance(first_seen, str):
                first_seen_dt = datetime.fromisoformat(first_seen)
            else:
                first_seen_dt = first_seen
            # Ensure timezone-aware comparison
            now = datetime.now(timezone.utc)
            if first_seen_dt.tzinfo is None:
                first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
            age_days = (now - first_seen_dt).days
            if age_days < 3:
                modifier_total += 10
                modifier_reasons.append("context: domain_age_lt_3_days")
        except (ValueError, TypeError):
            logger.debug("Could not parse first_seen date: %s", first_seen)

    # --- High-risk registrar modifier ---
    registrar = ctx.snapshot_record.get("registrar")
    if registrar:
        registrar_lower = registrar.lower()
        high_risk_lower = [r.lower() for r in HIGH_RISK_REGISTRARS]
        if registrar_lower in high_risk_lower:
            modifier_total += 5
            modifier_reasons.append("context: high_risk_registrar")

    # --- Compute final score (capped at 100) ---
    final_score = min(100, score + modifier_total)

    # --- Determine risk level and severity from final_score ---
    if final_score >= RISK_THRESHOLD_HIGH:
        risk_level = "high"
    elif final_score >= RISK_THRESHOLD_MEDIUM:
        risk_level = "medium"
    else:
        risk_level = "low"

    severity_map = {"high": "high", "medium": "medium", "low": "low"}
    severity = severity_map[risk_level]

    return {
        "score": final_score,
        "risk_level": risk_level,
        "severity": severity,
        "modifier_total": modifier_total,
        "modifier_reasons": modifier_reasons,
    }


class ScoringService:
    """Stateful scoring service that loads weights from DB (or defaults)."""

    def __init__(self) -> None:
        self._weights: dict[str, float] = DEFAULT_WEIGHTS.copy()

    def load_weights(self, db_session: Optional[object] = None) -> None:
        """Load plugin weights from the database.

        Falls back to DEFAULT_WEIGHTS if the database is unavailable or
        no PluginWeightModel rows exist.

        Args:
            db_session: Optional SQLAlchemy session.  If None, keeps
                current weights unchanged.
        """
        if db_session is None:
            logger.debug("No DB session provided; using default weights.")
            self._weights = DEFAULT_WEIGHTS.copy()
            return

        try:
            # Lazy import to avoid hard DB dependency at module level.
            from database import PluginWeightModel  # type: ignore[import-untyped]

            rows = db_session.query(PluginWeightModel).all()
            if rows:
                self._weights = {row.plugin_name: row.weight for row in rows}
                logger.info("Loaded %d plugin weights from DB.", len(rows))
            else:
                logger.info("No weight rows in DB; using defaults.")
                self._weights = DEFAULT_WEIGHTS.copy()
        except Exception:
            logger.exception("Failed to load weights from DB; using defaults.")
            self._weights = DEFAULT_WEIGHTS.copy()

    def get_weights(self) -> dict[str, float]:
        """Return the current weight mapping."""
        return self._weights.copy()

    def score_results(self, results: list[PluginResult]) -> dict:
        """Score a list of plugin results using current weights.

        Args:
            results: Plugin results from the analysis pipeline.

        Returns:
            Score dictionary from calculate_score().
        """
        return calculate_score(results, self._weights)