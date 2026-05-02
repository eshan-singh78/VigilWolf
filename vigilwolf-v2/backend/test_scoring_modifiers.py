"""Tests for context-aware scoring modifiers in VigilWolf v2."""
from datetime import datetime, timedelta, timezone

import pytest

from plugins.base import SnapshotContext
from services.scoring_service import apply_context_modifiers


def _make_ctx(**overrides) -> SnapshotContext:
    """Build a minimal SnapshotContext for testing.

    Defaults: domain age > 3 days, safe registrar, no special metadata.
    Override snapshot_record fields via kwargs.
    """
    defaults = {
        "snapshot_id": "test-snapshot",
        "domain": "example.com",
        "html": "<html></html>",
        "text": "",
        "forms": [],
        "links": [],
        "scripts": [],
        "metadata": {},
        "snapshot_record": {},
    }
    defaults.update(overrides)
    return SnapshotContext(**defaults)


# ---------------------------------------------------------------------------
# test_modifier_young_domain
# ---------------------------------------------------------------------------
def test_modifier_young_domain():
    """Domain age < 3 days should add +10 to the score."""
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": two_days_ago, "registrar": "saferegistrar"})

    result = apply_context_modifiers(score=40, ctx=ctx, reasons=[])

    assert result["score"] == 50
    assert result["modifier_total"] == 10
    assert "context: domain_age_lt_3_days" in result["modifier_reasons"]


# ---------------------------------------------------------------------------
# test_modifier_high_risk_registrar
# ---------------------------------------------------------------------------
def test_modifier_high_risk_registrar():
    """Registrar in HIGH_RISK_REGISTRARS should add +5 (case-insensitive)."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": old_date, "registrar": "NameCheap"})

    result = apply_context_modifiers(score=40, ctx=ctx, reasons=[])

    assert result["score"] == 45
    assert result["modifier_total"] == 5
    assert "context: high_risk_registrar" in result["modifier_reasons"]


# ---------------------------------------------------------------------------
# test_modifier_both
# ---------------------------------------------------------------------------
def test_modifier_both():
    """Young domain + high-risk registrar should add +15, capped at 100."""
    one_day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": one_day_ago, "registrar": "namecheap"})

    result = apply_context_modifiers(score=60, ctx=ctx, reasons=[])

    assert result["score"] == 75
    assert result["modifier_total"] == 15
    assert "context: domain_age_lt_3_days" in result["modifier_reasons"]
    assert "context: high_risk_registrar" in result["modifier_reasons"]


# ---------------------------------------------------------------------------
# test_modifier_old_domain_safe_registrar
# ---------------------------------------------------------------------------
def test_modifier_old_domain_safe_registrar():
    """Old domain with safe registrar should add no modifier."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": old_date, "registrar": "saferegistrar"})

    result = apply_context_modifiers(score=30, ctx=ctx, reasons=[])

    assert result["score"] == 30
    assert result["modifier_total"] == 0
    assert result["modifier_reasons"] == []


# ---------------------------------------------------------------------------
# test_modifier_score_cap
# ---------------------------------------------------------------------------
def test_modifier_score_cap():
    """Score + modifier total should be capped at 100."""
    one_day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": one_day_ago, "registrar": "godaddy"})

    result = apply_context_modifiers(score=95, ctx=ctx, reasons=[])

    # 95 + 15 = 110, capped to 100
    assert result["score"] == 100
    assert result["modifier_total"] == 15


# ---------------------------------------------------------------------------
# test_modifier_reasons_included
# ---------------------------------------------------------------------------
def test_modifier_reasons_included():
    """Modifier reasons should appear in the returned dict."""
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": two_days_ago, "registrar": "dynadot"})

    result = apply_context_modifiers(score=20, ctx=ctx, reasons=["existing_reason"])

    assert "context: domain_age_lt_3_days" in result["modifier_reasons"]
    assert "context: high_risk_registrar" in result["modifier_reasons"]
    assert result["modifier_total"] == 15


# ---------------------------------------------------------------------------
# test_modifier_missing_first_seen
# ---------------------------------------------------------------------------
def test_modifier_missing_first_seen():
    """Missing first_seen should skip the age modifier (no crash)."""
    ctx = _make_ctx(snapshot_record={"registrar": "namecheap"})

    result = apply_context_modifiers(score=30, ctx=ctx, reasons=[])

    assert result["score"] == 35  # Only registrar modifier
    assert result["modifier_total"] == 5
    assert "context: domain_age_lt_3_days" not in result["modifier_reasons"]


# ---------------------------------------------------------------------------
# test_modifier_risk_level_escalation
# ---------------------------------------------------------------------------
def test_modifier_risk_level_escalation():
    """Modifiers should correctly escalate risk_level from low to medium."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    ctx = _make_ctx(snapshot_record={"first_seen": old_date, "registrar": "namecheap"})

    # Score 38 is "low" (< 40), +5 = 43 which is "medium" (>= 40)
    result = apply_context_modifiers(score=38, ctx=ctx, reasons=[])

    assert result["score"] == 43
    assert result["risk_level"] == "medium"
    assert result["severity"] == "medium"