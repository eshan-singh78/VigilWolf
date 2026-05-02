"""Tests for dispatch_alert — verify it calls AlertService.send_alert with the
correct positional arguments and respects the dry-run gate."""

from unittest.mock import patch, MagicMock
import sys
import os

# Ensure the backend directory is on the import path.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugins.base import SnapshotContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ctx() -> SnapshotContext:
    """Return a minimal SnapshotContext for testing."""
    return SnapshotContext(
        snapshot_id="snap-001",
        domain="evil.example.com",
        html="<html></html>",
        text="",
        forms=[],
        links=[],
        scripts=[],
        metadata={},
        snapshot_record={"domain_id": "dom-001"},
    )


def _make_score_outcome() -> dict:
    """Return a minimal score_outcome dict for testing."""
    return {
        "score": 75,
        "normalized_score": 75.0,
        "risk_level": "high",
        "severity": "critical",
        "reasons": ["suspicious domain"],
        "dominant_signals": ["ssl_plugin"],
        "plugin_breakdown": {},
        "overall_confidence": 0.9,
    }


# ---------------------------------------------------------------------------
# Test: send_alert receives correct arguments
# ---------------------------------------------------------------------------

@patch("worker.config")
@patch("worker.AlertService", create=True)
@patch("database.get_session")
def test_dispatch_alert_passes_ctx_and_score_outcome(
    mock_get_session, mock_alert_service_cls, mock_config,
):
    """dispatch_alert must pass (ctx, score_outcome, session) to send_alert."""
    # Arrange
    mock_config.ALERTS_DRY_RUN = False
    mock_config.ALERTS_ENABLED = True

    # Mock the session context manager returned by get_session()
    mock_session = MagicMock()
    mock_get_session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_get_session.return_value.__exit__ = MagicMock(return_value=False)

    # Mock AlertService class and instance
    mock_instance = MagicMock()
    mock_alert_service_cls.return_value = mock_instance

    # Patch the import inside dispatch_alert so that
    #   from services.alert_service import AlertService
    #   from database import get_session
    # return our mocks.
    with patch.dict(sys.modules, {
        "services.alert_service": MagicMock(AlertService=mock_alert_service_cls),
        "database": MagicMock(get_session=mock_get_session),
    }):
        from worker import dispatch_alert

        ctx = _make_ctx()
        score_outcome = _make_score_outcome()

        # Act
        dispatch_alert(ctx, score_outcome)

    # Assert — send_alert called with (ctx, score_outcome, session)
    mock_instance.send_alert.assert_called_once_with(ctx, score_outcome, mock_session)


# ---------------------------------------------------------------------------
# Test: dry-run skips send_alert entirely
# ---------------------------------------------------------------------------

@patch("worker.config")
def test_dispatch_alert_dry_run_skips_send_alert(mock_config):
    """When ALERTS_DRY_RUN is True, send_alert must NOT be called."""
    mock_config.ALERTS_DRY_RUN = True

    mock_alert_service_cls = MagicMock()
    mock_instance = MagicMock()
    mock_alert_service_cls.return_value = mock_instance

    ctx = _make_ctx()
    score_outcome = _make_score_outcome()

    with patch.dict(sys.modules, {
        "services.alert_service": MagicMock(AlertService=mock_alert_service_cls),
    }):
        from worker import dispatch_alert
        dispatch_alert(ctx, score_outcome)

    # AlertService should never be instantiated when dry-run is active.
    mock_alert_service_cls.assert_not_called()
    mock_instance.send_alert.assert_not_called()