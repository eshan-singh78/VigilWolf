"""Tests for intelligence_worker — verify feature-flag gating and enqueue behaviour."""

import sys
import os
from unittest.mock import patch, MagicMock

# Ensure the backend directory is on the import path.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Test: run_intelligence_pipeline returns None when pipeline is disabled
# ---------------------------------------------------------------------------


@patch("intelligence_worker.config")
def test_run_intelligence_pipeline_disabled(mock_config):
    """When INTELLIGENCE_PIPELINE_ENABLED is False, run_intelligence_pipeline
    must return None immediately without touching any services."""
    mock_config.INTELLIGENCE_PIPELINE_ENABLED = False

    # Import fresh so the config patch takes effect.
    from intelligence_worker import run_intelligence_pipeline

    result = run_intelligence_pipeline(snapshot_id="snap-001")

    assert result is None


# ---------------------------------------------------------------------------
# Test: enqueue_intelligence_pipeline returns immediately when disabled
# ---------------------------------------------------------------------------


@patch("intelligence_worker.config")
def test_enqueue_intelligence_pipeline_disabled(mock_config):
    """When INTELLIGENCE_PIPELINE_ENABLED is False, enqueue_intelligence_pipeline
    must return immediately without enqueuing or running anything."""
    mock_config.INTELLIGENCE_PIPELINE_ENABLED = False

    from intelligence_worker import enqueue_intelligence_pipeline

    # Should complete without error and without touching Dramatiq or any service.
    enqueue_intelligence_pipeline(snapshot_id="snap-001")


# ---------------------------------------------------------------------------
# Test: enqueue_intelligence_pipeline runs synchronously when Dramatiq is off
# ---------------------------------------------------------------------------


@patch("intelligence_worker.run_intelligence_pipeline")
@patch("intelligence_worker.config")
def test_enqueue_sync_calls_run_directly(mock_config, mock_run):
    """When USE_DRAMATIQ_PIPELINE is False, enqueue_intelligence_pipeline calls
    run_intelligence_pipeline synchronously."""
    mock_config.INTELLIGENCE_PIPELINE_ENABLED = True
    mock_config.USE_DRAMATIQ_PIPELINE = False
    mock_run.return_value = {"snapshot_id": "snap-001", "stages": {}}

    from intelligence_worker import enqueue_intelligence_pipeline

    enqueue_intelligence_pipeline(snapshot_id="snap-001")

    mock_run.assert_called_once_with("snap-001")


# ---------------------------------------------------------------------------
# Test: enqueue_intelligence_pipeline uses Dramatiq when enabled
# ---------------------------------------------------------------------------


@patch("intelligence_worker._get_intelligence_actor")
@patch("intelligence_worker.config")
def test_enqueue_dramatiq_sends_actor(mock_config, mock_get_actor):
    """When USE_DRAMATIQ_PIPELINE is True, enqueue_intelligence_pipeline
    sends a Dramatiq actor message instead of running synchronously."""
    mock_config.INTELLIGENCE_PIPELINE_ENABLED = True
    mock_config.USE_DRAMATIQ_PIPELINE = True

    mock_actor = MagicMock()
    mock_get_actor.return_value = mock_actor

    from intelligence_worker import enqueue_intelligence_pipeline

    enqueue_intelligence_pipeline(snapshot_id="snap-002")

    mock_get_actor.assert_called_once()
    mock_actor.send.assert_called_once_with(snapshot_id="snap-002")


# ---------------------------------------------------------------------------
# Test: run_intelligence_pipeline skips disabled stages
# ---------------------------------------------------------------------------


@patch("intelligence_worker._emit_intelligence_update")
@patch("intelligence_worker.config")
def test_run_pipeline_skips_disabled_stages(mock_config, mock_emit):
    """When individual stage flags are False, those stages must be skipped."""
    mock_config.INTELLIGENCE_PIPELINE_ENABLED = True
    mock_config.CLUSTERING_ENABLED = False
    mock_config.CAMPAIGN_DETECTION_ENABLED = False
    mock_config.PHISHKIT_DETECTION_ENABLED = False
    mock_config.C2_DETECTION_ENABLED = False
    mock_config.ACTOR_PROFILING_ENABLED = False

    from intelligence_worker import run_intelligence_pipeline

    result = run_intelligence_pipeline(snapshot_id="snap-003")

    assert result is not None
    assert result["snapshot_id"] == "snap-003"
    assert result["stages"] == {}
    mock_emit.assert_called_once()


# ---------------------------------------------------------------------------
# Test: run_intelligence_pipeline catches stage errors and continues
# ---------------------------------------------------------------------------


@patch("intelligence_worker._emit_intelligence_update")
@patch("intelligence_worker.config")
def test_run_pipeline_continues_after_stage_error(mock_config, mock_emit):
    """If clustering raises an exception, campaign detection should still run."""
    mock_config.INTELLIGENCE_PIPELINE_ENABLED = True
    mock_config.CLUSTERING_ENABLED = True
    mock_config.CAMPAIGN_DETECTION_ENABLED = True
    mock_config.PHISHKIT_DETECTION_ENABLED = False
    mock_config.ACTOR_PROFILING_ENABLED = False

    # Mock the database and service imports.
    mock_session = MagicMock()
    mock_get_session = MagicMock()
    mock_get_session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_get_session.return_value.__exit__ = MagicMock(return_value=False)

    mock_cluster_snapshot = MagicMock(side_effect=RuntimeError("DB error"))
    mock_detect_campaigns_for_snapshot = MagicMock(return_value=2)

    with patch.dict(sys.modules, {
        "database": MagicMock(get_session=mock_get_session),
        "services.clustering_service": MagicMock(cluster_snapshot=mock_cluster_snapshot),
        "services.campaign_service": MagicMock(detect_campaigns_for_snapshot=mock_detect_campaigns_for_snapshot),
    }):
        from intelligence_worker import run_intelligence_pipeline

        result = run_intelligence_pipeline(snapshot_id="snap-004")

    # Clustering should have logged errors, but pipeline should continue.
    assert result is not None
    assert result["stages"]["clustering"] == {"error": True}
    assert result["stages"]["campaign_detection"] == {"campaigns_created_or_updated": 2}
    mock_emit.assert_called_once()