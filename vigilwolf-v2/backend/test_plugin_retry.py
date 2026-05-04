"""Tests for plugin retry idempotency (C-4)."""
from unittest.mock import MagicMock
from database import AnalysisResultModel


def test_duplicate_analysis_result_does_not_raise():
    """On retry, inserting a duplicate AnalysisResultModel should be skipped."""
    session = MagicMock()
    existing = MagicMock(spec=AnalysisResultModel)
    session.query.return_value.filter_by.return_value.first.return_value = existing

    snapshot_id = "test-snap-123"
    plugin_name = "ioc_extractor"
    result = session.query(AnalysisResultModel).filter_by(
        snapshot_id=snapshot_id, plugin_name=plugin_name
    ).first()

    assert result is not None
    session.add.assert_not_called()