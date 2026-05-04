"""Tests for watermark forward-only guarantee (C-3)."""
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock


def test_clustering_watermark_only_advances_forward():
    """Watermark must never go backwards when a newer timestamp already exists."""
    from services.clustering_service import _set_watermark

    session = MagicMock()
    existing_row = MagicMock()
    existing_row.last_processed_at = datetime.now(timezone.utc)
    existing_row.updated_at = datetime.now(timezone.utc)
    session.query.return_value.get.return_value = existing_row

    older_ts = datetime.now(timezone.utc) - timedelta(hours=1)
    _set_watermark("structural_hash", older_ts, session)

    # The watermark should NOT have been set to the older value
    assert existing_row.last_processed_at != older_ts


def test_phishkit_watermark_only_advances_forward():
    """Phishkit watermark must never go backwards either."""
    from services.phishkit_service import _set_watermark

    session = MagicMock()
    existing_row = MagicMock()
    existing_row.last_processed_at = datetime.now(timezone.utc)
    existing_row.updated_at = datetime.now(timezone.utc)
    session.query.return_value.get.return_value = existing_row

    older_ts = datetime.now(timezone.utc) - timedelta(hours=1)
    _set_watermark("phishkit", older_ts, session)

    assert existing_row.last_processed_at != older_ts