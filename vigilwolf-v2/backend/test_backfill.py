"""Tests for the VigilWolf v2 backfill script.

Uses in-memory SQLite for database operations. Mocks get_session at the
database module level so the lazy import inside backfill_snapshots picks
up our test session factory.
"""
import os
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database import Base, DomainModel, SnapshotModel, RiskScoreModel, GroupModel
import config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """Create an in-memory SQLite engine with all tables."""
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=eng)
    yield eng


@pytest.fixture
def session(engine):
    """Return a session bound to the in-memory engine."""
    sess = Session(bind=engine)
    yield sess
    sess.close()


@pytest.fixture
def seeded_db(engine):
    """Seed the in-memory DB with a group, domain, and four snapshots.

    Snapshots:
      - snap-good:     success=True,  html_path="snapshots/good.html"
      - snap-no-html:  success=True,  html_path=""  (should be skipped)
      - snap-failed:   success=False, html_path="snapshots/failed.html" (should be skipped by query)
      - snap-badref:   success=True,  html_path="snapshots/badref.html",
                       domain_id=nonexistent (should be skipped — no matching domain)
    """
    sess = Session(bind=engine)

    group = GroupModel(name="test-group")
    sess.add(group)
    sess.flush()

    domain1 = DomainModel(id="dom-1", group_id=group.id, url="example.com")
    domain2 = DomainModel(id="dom-2", group_id=group.id, url="other.com")
    sess.add_all([domain1, domain2])
    sess.flush()

    snapshots = [
        SnapshotModel(
            id="snap-good",
            domain_id=domain1.id,
            trigger_type="nrd_ingest",
            html_path="snapshots/good.html",
            success=True,
        ),
        SnapshotModel(
            id="snap-no-html",
            domain_id=domain1.id,
            trigger_type="nrd_ingest",
            html_path="",  # empty string = no HTML stored (NOT NULL column)
            success=True,
        ),
        SnapshotModel(
            id="snap-failed",
            domain_id=domain1.id,
            trigger_type="nrd_ingest",
            html_path="snapshots/failed.html",
            success=False,
        ),
        SnapshotModel(
            id="snap-badref",
            domain_id="nonexistent-domain-id",
            trigger_type="nrd_ingest",
            html_path="snapshots/badref.html",
            success=True,
        ),
    ]
    sess.add_all(snapshots)
    sess.commit()
    sess.close()
    return engine


def _make_session_factory(engine):
    """Return a callable that yields Session objects bound to the given engine.

    Mimics the context-manager interface of database.get_session().
    """
    from contextlib import contextmanager

    @contextmanager
    def session_ctx():
        sess = Session(bind=engine)
        try:
            yield sess
        finally:
            sess.close()

    return session_ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBackfillDryRun:
    """Dry-run mode should not create any risk scores or run the pipeline."""

    @patch("backfill._load_html", return_value="<html>test</html>")
    def test_dry_run_no_risk_scores(self, mock_load_html, seeded_db):
        """Dry run should not create any RiskScoreModel rows."""
        import database
        original_get_session = database.get_session
        database.get_session = _make_session_factory(seeded_db)

        try:
            from backfill import backfill_snapshots
            result = backfill_snapshots(dry_run=True)
        finally:
            database.get_session = original_get_session

        # snap-good: success=True, html_path set, valid domain => processed
        # snap-badref: success=True, html_path set, but no domain => skipped
        # snap-no-html: success=True, but html_path="" => skipped
        # snap-failed: excluded by WHERE success=True
        assert result["processed"] >= 1, f"Expected at least 1 processed, got {result}"
        assert result["errors"] == 0

        # Verify no RiskScoreModel rows were created
        with Session(bind=seeded_db) as check_sess:
            risk_count = check_sess.query(RiskScoreModel).count()
        assert risk_count == 0, "Dry-run should not create any risk scores"


class TestBackfillSkipsFailedSnapshots:
    """Snapshots with success=False should be excluded by the query."""

    @patch("backfill._load_html", return_value="<html>test</html>")
    def test_skips_failed_snapshots(self, mock_load_html, seeded_db):
        """Only success=True snapshots are selected by the query."""
        import database
        original_get_session = database.get_session
        database.get_session = _make_session_factory(seeded_db)

        try:
            from backfill import backfill_snapshots
            result = backfill_snapshots(dry_run=True)
        finally:
            database.get_session = original_get_session

        # snap-failed (success=False) is excluded by the query.
        # No errors should occur.
        assert result["errors"] == 0


class TestBackfillSkipsMissingHtml:
    """Snapshots without html_path should be skipped."""

    @patch("backfill._load_html", return_value=None)
    def test_skips_snapshots_where_html_load_fails(self, mock_load_html, seeded_db):
        """If _load_html returns None, the snapshot should be skipped."""
        import database
        original_get_session = database.get_session
        database.get_session = _make_session_factory(seeded_db)

        try:
            from backfill import backfill_snapshots
            result = backfill_snapshots(dry_run=True)
        finally:
            database.get_session = original_get_session

        # _load_html returns None for everything with a non-empty html_path,
        # so those get skipped. snap-no-html is also skipped (empty html_path).
        assert result["skipped"] >= 1, f"Expected skips, got {result}"


class TestBackfillSkipsEmptyHtmlPath:
    """Snapshots with empty html_path should be skipped."""

    @patch("backfill._load_html", return_value="<html>test</html>")
    def test_skips_empty_html_path(self, mock_load_html, seeded_db):
        """Snapshots with html_path='' should be skipped before _load_html is called."""
        import database
        original_get_session = database.get_session
        database.get_session = _make_session_factory(seeded_db)

        try:
            from backfill import backfill_snapshots
            result = backfill_snapshots(dry_run=True)
        finally:
            database.get_session = original_get_session

        # snap-no-html has html_path="" and should be skipped.
        # Total should cover all 3 success=True snapshots:
        #   snap-good (processed or skipped), snap-no-html (skipped), snap-badref (skipped)
        assert result["skipped"] >= 1, f"Expected at least 1 skip (empty html_path), got {result}"
        total = result["processed"] + result["skipped"] + result["errors"]
        assert total == 3, f"Expected 3 total snapshots processed/skipped/errored, got {total}"


class TestBackfillReturnsCounts:
    """Backfill should return processed/skipped/errors counts."""

    @patch("backfill._load_html", return_value="<html>test</html>")
    def test_returns_count_dict(self, mock_load_html, seeded_db):
        """backfill_snapshots should return a dict with processed, skipped, errors."""
        import database
        original_get_session = database.get_session
        database.get_session = _make_session_factory(seeded_db)

        try:
            from backfill import backfill_snapshots
            result = backfill_snapshots(dry_run=True)
        finally:
            database.get_session = original_get_session

        assert isinstance(result, dict)
        assert "processed" in result
        assert "skipped" in result
        assert "errors" in result
        assert all(isinstance(v, int) for v in result.values())


class TestBackfillLimit:
    """The --limit flag should cap the number of snapshots processed."""

    @patch("backfill._load_html", return_value="<html>test</html>")
    def test_limit_caps_processing(self, mock_load_html, seeded_db):
        """With limit=1, only one snapshot should be in the processing loop."""
        import database
        original_get_session = database.get_session
        database.get_session = _make_session_factory(seeded_db)

        try:
            from backfill import backfill_snapshots
            result = backfill_snapshots(dry_run=True, limit=1)
        finally:
            database.get_session = original_get_session

        # With limit=1, at most 1 snapshot is examined.
        assert result["processed"] + result["skipped"] + result["errors"] <= 1, (
            f"Expected at most 1 snapshot processed/skipped/errored with limit=1, got {result}"
        )


class TestBackfillLoadHtml:
    """Tests for the _load_html helper."""

    def test_load_html_returns_none_for_missing_file(self, tmp_path):
        """_load_html returns None when the file does not exist."""
        from backfill import _load_html

        with patch.object(config, "MONITORING_DATA_DIR", str(tmp_path)):
            result = _load_html("nonexistent.html")
        assert result is None

    def test_load_html_reads_existing_file(self, tmp_path):
        """_load_html returns file contents for an existing file."""
        from backfill import _load_html

        # Create a test file
        sub = tmp_path / "snapshots"
        sub.mkdir()
        (sub / "test.html").write_text("<html>hello</html>", encoding="utf-8")

        with patch.object(config, "MONITORING_DATA_DIR", str(tmp_path)):
            result = _load_html("snapshots/test.html")

        assert result == "<html>hello</html>"

    def test_load_html_returns_none_on_read_error(self, tmp_path):
        """_load_html returns None when the file can't be read."""
        from backfill import _load_html

        # Create a directory where a file is expected (causes read error)
        sub = tmp_path / "snapshots"
        sub.mkdir()
        (sub / "bad.html").mkdir()  # directory, not a file

        with patch.object(config, "MONITORING_DATA_DIR", str(tmp_path)):
            result = _load_html("snapshots/bad.html")

        assert result is None