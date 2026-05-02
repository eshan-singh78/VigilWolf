"""Tests for the EnvelopeMiddleware.

Verifies that /api/v2/* responses are wrapped in the standard envelope
while /health, error responses, and non-JSON responses pass through unchanged.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from main import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """In-memory SQLite engine with all tables created."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng


@pytest.fixture(scope="module")
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def db_session(session_factory):
    session = session_factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def client(engine, session_factory):
    """Test client with DB session override."""

    def _override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    tc = TestClient(app)
    yield tc
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEnvelopeWrapping:
    """Core wrapping behaviour for /api/v2/* paths."""

    def test_envelope_wraps_v2_response(self, client):
        """Successful v2 responses should be wrapped in {data, meta}."""
        resp = client.get("/api/v2/domains")
        assert resp.status_code == 200
        body = resp.json()

        # Top-level keys should be exactly "data" and "meta"
        assert "data" in body
        assert "meta" in body

        meta = body["meta"]
        assert "request_id" in meta
        assert "timestamp" in meta
        # request_id should be a 12-char hex string
        assert len(meta["request_id"]) == 12

    def test_envelope_does_not_wrap_health(self, client):
        """The /health endpoint is not a v2 path and must not be wrapped."""
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()

        # The raw response has "status" and "version" at top level — no
        # envelope wrapping should occur.
        assert "status" in body
        assert "version" in body
        assert "data" not in body
        assert "meta" not in body

    def test_envelope_does_not_wrap_errors(self, client):
        """Error responses (4xx) must pass through unwrapped."""
        resp = client.get("/api/v2/domains/nonexistent-id")
        assert resp.status_code == 404
        body = resp.json()

        # Error responses should have FastAPI's default "detail" key,
        # not the envelope structure.
        assert "detail" in body
        assert "data" not in body
        assert "meta" not in body

    def test_request_id_unique(self, client):
        """Each request should receive a different request_id."""
        resp1 = client.get("/api/v2/domains")
        resp2 = client.get("/api/v2/domains")

        id1 = resp1.json()["meta"]["request_id"]
        id2 = resp2.json()["meta"]["request_id"]
        assert id1 != id2

    def test_pagination_fields_in_meta(self, client):
        """Pagination keys (next_cursor, total, has_more) should be
        promoted from the data dict into meta."""

        resp = client.get("/api/v2/domains")
        assert resp.status_code == 200
        body = resp.json()

        meta = body["meta"]
        # The /domains endpoint returns {items, next_cursor, total}.
        # After envelope wrapping, items becomes data and pagination keys
        # are in meta.
        assert "total" in meta
        # next_cursor should exist (may be None)
        assert "next_cursor" in meta
        # data should be the items list
        assert isinstance(body["data"], list)

    def test_timestamp_format(self, client):
        """The timestamp in meta should be ISO 8601 UTC."""
        resp = client.get("/api/v2/domains")
        meta = resp.json()["meta"]
        ts = meta["timestamp"]
        # Should end with Z (UTC) and look like YYYY-MM-DDTHH:MM:SSZ
        assert ts.endswith("Z")
        assert "T" in ts

    def test_single_item_response_wrapped(self, client):
        """A dict response without 'items' should be wrapped as data
        (not further deconstructed)."""
        # /api/v2/threats/stats returns {total, high, medium, low}
        resp = client.get("/api/v2/threats/stats")
        assert resp.status_code == 200
        body = resp.json()

        assert "data" in body
        assert "meta" in body
        # 'total' should have been promoted to meta
        assert "total" in body["meta"]
        # data should still have the remaining keys (high, medium, low)
        assert "high" in body["data"]
        assert "medium" in body["data"]
        assert "low" in body["data"]

    def test_request_id_on_state(self, client):
        """The middleware should attach request_id to request.state."""
        # We verify this indirectly — if the envelope contains a request_id,
        # the middleware successfully set it on state during dispatch.
        resp = client.get("/api/v2/domains")
        assert resp.status_code == 200
        request_id = resp.json()["meta"]["request_id"]
        assert isinstance(request_id, str)
        assert len(request_id) == 12