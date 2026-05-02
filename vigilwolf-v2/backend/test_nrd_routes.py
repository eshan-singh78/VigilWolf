"""Tests for NRD routes and monitoring domain management endpoints."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db, GroupModel, DomainModel
from main import app
import config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """Create a fresh in-memory SQLite engine with all tables."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng


@pytest.fixture(scope="module")
def session_factory(engine):
    """Session factory bound to the test engine."""
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def db_session(session_factory):
    """Provide a transactional test session that rolls back after each test."""
    session = session_factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def client(engine, session_factory):
    """FastAPI test client with DB session override."""
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


@pytest.fixture
def nrd_temp_dir(tmp_path, monkeypatch):
    """Set up a temporary NRD directory and patch MONITORING_DATA_DIR."""
    nrd_dir = tmp_path / "nrd-file-dump"
    nrd_dir.mkdir()
    monkeypatch.setattr("services.nrd_service.NRD_DIR", str(nrd_dir))
    monkeypatch.setattr("services.nrd_service.MONITORING_DATA_DIR", str(tmp_path))
    return nrd_dir


def _unwrap_envelope(json_body: dict) -> dict:
    """Extract the 'data' payload from the EnvelopeMiddleware wrapper.

    Successful /api/v2/* responses are wrapped as:
        {"data": <original body>, "meta": {"request_id": ..., "timestamp": ...}}
    The 'total' key (if present in the original body) is promoted into meta.
    """
    if "data" in json_body:
        return json_body["data"]
    return json_body


# ---------------------------------------------------------------------------
# NRD route tests
# ---------------------------------------------------------------------------

class TestNrdRoutes:
    """Tests for /api/v2/nrd/* endpoints."""

    def test_list_nrd_dumps_empty(self, client, nrd_temp_dir):
        """Returns empty list when no dumps exist."""
        resp = client.get("/api/v2/nrd/latest")
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert body["dumps"] == []

    def test_list_nrd_dumps_with_files(self, client, nrd_temp_dir):
        """Returns dumps with metadata when files exist."""
        # Create a test dump file
        dump_path = nrd_temp_dir / "nrd_2025-11-21.txt"
        dump_path.write_text("example.com\nfake-domain.net\n")

        resp = client.get("/api/v2/nrd/latest")
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert body["dumps"]
        dump = body["dumps"][0]
        assert dump["filename"] == "nrd_2025-11-21.txt"
        assert dump["date"] == "2025-11-21"
        assert dump["domain_count"] == 2
        assert dump["size_bytes"] > 0
        assert dump["last_modified"] is not None

    def test_search_nrd_dumps(self, client, nrd_temp_dir):
        """Search returns matching results."""
        dump_path = nrd_temp_dir / "nrd_2025-11-22.txt"
        dump_path.write_text("evil-phishing.com\nlegit-site.org\nbad-evil.net\n")

        resp = client.get("/api/v2/nrd/search", params={"q": "evil"})
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert body["query"] == "evil"
        domains = [r["domain"] for r in body["results"]]
        assert "evil-phishing.com" in domains
        assert "bad-evil.net" in domains

    def test_search_nrd_dumps_limit(self, client, nrd_temp_dir):
        """Search respects the limit parameter."""
        dump_path = nrd_temp_dir / "nrd_2025-11-23.txt"
        lines = [f"domain{i}.com\n" for i in range(10)]
        dump_path.write_text("".join(lines))

        resp = client.get("/api/v2/nrd/search", params={"q": "domain", "limit": 3})
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert len(body["results"]) == 3

    def test_search_nrd_dumps_no_match(self, client, nrd_temp_dir):
        """Search returns empty when no domains match."""
        dump_path = nrd_temp_dir / "nrd_2025-11-24.txt"
        dump_path.write_text("alpha.com\nbeta.org\n")

        resp = client.get("/api/v2/nrd/search", params={"q": "zzznonexistent"})
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert body["results"] == []

    def test_get_nrd_stats(self, client, nrd_temp_dir):
        """Stats return correct structure."""
        dump1 = nrd_temp_dir / "nrd_2025-11-20.txt"
        dump1.write_text("a.com\nb.net\n")
        dump2 = nrd_temp_dir / "nrd_2025-11-21.txt"
        dump2.write_text("c.org\nd.io\ne.co\n")

        resp = client.get("/api/v2/nrd/stats")
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert "total_domains" in body
        assert "total_dumps" in body
        assert "latest_dump" in body
        assert body["total_dumps"] == 2
        assert body["total_domains"] == 5
        assert body["latest_dump"] == "nrd_2025-11-21.txt"

    def test_get_nrd_stats_empty(self, client, nrd_temp_dir):
        """Stats return zeroed structure when no dumps exist."""
        # nrd_temp_dir is empty (no files created)
        resp = client.get("/api/v2/nrd/stats")
        assert resp.status_code == 200
        body = _unwrap_envelope(resp.json())
        assert body["total_domains"] == 0
        assert body["total_dumps"] == 0
        assert body["latest_dump"] is None

    def test_search_missing_query(self, client):
        """Search returns 422 when query parameter is missing."""
        resp = client.get("/api/v2/nrd/search")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Monitoring domain management tests
# ---------------------------------------------------------------------------

class TestMonitoringDomainManagement:
    """Tests for POST/DELETE domain management on monitoring groups."""

    def _create_group(self, client, name="Test Group"):
        """Helper: create a monitoring group via DB and return its ID.

        Uses the overridden dependency session so it talks to the in-memory
        test database instead of the production file.
        """
        # Grab a session via the same dependency override the client uses
        gen = app.dependency_overrides[get_db]()
        session = next(gen)
        try:
            group = GroupModel(name=name)
            session.add(group)
            session.commit()
            session.refresh(group)
            group_id = group.id
        finally:
            session.close()
        return group_id

    def test_add_domain_to_group(self, client):
        """Add a domain to a monitoring group."""
        group_id = self._create_group(client)

        resp = client.post(
            f"/api/v2/monitoring/groups/{group_id}/domains",
            json={"domain": "example.com", "frequency_seconds": 3600},
        )
        assert resp.status_code == 201
        data = _unwrap_envelope(resp.json())
        assert data["url"] == "example.com"
        assert data["group_id"] == group_id
        assert data["frequency_seconds"] == 3600
        assert data["active"] is True
        assert data["created"] is True
        assert "id" in data

    def test_add_domain_idempotent(self, client):
        """Adding the same domain twice returns created=False on second call."""
        group_id = self._create_group(client)

        resp1 = client.post(
            f"/api/v2/monitoring/groups/{group_id}/domains",
            json={"domain": "duplicate.com", "frequency_seconds": 1800},
        )
        assert resp1.status_code == 201
        assert _unwrap_envelope(resp1.json())["created"] is True

        resp2 = client.post(
            f"/api/v2/monitoring/groups/{group_id}/domains",
            json={"domain": "duplicate.com", "frequency_seconds": 1800},
        )
        assert resp2.status_code == 201
        data2 = _unwrap_envelope(resp2.json())
        assert data2["created"] is False
        assert data2["id"] == _unwrap_envelope(resp1.json())["id"]

    def test_add_domain_group_not_found(self, client):
        """Returns 404 when adding a domain to a nonexistent group."""
        resp = client.post(
            "/api/v2/monitoring/groups/nonexistent-group/domains",
            json={"domain": "example.com", "frequency_seconds": 3600},
        )
        assert resp.status_code == 404

    def test_remove_domain_from_group(self, client):
        """Remove a domain from a monitoring group."""
        group_id = self._create_group(client)

        # Add a domain first
        add_resp = client.post(
            f"/api/v2/monitoring/groups/{group_id}/domains",
            json={"domain": "remove-me.com", "frequency_seconds": 3600},
        )
        domain_id = _unwrap_envelope(add_resp.json())["id"]

        # Remove it
        del_resp = client.delete(
            f"/api/v2/monitoring/groups/{group_id}/domains/{domain_id}"
        )
        assert del_resp.status_code == 200
        data = _unwrap_envelope(del_resp.json())
        assert data["deleted"] is True
        assert data["domain_id"] == domain_id
        assert data["group_id"] == group_id

        # Verify it's gone via the list endpoint
        list_resp = client.get(f"/api/v2/monitoring/groups/{group_id}/domains")
        assert list_resp.status_code == 200
        list_body = _unwrap_envelope(list_resp.json())
        domain_ids = [d["id"] for d in list_body]
        assert domain_id not in domain_ids

    def test_remove_domain_not_found(self, client):
        """Returns 404 when removing a nonexistent domain."""
        group_id = self._create_group(client)

        resp = client.delete(
            f"/api/v2/monitoring/groups/{group_id}/domains/nonexistent-domain"
        )
        assert resp.status_code == 404

    def test_remove_domain_wrong_group(self, client):
        """Returns 404 when removing a domain from the wrong group."""
        group_a = self._create_group(client, name="Group A")
        group_b = self._create_group(client, name="Group B")

        # Add domain to group A
        add_resp = client.post(
            f"/api/v2/monitoring/groups/{group_a}/domains",
            json={"domain": "only-in-a.com", "frequency_seconds": 3600},
        )
        domain_id = _unwrap_envelope(add_resp.json())["id"]

        # Try to remove it from group B
        del_resp = client.delete(
            f"/api/v2/monitoring/groups/{group_b}/domains/{domain_id}"
        )
        assert del_resp.status_code == 404

    def test_add_domain_default_frequency(self, client):
        """Adding a domain without frequency_seconds uses default of 3600."""
        group_id = self._create_group(client)

        resp = client.post(
            f"/api/v2/monitoring/groups/{group_id}/domains",
            json={"domain": "default-freq.com"},
        )
        assert resp.status_code == 201
        data = _unwrap_envelope(resp.json())
        assert data["frequency_seconds"] == 3600

    def test_nrd_routes_exist(self, client):
        """Verify NRD routes are registered in the app."""
        routes = {route.path for route in app.routes}
        assert "/api/v2/nrd/latest" in routes
        assert "/api/v2/nrd/search" in routes
        assert "/api/v2/nrd/stats" in routes

    def test_monitoring_domain_routes_exist(self, client):
        """Verify monitoring domain management routes are registered."""
        routes = {route.path for route in app.routes}
        assert "/api/v2/monitoring/groups/{group_id}/domains" in routes