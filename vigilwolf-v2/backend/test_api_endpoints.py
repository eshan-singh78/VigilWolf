"""Tests for v2 API endpoints.

Verifies that each router has the expected routes and that basic endpoint
responses work with an in-memory SQLite database.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db, WebhookModel, GroupModel
from main import app


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


# ---------------------------------------------------------------------------
# Route existence tests
# ---------------------------------------------------------------------------

class TestRouteExistence:
    """Verify that all expected v2 routes are registered."""

    def test_domains_routes_exist(self, client):
        routes = {route.path for route in app.routes}
        assert "/api/v2/domains" in routes
        assert "/api/v2/domains/{domain_id}" in routes
        assert "/api/v2/domains/{domain_id}/threat" in routes
        assert "/api/v2/threats" in routes
        assert "/api/v2/threats/stats" in routes

    def test_webhooks_routes_exist(self, client):
        routes = {route.path for route in app.routes}
        assert "/api/v2/webhooks" in routes
        assert "/api/v2/webhooks/{webhook_id}" in routes
        assert "/api/v2/webhooks/{webhook_id}/test" in routes

    def test_alerts_routes_exist(self, client):
        routes = {route.path for route in app.routes}
        assert "/api/v2/alerts" in routes
        assert "/api/v2/alerts/{alert_id}" in routes
        assert "/api/v2/alerts/{alert_id}/retry" in routes

    def test_search_routes_exist(self, client):
        routes = {route.path for route in app.routes}
        assert "/api/v2/search" in routes
        assert "/api/v2/pivot/domain/{domain_id}" in routes

    def test_plugins_routes_exist(self, client):
        routes = {route.path for route in app.routes}
        assert "/api/v2/plugins" in routes
        assert "/api/v2/plugins/{plugin_name}/weight" in routes
        assert "/api/v2/plugins/{plugin_name}/enabled" in routes
        assert "/api/v2/risk-thresholds" in routes

    def test_monitoring_routes_exist(self, client):
        routes = {route.path for route in app.routes}
        assert "/api/v2/monitoring/status" in routes
        assert "/api/v2/monitoring/groups" in routes
        assert "/api/v2/monitoring/groups/{group_id}/domains" in routes


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "2.0.0"


# ---------------------------------------------------------------------------
# Domain endpoint tests
# ---------------------------------------------------------------------------

class TestDomainsEndpoints:
    def test_list_domains_empty(self, client):
        resp = client.get("/api/v2/domains")
        assert resp.status_code == 200
        body = resp.json()
        data = body["data"]
        meta = body["meta"]
        assert data == []
        assert meta["total"] == 0
        assert meta["next_cursor"] is None

    def test_get_domain_not_found(self, client):
        resp = client.get("/api/v2/domains/nonexistent-id")
        assert resp.status_code == 404

    def test_threat_stats_empty(self, client):
        resp = client.get("/api/v2/threats/stats")
        assert resp.status_code == 200
        body = resp.json()
        data = body["data"]
        meta = body["meta"]
        assert meta["total"] == 0
        assert data["high"] == 0
        assert data["medium"] == 0
        assert data["low"] == 0


# ---------------------------------------------------------------------------
# Webhook endpoint tests
# ---------------------------------------------------------------------------

class TestWebhookEndpoints:
    def test_create_webhook(self, client):
        payload = {
            "name": "Test Hook",
            "url": "https://example.com/webhook",
            "secret": "mysecret",
            "events": ["phishing_detected"],
            "enabled": True,
            "filters": {},
        }
        resp = client.post("/api/v2/webhooks", json=payload)
        assert resp.status_code == 201
        data = resp.json()["data"]
        assert data["name"] == "Test Hook"
        assert data["url"] == "https://example.com/webhook"
        assert data["enabled"] is True
        assert "id" in data

    def test_list_webhooks(self, client):
        # Create one first
        client.post("/api/v2/webhooks", json={
            "name": "List Test Hook",
            "url": "https://example.com/list-hook",
            "events": ["phishing_detected"],
        })
        resp = client.get("/api/v2/webhooks")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_webhook(self, client):
        # Create one first
        create_resp = client.post("/api/v2/webhooks", json={
            "name": "Get Test Hook",
            "url": "https://example.com/get-hook",
            "events": ["phishing_detected"],
        })
        webhook_id = create_resp.json()["data"]["id"]

        resp = client.get(f"/api/v2/webhooks/{webhook_id}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["id"] == webhook_id
        assert data["name"] == "Get Test Hook"

    def test_update_webhook(self, client):
        # Create one first
        create_resp = client.post("/api/v2/webhooks", json={
            "name": "Update Test Hook",
            "url": "https://example.com/update-hook",
            "events": ["phishing_detected"],
        })
        webhook_id = create_resp.json()["data"]["id"]

        resp = client.put(f"/api/v2/webhooks/{webhook_id}", json={
            "name": "Updated Hook",
            "enabled": False,
        })
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["name"] == "Updated Hook"
        assert data["enabled"] is False

    def test_delete_webhook(self, client):
        # Create one first
        create_resp = client.post("/api/v2/webhooks", json={
            "name": "Delete Test Hook",
            "url": "https://example.com/delete-hook",
            "events": ["phishing_detected"],
        })
        webhook_id = create_resp.json()["data"]["id"]

        resp = client.delete(f"/api/v2/webhooks/{webhook_id}")
        assert resp.status_code == 200
        assert resp.json()["data"]["deleted"] is True

        # Verify it's gone
        get_resp = client.get(f"/api/v2/webhooks/{webhook_id}")
        assert get_resp.status_code == 404

    def test_get_webhook_not_found(self, client):
        resp = client.get("/api/v2/webhooks/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Alert endpoint tests
# ---------------------------------------------------------------------------

class TestAlertEndpoints:
    def test_list_alerts_empty(self, client):
        resp = client.get("/api/v2/alerts")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == []
        assert body["meta"]["total"] == 0
        assert body["meta"]["next_cursor"] is None

    def test_get_alert_not_found(self, client):
        resp = client.get("/api/v2/alerts/999999")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Plugin endpoint tests
# ---------------------------------------------------------------------------

class TestPluginEndpoints:
    def test_list_plugins(self, client):
        # Need to register at least one plugin for this to return data.
        # The PLUGIN_REGISTRY may be empty if no plugins were loaded.
        # Import and register a test plugin.
        from plugins.base import AnalysisPlugin, PluginType, PluginResult, SnapshotContext

        class _TestPlugin(AnalysisPlugin):
            name = "test_api_plugin"
            version = "1.0.0"
            plugin_type = PluginType.DETECTION

            def run(self, ctx):
                return PluginResult(
                    plugin_name=self.name,
                    plugin_version=self.version,
                    plugin_type=self.plugin_type,
                    score_contribution=0,
                    confidence=1.0,
                    tags=[],
                    findings={},
                )

        from plugins.registry import PLUGIN_REGISTRY
        if "test_api_plugin" not in PLUGIN_REGISTRY:
            PLUGIN_REGISTRY["test_api_plugin"] = _TestPlugin

        resp = client.get("/api/v2/plugins")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "plugins" in data
        assert isinstance(data["plugins"], list)

        # Verify the test plugin appears
        names = [p["name"] for p in data["plugins"]]
        assert "test_api_plugin" in names
        plugin = [p for p in data["plugins"] if p["name"] == "test_api_plugin"][0]
        assert plugin["version"] == "1.0.0"
        assert plugin["plugin_type"] == "detection"

        # Clean up
        if "test_api_plugin" in PLUGIN_REGISTRY:
            del PLUGIN_REGISTRY["test_api_plugin"]

    def test_update_plugin_weight_not_found(self, client):
        resp = client.put("/api/v2/plugins/nonexistent_plugin/weight", json={"weight": 0.5})
        assert resp.status_code == 404

    def test_update_plugin_enabled_not_found(self, client):
        resp = client.put("/api/v2/plugins/nonexistent_plugin/enabled", json={"enabled": False})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Risk thresholds endpoint tests
# ---------------------------------------------------------------------------

class TestRiskThresholdsEndpoint:
    def test_get_risk_thresholds(self, client):
        resp = client.get("/api/v2/risk-thresholds")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "risk_threshold_high" in data
        assert "risk_threshold_medium" in data
        assert isinstance(data["risk_threshold_high"], int)
        assert isinstance(data["risk_threshold_medium"], int)


# ---------------------------------------------------------------------------
# Monitoring endpoint tests
# ---------------------------------------------------------------------------

class TestMonitoringEndpoints:
    def test_system_status(self, client):
        resp = client.get("/api/v2/monitoring/status")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "ok"
        assert data["version"] == "2.0.0"
        assert isinstance(data["total_domains"], int)
        assert isinstance(data["total_groups"], int)

    def test_list_groups_empty(self, client):
        resp = client.get("/api/v2/monitoring/groups")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert isinstance(data, list)

    def test_group_domains_not_found(self, client):
        resp = client.get("/api/v2/monitoring/groups/nonexistent-id/domains")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Search endpoint tests
# ---------------------------------------------------------------------------

class TestSearchEndpoints:
    def test_search_with_query(self, client):
        resp = client.get("/api/v2/search", params={"q": "example"})
        assert resp.status_code == 200
        body = resp.json()
        data = body["data"]
        assert "results" in data
        assert isinstance(data["results"], list)
        # "total" is promoted to meta
        assert "total" in body["meta"]

    def test_pivot_domain_not_found(self, client):
        resp = client.get("/api/v2/pivot/domain/nonexistent-id")
        assert resp.status_code == 404