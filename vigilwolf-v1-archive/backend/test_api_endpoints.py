"""Integration tests for monitoring API endpoints.

Tests the FastAPI endpoints for:
- Group creation
- Group listing
- Group details
- Domain listing
- Force dump
- Snapshot retrieval
"""
import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import shutil
import tempfile
import os
from unittest.mock import Mock, patch

# Import the FastAPI app
from main import app
from plugins.monitoring_service import get_monitoring_service
from plugins.storage_manager import get_storage_manager
from plugins.capture_engine import get_capture_engine
from scheduler import get_scheduler
import config
import database


@pytest.fixture(scope="function", autouse=True)
def test_data_dir():
    """Create a temporary data directory and in-memory database for tests."""
    temp_dir = tempfile.mkdtemp()
    original_dir = os.environ.get('MONITORING_DATA_DIR')
    original_db = os.environ.get('DATABASE_URL')
    os.environ['MONITORING_DATA_DIR'] = temp_dir
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    os.environ['API_KEY'] = 'test-api-key'

    # Mutate config in place so dependent modules see the new DATABASE_URL
    # without needing to be reloaded
    original_config_db_url = config.DATABASE_URL
    original_config_api_key = config.API_KEY
    original_config_data_dir = config.MONITORING_DATA_DIR
    config.DATABASE_URL = 'sqlite:///:memory:'
    config.API_KEY = 'test-api-key'
    config.MONITORING_DATA_DIR = temp_dir

    # Reset global instances
    import plugins.storage_manager as sm
    import plugins.monitoring_service as ms
    import plugins.capture_engine as ce
    import scheduler
    sm._storage_manager = None
    ms._monitoring_service = None
    ce._capture_engine = None
    scheduler._scheduler = None

    # Reset database engine so it creates a new in-memory DB
    database._engine = None
    database._SessionLocal = None
    database.init_db()

    yield temp_dir

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)
    if original_dir:
        os.environ['MONITORING_DATA_DIR'] = original_dir
    else:
        os.environ.pop('MONITORING_DATA_DIR', None)
    if original_db:
        os.environ['DATABASE_URL'] = original_db
    else:
        os.environ.pop('DATABASE_URL', None)

    config.DATABASE_URL = original_config_db_url
    config.API_KEY = original_config_api_key
    config.MONITORING_DATA_DIR = original_config_data_dir
    database._engine = None
    database._SessionLocal = None

    # Reset global instances again
    sm._storage_manager = None
    ms._monitoring_service = None
    ce._capture_engine = None
    scheduler._scheduler = None


@pytest.fixture
def mock_capture_engine():
    """Mock the capture engine to avoid real HTTP requests."""
    with patch('plugins.monitoring_service.get_capture_engine') as mock:
        engine = Mock()
        engine.fetch_html.return_value = ("<html><body>Test</body></html>", True)
        engine.capture_screenshot.return_value = True
        engine.download_assets.return_value = []
        mock.return_value = engine
        yield engine


@pytest.fixture
def client(test_data_dir, mock_capture_engine):
    """Create a test client for the FastAPI app."""
    return TestClient(app)


class TestGroupCreation:
    """Test group creation endpoint."""

    def test_create_group_success(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    },
                    {
                        "url": "https://test.com",
                        "dump_mode": "html_and_assets",
                        "frequency_seconds": 7200
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        assert response.status_code == 201
        data = response.json()

        assert "id" in data
        assert data["name"] == "Test Group"
        assert data["domain_count"] == 2
        assert len(data["domains"]) == 2
        assert data["domains"][0]["url"] == "https://example.com"
        assert data["domains"][1]["url"] == "https://test.com"

    def test_create_group_requires_auth(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            }
        )
        assert response.status_code == 401

    def test_create_group_empty_name(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code == 422

    def test_create_group_no_domains(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": []
            },
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code == 422

    def test_create_group_invalid_url(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "not-a-url",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code == 400
        assert "http" in response.json()["detail"].lower()

    def test_create_group_invalid_dump_mode(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "invalid_mode",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code == 422

    def test_create_group_negative_frequency(self, client):
        response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": -100
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code == 422


class TestGroupListing:
    """Test group listing endpoints."""

    def test_list_groups_empty(self, client):
        response = client.get("/monitoring/groups", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 200
        data = response.json()
        assert "groups" in data
        assert isinstance(data["groups"], list)

    def test_list_groups_with_data(self, client):
        initial_response = client.get("/monitoring/groups", headers={"Authorization": "Bearer test-api-key"})
        initial_count = len(initial_response.json()["groups"])

        client.post(
            "/monitoring/groups",
            json={
                "name": "Group 1",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        client.post(
            "/monitoring/groups",
            json={
                "name": "Group 2",
                "domains": [
                    {
                        "url": "https://test.com",
                        "dump_mode": "html_and_assets",
                        "frequency_seconds": 7200
                    },
                    {
                        "url": "https://demo.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 1800
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        response = client.get("/monitoring/groups", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 200
        data = response.json()
        assert len(data["groups"]) == initial_count + 2

        group_names = [g["name"] for g in data["groups"]]
        assert "Group 1" in group_names
        assert "Group 2" in group_names

        for group in data["groups"]:
            if group["name"] == "Group 1":
                assert group["domain_count"] == 1
            elif group["name"] == "Group 2":
                assert group["domain_count"] == 2

    def test_get_group_details(self, client):
        create_response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        group_id = create_response.json()["id"]

        response = client.get(f"/monitoring/groups/{group_id}", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == group_id
        assert data["name"] == "Test Group"
        assert data["domain_count"] == 1
        assert len(data["domain_ids"]) == 1

    def test_get_group_not_found(self, client):
        response = client.get("/monitoring/groups/non-existent-id", headers={"Authorization": "Bearer test-api-key"})
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestDomainListing:
    """Test domain listing endpoint."""

    def test_get_group_domains(self, client):
        create_response = client.post(
            "/monitoring/groups",
            json={
                "name": "Multi-Domain Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    },
                    {
                        "url": "https://test.com",
                        "dump_mode": "html_and_assets",
                        "frequency_seconds": 7200
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        group_id = create_response.json()["id"]

        response = client.get(f"/monitoring/groups/{group_id}/domains", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 200
        data = response.json()
        assert data["group_id"] == group_id
        assert data["group_name"] == "Multi-Domain Group"
        assert len(data["domains"]) == 2

        urls = [d["url"] for d in data["domains"]]
        assert "https://example.com" in urls
        assert "https://test.com" in urls

        for domain in data["domains"]:
            assert "id" in domain
            assert "dump_mode" in domain
            assert "frequency_seconds" in domain
            assert "created_at" in domain
            assert "active" in domain

    def test_get_domains_group_not_found(self, client):
        response = client.get("/monitoring/groups/non-existent-id/domains", headers={"Authorization": "Bearer test-api-key"})
        assert response.status_code == 404


class TestForceDump:
    """Test force dump endpoint."""

    def test_force_dump_success(self, client):
        create_response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        domain_id = create_response.json()["domains"][0]["id"]

        response = client.post(f"/monitoring/domains/{domain_id}/force-dump", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 201
        data = response.json()
        assert "snapshot_id" in data
        assert data["domain_id"] == domain_id
        assert data["trigger_type"] == "manual"
        assert "timestamp" in data

    def test_force_dump_domain_not_found(self, client):
        response = client.post("/monitoring/domains/non-existent-id/force-dump", headers={"Authorization": "Bearer test-api-key"})
        assert response.status_code == 400
        assert "not found" in response.json()["detail"].lower()


class TestSnapshotRetrieval:
    """Test snapshot retrieval endpoints."""

    def test_get_domain_snapshots(self, client):
        create_response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        domain_id = create_response.json()["domains"][0]["id"]

        response = client.get(f"/monitoring/domains/{domain_id}/snapshots", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 200
        data = response.json()
        assert data["domain_id"] == domain_id
        assert data["domain_url"] == "https://example.com"
        assert len(data["snapshots"]) >= 1

        snapshot = data["snapshots"][0]
        assert "id" in snapshot
        assert "timestamp" in snapshot
        assert "trigger_type" in snapshot
        assert snapshot["trigger_type"] == "initial"

    def test_get_domain_snapshots_not_found(self, client):
        response = client.get("/monitoring/domains/non-existent-id/snapshots", headers={"Authorization": "Bearer test-api-key"})
        assert response.status_code == 404

    def test_get_snapshot_details(self, client):
        create_response = client.post(
            "/monitoring/groups",
            json={
                "name": "Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_only",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        domain_id = create_response.json()["domains"][0]["id"]

        snapshots_response = client.get(f"/monitoring/domains/{domain_id}/snapshots", headers={"Authorization": "Bearer test-api-key"})
        snapshot_id = snapshots_response.json()["snapshots"][0]["id"]

        response = client.get(f"/monitoring/snapshots/{snapshot_id}", headers={"Authorization": "Bearer test-api-key"})

        assert response.status_code == 200
        data = response.json()

        assert data["snapshot"]["id"] == snapshot_id
        assert "timestamp" in data["snapshot"]
        assert "trigger_type" in data["snapshot"]

        assert data["domain"]["id"] == domain_id
        assert data["domain"]["url"] == "https://example.com"
        assert data["domain"]["dump_mode"] == "html_only"

        assert "ping_logs" in data
        assert "dump_logs" in data
        assert isinstance(data["ping_logs"], list)
        assert isinstance(data["dump_logs"], list)

    def test_get_snapshot_details_not_found(self, client):
        response = client.get("/monitoring/snapshots/non-existent-id", headers={"Authorization": "Bearer test-api-key"})
        assert response.status_code == 404


class TestPublicEndpointAuth:
    """Test that previously public endpoints now require auth."""

    def test_whois_requires_auth(self, client):
        response = client.get("/whois?domain=example.com")
        assert response.status_code == 401

    def test_whois_with_auth(self, client):
        response = client.get(
            "/whois?domain=example.com",
            headers={"Authorization": "Bearer test-api-key"}
        )
        # May fail for other reasons (whois not available), but should not 401
        assert response.status_code != 401

    def test_nrd_latest_requires_auth(self, client):
        response = client.get("/nrd-latest")
        assert response.status_code == 401

    def test_nrd_latest_with_auth(self, client):
        response = client.get(
            "/nrd-latest",
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code != 401

    def test_dump_nrd_requires_auth(self, client):
        response = client.get("/dump-nrd")
        assert response.status_code == 401


class TestEndToEndFlow:
    """Test complete end-to-end workflows."""

    def test_complete_monitoring_workflow(self, client):
        create_response = client.post(
            "/monitoring/groups",
            json={
                "name": "E2E Test Group",
                "domains": [
                    {
                        "url": "https://example.com",
                        "dump_mode": "html_and_assets",
                        "frequency_seconds": 3600
                    }
                ]
            },
            headers={"Authorization": "Bearer test-api-key"}
        )

        assert create_response.status_code == 201
        group_id = create_response.json()["id"]
        domain_id = create_response.json()["domains"][0]["id"]

        list_response = client.get("/monitoring/groups", headers={"Authorization": "Bearer test-api-key"})
        assert list_response.status_code == 200
        group_ids = [g["id"] for g in list_response.json()["groups"]]
        assert group_id in group_ids

        group_response = client.get(f"/monitoring/groups/{group_id}", headers={"Authorization": "Bearer test-api-key"})
        assert group_response.status_code == 200
        assert group_response.json()["name"] == "E2E Test Group"

        domains_response = client.get(f"/monitoring/groups/{group_id}/domains", headers={"Authorization": "Bearer test-api-key"})
        assert domains_response.status_code == 200
        assert len(domains_response.json()["domains"]) == 1

        force_dump_response = client.post(f"/monitoring/domains/{domain_id}/force-dump", headers={"Authorization": "Bearer test-api-key"})
        assert force_dump_response.status_code == 201

        snapshots_response = client.get(f"/monitoring/domains/{domain_id}/snapshots", headers={"Authorization": "Bearer test-api-key"})
        assert snapshots_response.status_code == 200
        snapshots = snapshots_response.json()["snapshots"]
        assert len(snapshots) >= 2

        snapshot_id = snapshots[0]["id"]
        details_response = client.get(f"/monitoring/snapshots/{snapshot_id}", headers={"Authorization": "Bearer test-api-key"})
        assert details_response.status_code == 200
        assert details_response.json()["snapshot"]["id"] == snapshot_id
