"""Test that all v2 schema tables exist with correct columns."""
import pytest
from sqlalchemy import create_engine, inspect
from database import Base, init_db


@pytest.fixture
def engine():
    """Create an in-memory SQLite engine for schema testing."""
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=eng)
    yield eng


def test_domains_table_has_v2_columns(engine):
    columns = {c["name"] for c in inspect(engine).get_columns("domains")}
    assert "id" in columns
    assert "domain" not in columns  # v2 adds 'domain' later; v1 has 'url' on monitoring_configs
    # v1 columns must still exist
    assert "url" in columns
    assert "dump_mode" in columns


def test_snapshots_table_has_v2_columns(engine):
    columns = {c["name"] for c in inspect(engine).get_columns("snapshots")}
    assert "sha256" in columns
    assert "size_bytes" in columns
    assert "retention_flag" in columns


def test_risk_scores_table_exists(engine):
    assert "risk_scores" in inspect(engine).get_table_names()


def test_analysis_results_table_exists(engine):
    columns = {c["name"] for c in inspect(engine).get_columns("analysis_results")}
    assert "plugin_name" in columns
    assert "plugin_version" in columns
    assert "plugin_type" in columns
    assert "confidence" in columns


def test_webhooks_table_exists(engine):
    assert "webhooks" in inspect(engine).get_table_names()


def test_alerts_table_has_v2_columns(engine):
    columns = {c["name"] for c in inspect(engine).get_columns("alerts")}
    assert "dedup_key" in columns
    assert "severity" in columns
    assert "payload_version" in columns


def test_domain_processing_state_exists(engine):
    assert "domain_processing_state" in inspect(engine).get_table_names()


def test_plugin_weights_table_exists(engine):
    assert "plugin_weights" in inspect(engine).get_table_names()


def test_domain_ips_table_exists(engine):
    assert "domain_ips" in inspect(engine).get_table_names()


def test_snapshot_plugin_status_exists(engine):
    assert "snapshot_plugin_status" in inspect(engine).get_table_names()


def test_dns_records_table_exists(engine):
    assert "dns_records" in inspect(engine).get_table_names()


def test_analyst_feedback_table_exists(engine):
    assert "analyst_feedback" in inspect(engine).get_table_names()


def test_audit_logs_table_exists(engine):
    assert "audit_logs" in inspect(engine).get_table_names()