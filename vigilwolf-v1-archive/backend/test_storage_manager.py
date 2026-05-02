"""Tests for the SQLite-based storage manager."""
import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

import config
import database
from plugins.storage_manager import StorageManager
from models import Snapshot, Group, Domain, PingLogEntry, DumpLogEntry


@pytest.fixture
def fresh_storage():
    """Create a fresh StorageManager with in-memory database."""
    temp_dir = tempfile.mkdtemp()
    original_db = config.DATABASE_URL
    config.DATABASE_URL = 'sqlite:///:memory:'
    # Reset global engine so in-memory DB is truly fresh
    database._engine = None
    database._SessionLocal = None
    database.init_db()

    storage = StorageManager(data_dir=temp_dir)

    yield storage

    config.DATABASE_URL = original_db
    database._engine = None
    database._SessionLocal = None
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_html_storage_preserves_content(fresh_storage):
    storage = fresh_storage
    domain_id = "test-domain-123"
    timestamp = "2025-11-18T10-30-00Z"
    snapshot_dir = storage.create_snapshot_directory(domain_id, timestamp)

    html_content = "<html><body>Hello World</body></html>"
    html_path = storage.save_html(snapshot_dir, html_content)

    retrieved_content = storage.load_html(html_path)
    assert retrieved_content == html_content


def test_snapshot_round_trip_integrity(fresh_storage):
    storage = fresh_storage
    domain_id = "test-domain-456"
    timestamp = datetime.now(timezone.utc).isoformat()
    snapshot_dir = storage.create_snapshot_directory(domain_id, timestamp)

    html_path = storage.save_html(snapshot_dir, "<html>Test</html>")

    snapshot = Snapshot.create(
        domain_id=domain_id,
        trigger_type="initial",
        html_path=html_path
    )

    storage.save_snapshot_metadata(snapshot)
    retrieved = storage.get_snapshot(snapshot.id)

    assert retrieved is not None
    assert retrieved.id == snapshot.id
    assert retrieved.domain_id == snapshot.domain_id
    assert retrieved.trigger_type == snapshot.trigger_type


def test_log_append_operations(fresh_storage):
    storage = fresh_storage
    domain_id = "test-domain-789"

    entry1 = PingLogEntry.create(
        reachable=True,
        status_code=200,
        change_detected=False,
        message="No change"
    )
    entry2 = PingLogEntry.create(
        reachable=True,
        status_code=200,
        change_detected=True,
        message="Change detected"
    )

    storage.append_ping_log(domain_id, entry1)
    storage.append_ping_log(domain_id, entry2)

    entries = storage.read_ping_log(domain_id)
    assert len(entries) == 2
    assert entries[0].message == "No change"
    assert entries[1].message == "Change detected"


def test_dump_log_operations(fresh_storage):
    storage = fresh_storage
    domain_id = "test-domain-abc"

    entry1 = DumpLogEntry.create(
        trigger_type="initial",
        snapshot_id="snap-1",
        success=True,
        message="Initial dump"
    )
    entry2 = DumpLogEntry.create(
        trigger_type="automatic",
        snapshot_id="snap-2",
        success=True,
        message="Automatic dump"
    )

    storage.append_dump_log(domain_id, entry1)
    storage.append_dump_log(domain_id, entry2)

    entries = storage.read_dump_log(domain_id)
    assert len(entries) == 2
    assert entries[0].trigger_type == "initial"
    assert entries[1].trigger_type == "automatic"


def test_group_operations(fresh_storage):
    storage = fresh_storage

    group1 = Group.create("Test Group 1")
    group2 = Group.create("Test Group 2")

    storage.save_group(group1)
    storage.save_group(group2)

    # Create domains associated with groups so relationship populates domain_ids
    domain1 = Domain.create(
        group_id=group1.id,
        url="https://example1.com",
        dump_mode="html_only",
        frequency_seconds=3600
    )
    domain2 = Domain.create(
        group_id=group1.id,
        url="https://example2.com",
        dump_mode="html_and_assets",
        frequency_seconds=7200
    )
    domain3 = Domain.create(
        group_id=group2.id,
        url="https://example3.com",
        dump_mode="html_only",
        frequency_seconds=1800
    )
    storage.save_domain(domain1)
    storage.save_domain(domain2)
    storage.save_domain(domain3)

    groups = storage.load_groups()
    assert len(groups) == 2

    loaded_group1 = storage.get_group(group1.id)
    assert loaded_group1 is not None
    assert loaded_group1.name == "Test Group 1"
    assert len(loaded_group1.domain_ids) == 2


def test_domain_operations(fresh_storage):
    storage = fresh_storage

    domain1 = Domain.create(
        group_id="group-1",
        url="https://example.com",
        dump_mode="html_only",
        frequency_seconds=3600
    )
    domain2 = Domain.create(
        group_id="group-1",
        url="https://test.com",
        dump_mode="html_and_assets",
        frequency_seconds=7200
    )
    domain3 = Domain.create(
        group_id="group-2",
        url="https://other.com",
        dump_mode="html_only",
        frequency_seconds=1800
    )

    storage.save_domain(domain1)
    storage.save_domain(domain2)
    storage.save_domain(domain3)

    domains = storage.load_domains()
    assert len(domains) == 3

    loaded_domain1 = storage.get_domain(domain1.id)
    assert loaded_domain1 is not None
    assert loaded_domain1.url == "https://example.com"

    group1_domains = storage.get_domains_by_group("group-1")
    assert len(group1_domains) == 2

    group2_domains = storage.get_domains_by_group("group-2")
    assert len(group2_domains) == 1


def test_snapshot_listing(fresh_storage):
    storage = fresh_storage
    domain_id = "test-domain-xyz"

    for i in range(3):
        timestamp = f"2025-11-18T10:3{i}:00Z"
        snapshot_dir = storage.create_snapshot_directory(domain_id, timestamp)
        html_path = storage.save_html(snapshot_dir, f"<html>Content {i}</html>")

        snapshot = Snapshot.create(
            domain_id=domain_id,
            trigger_type="automatic",
            html_path=html_path
        )
        storage.save_snapshot_metadata(snapshot)

    snapshots = storage.load_snapshots_for_domain(domain_id)
    assert len(snapshots) == 3
    assert snapshots[0].timestamp <= snapshots[1].timestamp <= snapshots[2].timestamp


def test_reset_environment(fresh_storage):
    storage = fresh_storage

    group = Group.create("Test Group", ["domain-1"])
    domain = Domain.create(
        group_id=group.id,
        url="https://example.com",
        dump_mode="html_only",
        frequency_seconds=3600
    )
    storage.save_group(group)
    storage.save_domain(domain)

    stats = storage.reset_environment()

    assert stats['groups_deleted'] >= 1
    assert stats['domains_deleted'] >= 1
    assert storage.load_groups() == []
    assert storage.load_domains() == []
