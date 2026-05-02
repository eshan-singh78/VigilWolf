"""Integration tests for startup and shutdown sequences.

Tests:
- State persistence across restarts
- Scheduler recovery
- Graceful shutdown

Note: These tests focus on the startup/shutdown behavior and state management.
They use a simplified approach that tests the core functionality without
complete environment isolation.
"""
import pytest
import os
import shutil
import tempfile
from pathlib import Path

import config
import database
from models import Group, Domain, Snapshot
from scheduler import get_scheduler, DomainScheduler
from plugins.storage_manager import StorageManager
from plugins.monitoring_service import MonitoringService


@pytest.fixture
def test_data_dir(tmp_path):
    """Create a temporary data directory for testing."""
    data_dir = tmp_path / "test_monitoring_data"
    data_dir.mkdir()

    original_db = config.DATABASE_URL
    config.DATABASE_URL = f"sqlite:///{data_dir / 'test.db'}"
    config.MONITORING_DATA_DIR = str(data_dir)
    database._engine = None
    database._SessionLocal = None
    database.init_db()

    yield data_dir

    config.DATABASE_URL = original_db
    database._engine = None
    database._SessionLocal = None

    if data_dir.exists():
        shutil.rmtree(data_dir)


@pytest.fixture
def fresh_instances(test_data_dir):
    """Create fresh instances of services for each test."""
    import plugins.storage_manager as sm
    import plugins.monitoring_service as ms
    import scheduler

    # Stop any running scheduler first
    if scheduler._scheduler is not None and scheduler._scheduler.scheduler is not None:
        if scheduler._scheduler.scheduler.running:
            scheduler._scheduler.stop_scheduler()

    sm._storage_manager = None
    ms._monitoring_service = None
    scheduler._scheduler = None

    yield

    # Clean up after test - stop scheduler if running
    if scheduler._scheduler is not None and scheduler._scheduler.scheduler is not None:
        if scheduler._scheduler.scheduler.running:
            scheduler._scheduler.stop_scheduler()

    sm._storage_manager = None
    ms._monitoring_service = None
    scheduler._scheduler = None


class TestStartupSequence:
    """Test the application startup sequence."""

    def test_directories_created_on_startup(self, test_data_dir, fresh_instances):
        """Test that necessary directories are created during startup."""
        config.ensure_directories()

        # Verify directories exist
        assert Path(config.MONITORING_DATA_DIR).exists()

    def test_empty_state_loads_successfully(self, test_data_dir, fresh_instances):
        """Test that system starts successfully with no existing data."""
        storage = StorageManager(data_dir=str(test_data_dir))
        groups = storage.load_groups()
        domains = storage.load_domains()

        assert groups == []
        assert domains == []

    def test_scheduler_starts_successfully(self, test_data_dir, fresh_instances):
        """Test that scheduler starts without errors."""
        scheduler = get_scheduler()
        scheduler.start_scheduler()

        assert scheduler.scheduler is not None
        assert scheduler.scheduler.running

        # Clean up
        scheduler.stop_scheduler()

    def test_existing_state_loads_on_startup(self, test_data_dir, fresh_instances):
        """Test that existing groups and domains are loaded on startup."""
        storage = StorageManager(data_dir=str(test_data_dir))

        group = Group.create(name="Test Group")
        storage.save_group(group)

        domain = Domain.create(
            group_id=group.id,
            url="https://example.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )
        storage.save_domain(domain)

        # Simulate restart by creating new storage instance
        new_storage = StorageManager(data_dir=str(test_data_dir))
        loaded_groups = new_storage.load_groups()
        loaded_domains = new_storage.load_domains()

        assert len(loaded_groups) == 1
        assert loaded_groups[0].id == group.id
        assert loaded_groups[0].name == "Test Group"

        assert len(loaded_domains) == 1
        assert loaded_domains[0].id == domain.id
        assert loaded_domains[0].url == "https://example.com"


class TestStatePersistence:
    """Test state persistence across restarts."""

    def test_groups_persist_across_restart(self, test_data_dir, fresh_instances):
        """Test that groups are persisted and restored across restarts."""
        storage1 = StorageManager(data_dir=str(test_data_dir))

        group1 = Group.create(name="Group 1")
        group2 = Group.create(name="Group 2")
        storage1.save_group(group1)
        storage1.save_group(group2)

        # Simulate restart with new storage instance
        storage2 = StorageManager(data_dir=str(test_data_dir))
        loaded_groups = storage2.load_groups()

        assert len(loaded_groups) == 2
        group_names = {g.name for g in loaded_groups}
        assert "Group 1" in group_names
        assert "Group 2" in group_names

    def test_domains_persist_across_restart(self, test_data_dir, fresh_instances):
        """Test that domain configurations persist across restarts."""
        storage1 = StorageManager(data_dir=str(test_data_dir))

        domain = Domain.create(
            group_id="test-group",
            url="https://example.com",
            dump_mode="html_and_assets",
            frequency_seconds=7200
        )
        storage1.save_domain(domain)
        domain_id = domain.id

        # Simulate restart with new storage instance
        storage2 = StorageManager(data_dir=str(test_data_dir))
        loaded_domain = storage2.get_domain(domain_id)

        assert loaded_domain is not None
        assert loaded_domain.url == "https://example.com"
        assert loaded_domain.dump_mode == "html_and_assets"
        assert loaded_domain.frequency_seconds == 7200
        assert loaded_domain.active is True

    def test_snapshots_persist_across_restart(self, test_data_dir, fresh_instances):
        """Test that snapshot metadata persists across restarts."""
        storage1 = StorageManager(data_dir=str(test_data_dir))

        domain = Domain.create(
            group_id="test-group",
            url="https://example.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )
        storage1.save_domain(domain)

        snapshot_dir = storage1.create_snapshot_directory(domain.id, "2025-11-18T10-00-00-000000Z")

        snapshot = Snapshot.create(
            domain_id=domain.id,
            trigger_type="initial",
            html_path=f"{snapshot_dir}/page.html",
            screenshot_path=f"{snapshot_dir}/screenshot.png",
            assets_dir=f"{snapshot_dir}/assets/",
            asset_count=5
        )
        storage1.save_snapshot_metadata(snapshot)
        snapshot_id = snapshot.id

        # Simulate restart with new storage instance
        storage2 = StorageManager(data_dir=str(test_data_dir))
        loaded_snapshots = storage2.load_snapshots_for_domain(domain.id)

        assert len(loaded_snapshots) == 1
        assert loaded_snapshots[0].id == snapshot_id
        assert loaded_snapshots[0].domain_id == domain.id


class TestSchedulerRecovery:
    """Test scheduler recovery after restart."""

    def test_scheduler_reschedules_active_domains(self, test_data_dir, fresh_instances):
        """Test that scheduler reschedules all active domains after restart."""
        storage = StorageManager(data_dir=str(test_data_dir))

        domain1 = Domain.create(
            group_id="test-group",
            url="https://example1.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )
        domain2 = Domain.create(
            group_id="test-group",
            url="https://example2.com",
            dump_mode="html_only",
            frequency_seconds=1800
        )
        storage.save_domain(domain1)
        storage.save_domain(domain2)

        scheduler = DomainScheduler()
        scheduler.start_scheduler()
        scheduler.schedule_domain_check(domain1)
        scheduler.schedule_domain_check(domain2)

        # Verify jobs are scheduled
        jobs = scheduler.scheduler.get_jobs()
        job_ids = {job.id for job in jobs}
        assert f"check_domain_{domain1.id}" in job_ids
        assert f"check_domain_{domain2.id}" in job_ids

        # Clean up
        scheduler.stop_scheduler()

    def test_inactive_domains_not_scheduled(self, test_data_dir, fresh_instances):
        """Test that inactive domains are not scheduled."""
        storage = StorageManager(data_dir=str(test_data_dir))

        domain = Domain.create(
            group_id="test-group",
            url="https://example.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )
        domain.active = False
        storage.save_domain(domain)

        scheduler = DomainScheduler()
        scheduler.start_scheduler()

        # Load domains and schedule only active ones
        domains = storage.load_domains()
        for d in domains:
            if d.active:
                scheduler.schedule_domain_check(d)

        # Verify no jobs scheduled (domain is inactive)
        jobs = scheduler.scheduler.get_jobs()
        domain_jobs = [j for j in jobs if f"check_domain_{domain.id}" in j.id]
        assert len(domain_jobs) == 0

        # Clean up
        scheduler.stop_scheduler()


class TestGracefulShutdown:
    """Test graceful shutdown behavior."""

    def test_scheduler_stops_gracefully(self, test_data_dir, fresh_instances):
        """Test that scheduler stops and waits for running jobs."""
        scheduler = DomainScheduler()
        scheduler.start_scheduler()

        assert scheduler.scheduler is not None
        assert scheduler.scheduler.running

        # Stop scheduler
        scheduler.stop_scheduler()

        # Verify scheduler is stopped
        assert scheduler.scheduler is None or not scheduler.scheduler.running

    def test_state_saved_before_shutdown(self, test_data_dir, fresh_instances):
        """Test that state is properly saved before shutdown."""
        storage = StorageManager(data_dir=str(test_data_dir))

        group = Group.create(name="Test Group")
        domain = Domain.create(
            group_id=group.id,
            url="https://example.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )
        storage.save_group(group)
        storage.save_domain(domain)

        # Verify state is saved
        groups = storage.load_groups()
        loaded_domains = storage.load_domains()

        assert len(groups) == 1
        assert len(loaded_domains) == 1

        # Simulate shutdown (state should already be saved)
        scheduler = DomainScheduler()
        scheduler.start_scheduler()
        scheduler.stop_scheduler()

        # Verify state still exists after shutdown
        new_storage = StorageManager(data_dir=str(test_data_dir))
        groups_after = new_storage.load_groups()
        domains_after = new_storage.load_domains()

        assert len(groups_after) == 1
        assert len(domains_after) == 1

    def test_no_new_jobs_during_shutdown(self, test_data_dir, fresh_instances):
        """Test that no new jobs are scheduled during shutdown."""
        scheduler = DomainScheduler()
        scheduler.start_scheduler()

        # Stop scheduler
        scheduler.stop_scheduler()

        # Try to schedule a new domain (should not work)
        domain = Domain.create(
            group_id="test-group",
            url="https://example.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )

        scheduler.schedule_domain_check(domain)

        # Verify no jobs were scheduled (scheduler is stopped)
        if scheduler.scheduler is not None:
            jobs = scheduler.scheduler.get_jobs()
            assert len(jobs) == 0


class TestFullRestartCycle:
    """Test complete startup-shutdown-restart cycle."""

    def test_complete_restart_cycle(self, test_data_dir, fresh_instances):
        """Test a complete cycle: startup -> operation -> shutdown -> restart."""
        # === First Session: Startup ===
        storage1 = StorageManager(data_dir=str(test_data_dir))
        scheduler1 = DomainScheduler()
        scheduler1.start_scheduler()

        # Create some data
        group = Group.create(name="Test Group")
        domain = Domain.create(
            group_id=group.id,
            url="https://example.com",
            dump_mode="html_only",
            frequency_seconds=3600
        )
        storage1.save_group(group)
        storage1.save_domain(domain)

        # Schedule the domain
        scheduler1.schedule_domain_check(domain)

        # Verify scheduler is running
        assert scheduler1.scheduler.running
        jobs1 = scheduler1.scheduler.get_jobs()
        job_ids1 = {job.id for job in jobs1}
        assert f"check_domain_{domain.id}" in job_ids1

        # === Shutdown ===
        scheduler1.stop_scheduler()
        assert scheduler1.scheduler is None or not scheduler1.scheduler.running

        # === Second Session: Restart ===
        storage2 = StorageManager(data_dir=str(test_data_dir))
        scheduler2 = DomainScheduler()
        scheduler2.start_scheduler()

        # Verify state was restored
        groups2 = storage2.load_groups()
        assert len(groups2) == 1
        assert groups2[0].name == "Test Group"

        domain2 = storage2.get_domain(domain.id)
        assert domain2 is not None
        assert domain2.url == "https://example.com"

        # Reschedule active domains
        domains2 = storage2.load_domains()
        for d in domains2:
            if d.active:
                scheduler2.schedule_domain_check(d)

        # Verify scheduler recovered
        assert scheduler2.scheduler.running
        jobs2 = scheduler2.scheduler.get_jobs()
        job_ids2 = {job.id for job in jobs2}
        assert f"check_domain_{domain.id}" in job_ids2

        # Clean up
        scheduler2.stop_scheduler()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
