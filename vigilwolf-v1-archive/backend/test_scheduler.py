"""Unit tests for the scheduler module."""
import pytest
import time
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock

import config
import database
from scheduler import DomainScheduler, get_scheduler
from models import Domain, Group
from plugins.storage_manager import StorageManager
from plugins.monitoring_service import MonitoringService


@pytest.fixture
def temp_data_dir():
    """Create a temporary data directory for testing."""
    temp_dir = tempfile.mkdtemp()
    original_db = config.DATABASE_URL
    config.DATABASE_URL = 'sqlite:///:memory:'
    database.init_db()
    yield temp_dir
    shutil.rmtree(temp_dir)
    config.DATABASE_URL = original_db


@pytest.fixture
def storage(temp_data_dir):
    """Create a storage manager with temporary directory."""
    return StorageManager(data_dir=temp_data_dir)


@pytest.fixture
def scheduler(storage):
    """Create a scheduler instance for testing."""
    sched = DomainScheduler()
    sched.storage = storage
    yield sched
    if sched.scheduler is not None and sched.scheduler.running:
        sched.stop_scheduler()


def test_scheduler_initialization(scheduler):
    assert scheduler.scheduler is None
    assert scheduler.monitoring_service is not None
    assert scheduler.storage is not None
    assert scheduler.capture is not None


def test_start_scheduler(scheduler):
    scheduler.start_scheduler()
    assert scheduler.scheduler is not None
    assert scheduler.scheduler.running is True
    scheduler.stop_scheduler()


def test_start_scheduler_idempotent(scheduler):
    scheduler.start_scheduler()
    first_scheduler = scheduler.scheduler
    scheduler.start_scheduler()
    assert scheduler.scheduler is first_scheduler
    assert scheduler.scheduler.running is True
    scheduler.stop_scheduler()


def test_stop_scheduler(scheduler):
    scheduler.start_scheduler()
    assert scheduler.scheduler.running is True
    scheduler.stop_scheduler()
    assert scheduler.scheduler is None


def test_stop_scheduler_when_not_running(scheduler):
    scheduler.stop_scheduler()
    assert scheduler.scheduler is None


def test_schedule_domain_check(scheduler, storage):
    domain = Domain.create(
        group_id="test-group",
        url="https://example.com",
        dump_mode="html_only",
        frequency_seconds=60
    )
    storage.save_domain(domain)
    scheduler.start_scheduler()
    scheduler.schedule_domain_check(domain)

    job_id = f"check_domain_{domain.id}"
    job = scheduler.scheduler.get_job(job_id)

    assert job is not None
    assert job.id == job_id
    assert job.name == f"Check domain {domain.url}"
    scheduler.stop_scheduler()


def test_unschedule_domain_check(scheduler, storage):
    domain = Domain.create(
        group_id="test-group",
        url="https://example.com",
        dump_mode="html_only",
        frequency_seconds=60
    )
    storage.save_domain(domain)
    scheduler.start_scheduler()
    scheduler.schedule_domain_check(domain)

    job_id = f"check_domain_{domain.id}"
    assert scheduler.scheduler.get_job(job_id) is not None

    scheduler.unschedule_domain_check(domain.id)
    assert scheduler.scheduler.get_job(job_id) is None
    scheduler.stop_scheduler()


def test_unschedule_nonexistent_domain(scheduler):
    scheduler.start_scheduler()
    scheduler.unschedule_domain_check("nonexistent-domain-id")
    scheduler.stop_scheduler()


def test_scheduler_loads_existing_domains_on_start(scheduler, storage):
    domain1 = Domain.create(
        group_id="test-group",
        url="https://example1.com",
        dump_mode="html_only",
        frequency_seconds=60
    )
    domain2 = Domain.create(
        group_id="test-group",
        url="https://example2.com",
        dump_mode="html_only",
        frequency_seconds=120
    )
    domain2.active = False

    storage.save_domain(domain1)
    storage.save_domain(domain2)

    scheduler.start_scheduler()

    job1 = scheduler.scheduler.get_job(f"check_domain_{domain1.id}")
    job2 = scheduler.scheduler.get_job(f"check_domain_{domain2.id}")

    assert job1 is not None
    assert job2 is None
    scheduler.stop_scheduler()


def test_check_domain_inactive(scheduler, storage):
    domain = Domain.create(
        group_id="test-group",
        url="https://example.com",
        dump_mode="html_only",
        frequency_seconds=60
    )
    domain.active = False
    storage.save_domain(domain)

    scheduler.check_domain(domain.id)

    ping_logs = storage.read_ping_log(domain.id)
    assert len(ping_logs) == 0


def test_check_domain_nonexistent(scheduler):
    scheduler.check_domain("nonexistent-domain-id")


def test_get_scheduler_singleton():
    scheduler1 = get_scheduler()
    scheduler2 = get_scheduler()
    assert scheduler1 is scheduler2
    if scheduler1.scheduler is not None and scheduler1.scheduler.running:
        scheduler1.stop_scheduler()
