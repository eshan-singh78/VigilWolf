"""Property-based tests for the monitoring service.

Tests correctness properties for group and domain management.
"""
import pytest
import tempfile
import shutil
from pathlib import Path
from hypothesis import given, strategies as st, settings
from unittest.mock import Mock

import config
import database
from plugins.monitoring_service import MonitoringService
from plugins.storage_manager import StorageManager
from plugins.capture_engine import CaptureEngine
from models import Group, Domain


# Custom strategies for generating test data

@st.composite
def valid_url(draw):
    """Generate a valid HTTP/HTTPS URL."""
    protocol = draw(st.sampled_from(['http://', 'https://']))
    domain = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), min_codepoint=97, max_codepoint=122),
        min_size=1,
        max_size=20
    ))
    tld = draw(st.sampled_from(['.com', '.org', '.net', '.io']))
    return f"{protocol}{domain}{tld}"


@st.composite
def domain_config(draw):
    """Generate a valid domain configuration."""
    return {
        'url': draw(valid_url()),
        'dump_mode': draw(st.sampled_from(['html_only', 'html_and_assets'])),
        'frequency_seconds': draw(st.integers(min_value=1, max_value=86400))
    }


@st.composite
def group_name(draw):
    """Generate a valid group name."""
    return draw(st.text(min_size=1, max_size=100).filter(lambda x: x.strip()))


def create_test_service():
    """Create a monitoring service with temporary storage."""
    temp_dir = tempfile.mkdtemp()
    storage = StorageManager(data_dir=temp_dir)
    service = MonitoringService()
    service.storage = storage
    service._temp_dir = temp_dir

    mock_capture = Mock()
    mock_capture.fetch_html.return_value = ("<html><body>Test</body></html>", True)
    mock_capture.capture_screenshot.return_value = False

    def mock_download_assets(html, base_url, output_dir):
        assets_to_create = mock_capture.download_assets.return_value
        if not assets_to_create:
            return []
        assets_dir = Path(output_dir) / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        for asset_name in assets_to_create:
            asset_path = assets_dir / asset_name
            asset_path.write_text(f"Mock content for {asset_name}")
        return assets_to_create

    mock_capture.download_assets = Mock(side_effect=mock_download_assets, return_value=[])
    service.capture = mock_capture

    return service


def cleanup_test_service(service):
    """Clean up temporary storage for a test service."""
    if hasattr(service, '_temp_dir'):
        shutil.rmtree(service._temp_dir, ignore_errors=True)


@pytest.fixture(scope="function", autouse=True)
def fresh_db():
    """Set up a fresh in-memory database for each test."""
    original_db = config.DATABASE_URL
    config.DATABASE_URL = 'sqlite:///:memory:'
    database._engine = None
    database._SessionLocal = None
    database.init_db()
    yield
    config.DATABASE_URL = original_db
    database._engine = None
    database._SessionLocal = None


@settings(max_examples=10)
@given(
    name=group_name(),
    configs=st.lists(domain_config(), min_size=1, max_size=10)
)
def test_property_1_group_creation_preserves_all_domains(name, configs):
    """Property 1: Group creation preserves all domains."""
    database.reset_db()
    monitoring_service = create_test_service()
    try:
        group, domains = monitoring_service.create_group(name, configs)

        assert len(domains) == len(configs)
        assert len(group.domain_ids) == len(configs)

        domain_ids_set = {d.id for d in domains}
        group_ids_set = set(group.domain_ids)
        assert domain_ids_set == group_ids_set

        for i, (domain, config) in enumerate(zip(domains, configs)):
            assert domain.url == config['url']
            assert domain.dump_mode == config['dump_mode']
            assert domain.frequency_seconds == config['frequency_seconds']
            assert domain.group_id == group.id
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10, deadline=500)
@given(
    groups_data=st.lists(
        st.tuples(group_name(), st.lists(domain_config(), min_size=1, max_size=5)),
        min_size=1,
        max_size=10
    )
)
def test_property_4_group_id_uniqueness(groups_data):
    """Property 4: Group ID uniqueness."""
    database.reset_db()
    monitoring_service = create_test_service()
    try:
        created_groups = []
        for name, configs in groups_data:
            group, _ = monitoring_service.create_group(name, configs)
            created_groups.append(group)

        group_ids = [g.id for g in created_groups]
        assert len(group_ids) == len(set(group_ids))

        all_groups = monitoring_service.get_all_groups()
        all_ids = [g.id for g in all_groups]
        assert len(all_ids) == len(set(all_ids))

        # Verify all created groups are present in the database
        all_group_ids = {g.id for g in all_groups}
        for group in created_groups:
            assert group.id in all_group_ids
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10)
@given(
    name=group_name(),
    configs=st.lists(domain_config(), min_size=1, max_size=10)
)
def test_property_5_first_dump_count_matches_domain_count(name, configs):
    """Property 5: First dump count matches domain count."""
    database.reset_db()
    monitoring_service = create_test_service()
    try:
        group, domains = monitoring_service.create_group(name, configs)

        expected_count = len(configs)
        assert len(domains) == expected_count

        for domain in domains:
            snapshots = monitoring_service.storage.load_snapshots_for_domain(domain.id)
            assert len(snapshots) >= 1
            assert snapshots[0].trigger_type == "initial"

        total_snapshots = sum(
            len(monitoring_service.storage.load_snapshots_for_domain(d.id))
            for d in domains
        )
        assert total_snapshots >= expected_count
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10, deadline=500)
@given(
    name=group_name(),
    configs=st.lists(domain_config(), min_size=1, max_size=10)
)
def test_property_6_first_dump_contains_html(name, configs):
    """Property 6: First dump contains HTML."""
    database.reset_db()
    monitoring_service = create_test_service()
    try:
        group, domains = monitoring_service.create_group(name, configs)

        for domain in domains:
            snapshots = monitoring_service.storage.load_snapshots_for_domain(domain.id)
            assert len(snapshots) >= 1

            first_snapshot = snapshots[0]
            assert first_snapshot.html_path

            html_content = monitoring_service.storage.load_html(first_snapshot.html_path)
            assert html_content
            assert len(html_content) > 0
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10)
@given(
    name=group_name(),
    urls=st.lists(valid_url(), min_size=1, max_size=10),
    frequency=st.integers(min_value=1, max_value=86400)
)
def test_property_8_assets_captured_when_mode_is_html_and_assets(name, urls, frequency):
    """Property 8: Assets captured when mode is HTML + assets."""
    database.reset_db()
    monitoring_service = create_test_service()
    monitoring_service.capture.download_assets.return_value = ['style.css', 'script.js']

    try:
        configs = [
            {'url': url, 'dump_mode': 'html_and_assets', 'frequency_seconds': frequency}
            for url in urls
        ]

        group, domains = monitoring_service.create_group(name, configs)

        for domain in domains:
            assert domain.dump_mode == 'html_and_assets'
            snapshots = monitoring_service.storage.load_snapshots_for_domain(domain.id)
            assert len(snapshots) >= 1

            first_snapshot = snapshots[0]
            assert first_snapshot.asset_count > 0
            assert first_snapshot.assets_dir is not None
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10)
@given(
    name=group_name(),
    urls=st.lists(valid_url(), min_size=1, max_size=10),
    frequency=st.integers(min_value=1, max_value=86400)
)
def test_property_9_no_assets_captured_when_mode_is_html_only(name, urls, frequency):
    """Property 9: No assets captured when mode is HTML only."""
    database.reset_db()
    monitoring_service = create_test_service()

    try:
        configs = [
            {'url': url, 'dump_mode': 'html_only', 'frequency_seconds': frequency}
            for url in urls
        ]

        group, domains = monitoring_service.create_group(name, configs)

        for domain in domains:
            assert domain.dump_mode == 'html_only'
            snapshots = monitoring_service.storage.load_snapshots_for_domain(domain.id)
            assert len(snapshots) >= 1

            first_snapshot = snapshots[0]
            assert first_snapshot.asset_count == 0
            assert first_snapshot.assets_dir is None
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10)
@given(
    name=group_name(),
    configs=st.lists(domain_config(), min_size=1, max_size=10)
)
def test_property_20_force_dump_contains_html(name, configs):
    """Property 20: Force dump contains HTML."""
    database.reset_db()
    monitoring_service = create_test_service()
    try:
        group, domains = monitoring_service.create_group(name, configs)

        for domain in domains:
            force_snapshot = monitoring_service.trigger_force_dump(domain.id)
            assert force_snapshot is not None
            assert force_snapshot.html_path

            html_content = monitoring_service.storage.load_html(force_snapshot.html_path)
            assert html_content
            assert len(html_content) > 0
    finally:
        cleanup_test_service(monitoring_service)


@settings(max_examples=10, deadline=500)
@given(
    name=group_name(),
    configs=st.lists(domain_config(), min_size=2, max_size=10)
)
def test_property_24_all_created_groups_are_retrievable(name, configs):
    """Property 24: All created groups are retrievable."""
    database.reset_db()
    monitoring_service = create_test_service()
    try:
        group, _ = monitoring_service.create_group(name, configs)

        retrieved = monitoring_service.get_group(group.id)
        assert retrieved is not None
        assert retrieved.name == group.name
    finally:
        cleanup_test_service(monitoring_service)
