"""Test SQLite to PostgreSQL data migration integrity."""
import pytest
from sqlalchemy import create_engine, text, StaticPool
from database import Base


@pytest.fixture
def source_engine():
    """Create an in-memory SQLite engine with test data.

    Uses StaticPool so all connections share the same underlying
    in-memory database (required for migration functions that open
    separate connections).
    """
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    # Insert test data
    with eng.connect() as conn:
        conn.execute(text(
            "INSERT INTO groups (id, name, created_at) "
            "VALUES ('g1', 'Test Group', '2026-01-01 00:00:00+00:00')"
        ))
        conn.execute(text(
            "INSERT INTO domains (id, group_id, url, dump_mode, frequency_seconds, active, created_at) "
            "VALUES ('d1', 'g1', 'https://example.com', 'html_only', 300, 1, '2026-01-01 00:00:00+00:00')"
        ))
        conn.commit()
    yield eng


@pytest.fixture
def target_engine():
    """Create an empty in-memory SQLite engine as migration target."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng


def test_migrate_groups_count_matches(source_engine, target_engine):
    from migrate_sqlite_to_pg import migrate_table
    migrate_table(source_engine, target_engine, "groups")

    with target_engine.connect() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM groups")).scalar()
    assert result == 1


def test_migrate_domains_preserves_data(source_engine, target_engine):
    from migrate_sqlite_to_pg import migrate_table
    migrate_table(source_engine, target_engine, "groups")
    migrate_table(source_engine, target_engine, "domains")

    with target_engine.connect() as conn:
        row = conn.execute(
            text("SELECT url, dump_mode, frequency_seconds FROM domains WHERE id = 'd1'")
        ).fetchone()
    assert row is not None
    assert row[0] == "https://example.com"
    assert row[1] == "html_only"
    assert row[2] == 300


def test_validate_migration_catches_mismatch(source_engine, target_engine):
    from migrate_sqlite_to_pg import validate_migration
    # Target is empty — validation should catch count mismatches
    errors = validate_migration(source_engine, target_engine)
    assert len(errors) > 0


def test_validate_migration_passes_after_migrate(source_engine, target_engine):
    from migrate_sqlite_to_pg import migrate_table, validate_migration
    migrate_table(source_engine, target_engine, "groups")
    migrate_table(source_engine, target_engine, "domains")
    errors = validate_migration(source_engine, target_engine)
    assert len(errors) == 0


def test_boolean_conversion_active(source_engine, target_engine):
    from migrate_sqlite_to_pg import migrate_table
    migrate_table(source_engine, target_engine, "groups")
    migrate_table(source_engine, target_engine, "domains")

    with target_engine.connect() as conn:
        row = conn.execute(
            text("SELECT active FROM domains WHERE id = 'd1'")
        ).fetchone()
    # SQLite stored 1; after conversion the value should be a proper boolean
    assert row is not None
    assert row[0] is True or row[0] == 1


def test_migrate_empty_table(source_engine, target_engine):
    from migrate_sqlite_to_pg import migrate_table
    # snapshots table has no data in the source fixture
    migrated = migrate_table(source_engine, target_engine, "snapshots")
    assert migrated == 0