"""Tests for seed_weights module."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from database import PluginWeightModel, Base, get_session
from seed_weights import DEFAULT_WEIGHTS, seed_weights

# In-memory SQLite with StaticPool so connections share the same DB.
_TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@pytest.fixture(autouse=True)
def _fresh_db():
    """Create a fresh in-memory database for each test."""
    import database as _db_mod

    _db_mod._engine = _TEST_ENGINE
    Base.metadata.create_all(bind=_TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=_TEST_ENGINE)
    _db_mod._engine = None


# ---------------------------------------------------------------------------
# test_default_weights_complete
# ---------------------------------------------------------------------------

def test_default_weights_complete():
    """Verify DEFAULT_WEIGHTS contains all 7 expected plugins."""
    expected_plugins = {
        "login_detector",
        "keyword_detector",
        "brand_match",
        "external_js_detector",
        "nrd_age_scorer",
        "html_hasher",
        "ioc_extractor",
    }
    assert set(DEFAULT_WEIGHTS.keys()) == expected_plugins
    assert len(DEFAULT_WEIGHTS) == 7


# ---------------------------------------------------------------------------
# test_seed_weights_idempotent
# ---------------------------------------------------------------------------

def test_seed_weights_idempotent():
    """Calling seed_weights() twice should not duplicate rows."""
    seed_weights()
    seed_weights()

    with get_session() as session:
        rows = session.query(PluginWeightModel).all()
        by_name = {row.plugin_name: row for row in rows}

    # One row per plugin, no duplicates
    assert len(rows) == len(DEFAULT_WEIGHTS)

    # Verify each default weight was stored correctly
    for name, weight in DEFAULT_WEIGHTS.items():
        assert by_name[name].weight == weight
        assert by_name[name].enabled is True