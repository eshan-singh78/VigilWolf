"""VigilWolf v2 — Seed default plugin weights into the database.

On startup, this module ensures that every plugin listed in DEFAULT_WEIGHTS
has a corresponding row in the plugin_weights table.  Existing rows are never
overwritten, so operator-customised weights survive restarts.
"""

from database import PluginWeightModel, get_session

# Default weights for the Phase-1 detection plugins.
# These are only inserted when no row for that plugin_name exists yet.
DEFAULT_WEIGHTS: dict[str, float] = {
    "login_detector": 1.0,
    "keyword_detector": 0.6,
    "brand_match": 1.2,
    "external_js_detector": 0.8,
    "nrd_age_scorer": 0.5,
    "html_hasher": 1.0,
    "ioc_extractor": 1.0,
}


def seed_weights() -> None:
    """Insert default plugin weights if not already present.

    For each entry in DEFAULT_WEIGHTS, check whether a row with that
    plugin_name already exists.  If not, insert one with ``enabled=True``.
    This function is safe to call on every startup.
    """
    with get_session() as session:
        for name, weight in DEFAULT_WEIGHTS.items():
            existing = (
                session.query(PluginWeightModel)
                .filter_by(plugin_name=name)
                .first()
            )
            if not existing:
                session.add(
                    PluginWeightModel(plugin_name=name, weight=weight, enabled=True)
                )
        session.commit()