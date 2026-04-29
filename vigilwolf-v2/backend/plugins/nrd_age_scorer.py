"""Newly Registered Domain age scoring plugin for VigilWolf v2."""
from datetime import datetime, timezone
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


@register_plugin
class NRDAgeScorer(AnalysisPlugin):
    name = "nrd_age_scorer"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        first_seen = ctx.snapshot_record.get("first_seen")

        if not first_seen:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={},
            )

        # Parse ISO 8601 timestamp
        try:
            if isinstance(first_seen, datetime):
                first_seen_dt = first_seen
                if first_seen_dt.tzinfo is None:
                    first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
            else:
                # Handle ISO format strings, stripping trailing Z or timezone
                first_seen_str = str(first_seen)
                first_seen_str = first_seen_str.replace("Z", "+00:00")
                first_seen_dt = datetime.fromisoformat(first_seen_str)
                if first_seen_dt.tzinfo is None:
                    first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
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

        now = datetime.now(timezone.utc)
        age_days = (now - first_seen_dt).days

        if age_days > 30:
            score = 0
        elif age_days >= 8:
            score = 3
        elif age_days >= 4:
            score = 7
        else:  # 0-3 days
            score = 10

        tags = ["nrd_age"] if score > 0 else []

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=1.0,
            tags=tags,
            findings={"age_days": age_days},
        )