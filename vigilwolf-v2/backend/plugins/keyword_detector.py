"""Urgency/scam keyword detection plugin for VigilWolf v2."""
import re
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

URGENCY_KEYWORDS = [
    "verify", "secure", "update", "login", "otp", "suspend", "expire",
    "confirm", "unlock", "restore", "immediately", "unauthorized", "validate",
    "reactivate",
]

# Build a single regex pattern matching any keyword (case-insensitive, word boundary)
_KEYWORD_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(kw) for kw in URGENCY_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


@register_plugin
class KeywordDetector(AnalysisPlugin):
    name = "keyword_detector"
    version = "1.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        matches = _KEYWORD_PATTERN.findall(ctx.text)
        total_hits = len(matches)

        if total_hits < 2:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={"matches": matches, "total_hits": total_hits},
            )

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