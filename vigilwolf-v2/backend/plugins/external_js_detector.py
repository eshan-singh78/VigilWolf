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
        domain = ctx.domain
        if "://" in domain:
            domain = urlparse(domain).netloc

        external_count = 0
        for script in ctx.scripts:
            src = script.get("src", "")
            if not src:
                continue
            if not src.startswith("http"):
                continue
            script_domain = urlparse(src).netloc
            if script_domain and script_domain != domain:
                external_count += 1

        if external_count == 0:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=1.0,
                tags=[],
                findings={"external_js_count": 0},
            )

        score = min(10, external_count * 3)

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=0.70,
            tags=["external_js_detected"],
            findings={"external_js_count": external_count},
        )