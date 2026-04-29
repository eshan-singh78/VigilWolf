"""HTML structural and content fingerprinting plugin for VigilWolf v2."""
import hashlib
from bs4 import BeautifulSoup
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


def _extract_tag_structure(soup) -> str:
    """Recursively extract tag structure (names only, no text or attributes)."""
    parts = []
    for child in soup.children:
        if hasattr(child, "name") and child.name:
            # DocumentType and similar non-element nodes
            if isinstance(child.name, str):
                parts.append(f"<{child.name}>")
                parts.append(_extract_tag_structure(child))
                parts.append(f"</{child.name}>")
    return "".join(parts)


@register_plugin
class HTMLHasher(AnalysisPlugin):
    name = "html_hasher"
    version = "1.0.0"
    plugin_type = PluginType.FINGERPRINT

    def run(self, ctx: SnapshotContext) -> PluginResult:
        # Structural hash: tag structure only, no text
        soup = BeautifulSoup(ctx.html, "html.parser")
        structure_str = _extract_tag_structure(soup)
        structural_hash = hashlib.sha256(structure_str.encode("utf-8")).hexdigest()

        # Content hash: full HTML
        content_hash = hashlib.sha256(ctx.html.encode("utf-8")).hexdigest()

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=0,
            confidence=1.0,
            tags=["structural_hash"],
            findings={
                "structural_hash": structural_hash,
                "content_hash": content_hash,
            },
        )