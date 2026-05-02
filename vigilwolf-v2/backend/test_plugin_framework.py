"""Test plugin framework: base classes, registry, execution groups."""
import pytest
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import (
    PLUGIN_REGISTRY, register_plugin, ExecutionGroup, get_execution_groups,
    circuit_breaker, CircuitBreaker,
)


def test_plugin_type_enum():
    assert PluginType.DETECTION.value == "detection"
    assert PluginType.EXTRACTION.value == "extraction"
    assert PluginType.ENRICHMENT.value == "enrichment"
    assert PluginType.FINGERPRINT.value == "fingerprint"


def test_snapshot_context_creation():
    ctx = SnapshotContext(
        snapshot_id="snap1", domain="example.com",
        html="<html></html>", text="Hello",
        forms=[], links=["https://example.com/page"],
        scripts=[], metadata={"title": "Example"},
        snapshot_record={"id": "snap1", "domain_id": "d1"},
    )
    assert ctx.domain == "example.com"
    assert ctx.text == "Hello"
    assert ctx.links == ["https://example.com/page"]


def test_plugin_result_creation():
    result = PluginResult(
        plugin_name="login_detector", plugin_version="1.0.0",
        plugin_type=PluginType.DETECTION, score_contribution=40,
        confidence=0.95, tags=["login_form_detected"],
        findings={"has_password_field": True},
    )
    assert result.score_contribution == 40
    assert result.confidence == 0.95


def test_register_plugin():
    # Save state to avoid polluting other tests
    saved = dict(PLUGIN_REGISTRY)

    @register_plugin
    class TestPlugin(AnalysisPlugin):
        name = "test_plugin_unique_12345"
        version = "1.0.0"
        plugin_type = PluginType.DETECTION

        def run(self, ctx):
            return PluginResult(
                plugin_name=self.name, plugin_version=self.version,
                plugin_type=self.plugin_type, score_contribution=0,
                confidence=1.0, tags=[], findings={},
            )

    assert "test_plugin_unique_12345" in PLUGIN_REGISTRY

    # Cleanup
    PLUGIN_REGISTRY.clear()
    PLUGIN_REGISTRY.update(saved)


def test_execution_groups_structure():
    groups = get_execution_groups()
    assert isinstance(groups, list)
    assert all(isinstance(g, ExecutionGroup) for g in groups)
    detect_group = next((g for g in groups if g.name == "detect"), None)
    assert detect_group is not None
    assert len(detect_group.plugins) > 0


def test_circuit_breaker_allows_under_threshold():
    cb = CircuitBreaker(threshold=1000)
    assert cb.should_run("login_detector", PluginType.DETECTION, 500) == True
    assert cb.should_run("keyword_detector", PluginType.DETECTION, 500) == True


def test_circuit_breaker_restricts_over_threshold():
    cb = CircuitBreaker(threshold=1000)
    # Over threshold: high-impact detection still runs
    assert cb.should_run("login_detector", PluginType.DETECTION, 5000) == True
    assert cb.should_run("brand_match", PluginType.DETECTION, 5000) == True
    # Over threshold: low-impact detection skipped
    assert cb.should_run("keyword_detector", PluginType.DETECTION, 5000) == False
    # Over threshold: extraction still runs
    assert cb.should_run("ioc_extractor", PluginType.EXTRACTION, 5000) == True
    # Over threshold: enrichment and fingerprint skipped
    assert cb.should_run("whois_enricher", PluginType.ENRICHMENT, 5000) == False
    assert cb.should_run("html_hasher", PluginType.FINGERPRINT, 5000) == False


def test_analysis_plugin_must_implement_run():
    plugin = AnalysisPlugin()
    with pytest.raises(NotImplementedError):
        plugin.run(SnapshotContext(
            snapshot_id="x", domain="x", html="", text="",
            forms=[], links=[], scripts=[], metadata={}, snapshot_record={},
        ))