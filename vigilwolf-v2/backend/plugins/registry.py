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
    """A group of plugins that run in parallel. Groups run sequentially."""
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
    """Controls plugin execution under system load.

    Under load, keeps high-impact detection plugins and all extraction plugins.
    Skips low-impact detection and all enrichment/fingerprint."""

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


circuit_breaker = CircuitBreaker()