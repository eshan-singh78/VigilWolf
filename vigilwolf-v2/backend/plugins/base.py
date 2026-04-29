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
    """Parsed snapshot data passed to all plugins. Built once by context_builder,
    avoids redundant I/O across plugins."""
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
    """Structured output from every plugin run."""
    plugin_name: str
    plugin_version: str
    plugin_type: PluginType
    score_contribution: int
    confidence: float
    tags: list[str]
    findings: dict
    error: Optional[str] = None


class AnalysisPlugin:
    """Base class for all analysis plugins. Subclass and implement run()."""
    name: str = ""
    version: str = ""
    plugin_type: PluginType = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        raise NotImplementedError(f"Plugin {self.name} must implement run()")