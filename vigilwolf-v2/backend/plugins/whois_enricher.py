"""WHOIS enrichment plugin for VigilWolf v2.

Resolves domain registration info (registrar, creation date, name servers)
using the python-whois library. Runs in the 'enrich' execution group and
populates domain metadata used by other plugins (e.g. nrd_age_scorer context).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

logger = logging.getLogger(__name__)


def _whois_lookup(domain: str) -> dict[str, Any]:
    """Perform a WHOIS lookup for a domain, returning parsed data.

    Returns a dict with keys: registrar, creation_date, expiration_date,
    name_servers, whois_server. Returns empty dict on any failure.
    """
    try:
        import whois  # type: ignore[import-untyped]
        result = whois.whois(domain)
    except Exception:
        logger.debug("WHOIS lookup failed for %s", domain, exc_info=True)
        return {}

    if result is None:
        return {}

    data: dict[str, Any] = {}

    # Registrar
    registrar = getattr(result, "registrar", None)
    if registrar:
        data["registrar"] = str(registrar)

    # Creation date — may be a list or single value
    creation_date = getattr(result, "creation_date", None)
    if creation_date:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            data["creation_date"] = creation_date.isoformat()
        else:
            data["creation_date"] = str(creation_date)

    # Expiration date
    expiration_date = getattr(result, "expiration_date", None)
    if expiration_date:
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(expiration_date, datetime):
            data["expiration_date"] = expiration_date.isoformat()
        else:
            data["expiration_date"] = str(expiration_date)

    # Name servers
    name_servers = getattr(result, "name_servers", None)
    if name_servers:
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        data["name_servers"] = [ns.lower().rstrip(".") for ns in name_servers if ns]

    # WHOIS server
    whois_server = getattr(result, "whois_server", None)
    if whois_server:
        data["whois_server"] = str(whois_server)

    return data


@register_plugin
class WHOISEnricher(AnalysisPlugin):
    name = "whois_enricher"
    version = "1.0.0"
    plugin_type = PluginType.ENRICHMENT

    def run(self, ctx: SnapshotContext) -> PluginResult:
        domain = ctx.domain

        whois_data = _whois_lookup(domain)

        if not whois_data:
            return PluginResult(
                plugin_name=self.name,
                plugin_version=self.version,
                plugin_type=self.plugin_type,
                score_contribution=0,
                confidence=0.3,
                tags=[],
                findings={"lookup_failed": True, "domain": domain},
            )

        tags = ["whois_enriched"]
        if whois_data.get("registrar"):
            tags.append("whois_registrar_known")

        findings: dict[str, Any] = {"domain": domain, **whois_data}

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=0,
            confidence=0.9,
            tags=tags,
            findings=findings,
        )