"""DNS enrichment plugin for VigilWolf v2.

Resolves DNS records (A, NS, MX) for a domain and stores them in the
domain_ips and dns_records tables. Runs in the 'enrich' execution group.
"""
from __future__ import annotations

import logging
import socket
from typing import Any

from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

logger = logging.getLogger(__name__)


def _resolve_a_records(domain: str) -> list[str]:
    """Resolve A records for a domain. Returns list of IP addresses."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({addr[4][0] for addr in results})
    except socket.gaierror:
        return []


def _resolve_ns_records(domain: str) -> list[str]:
    """Resolve NS records for a domain using dns.resolver if available."""
    try:
        import dns.resolver  # type: ignore[import-untyped]
        answers = dns.resolver.resolve(domain, "NS")
        return [str(rdata.target).rstrip(".") for rdata in answers]
    except ImportError:
        logger.debug("dnspython not available; skipping NS resolution")
        return []
    except Exception:
        return []


def _resolve_mx_records(domain: str) -> list[str]:
    """Resolve MX records for a domain using dns.resolver if available."""
    try:
        import dns.resolver  # type: ignore[import-untyped]
        answers = dns.resolver.resolve(domain, "MX")
        return [str(rdata.exchange).rstrip(".") for rdata in answers]
    except ImportError:
        return []
    except Exception:
        return []


def _lookup_asn(ip: str) -> str | None:
    """Best-effort ASN lookup. Returns ASN string like 'AS13335' or None."""
    # Reverse DNS lookup pattern for ASN (Cymru)
    try:
        parts = ip.split(".")
        reversed_ip = ".".join(reversed(parts))
        hostname = f"{reversed_ip}.origin.asn.cymru.com"
        _, _, ips = socket.gethostbyname_ex(hostname)
        # Parse TXT response: "13335 | 1.1.1.0/24 | US | arin | 2013-04-11"
        return ips[0].split("|")[0].strip() if ips else None
    except Exception:
        return None


@register_plugin
class DNSEnricher(AnalysisPlugin):
    name = "dns_enricher"
    version = "1.0.0"
    plugin_type = PluginType.ENRICHMENT

    def run(self, ctx: SnapshotContext) -> PluginResult:
        domain = ctx.domain

        a_records = _resolve_a_records(domain)
        ns_records = _resolve_ns_records(domain)
        mx_records = _resolve_mx_records(domain)

        # ASN lookups for each IP
        asn_map: dict[str, str] = {}
        for ip in a_records:
            asn = _lookup_asn(ip)
            if asn:
                asn_map[ip] = asn

        tags = ["dns_enriched"]
        if a_records:
            tags.append("dns_has_a_records")
        if ns_records:
            tags.append("dns_has_ns_records")

        findings: dict[str, Any] = {
            "domain": domain,
            "a_records": a_records,
            "ns_records": ns_records,
            "mx_records": mx_records,
            "asn_map": asn_map,
        }

        # Store DNS results in the database if we have a session
        try:
            from database import get_session, DomainIpModel, DnsRecordModel
            snapshot_domain_id = ctx.snapshot_record.get("domain_id")
            if snapshot_domain_id:
                with get_session() as session:
                    # Store A records as domain_ips
                    for ip in a_records:
                        existing = session.query(DomainIpModel).filter_by(
                            domain_id=snapshot_domain_id, ip=ip
                        ).first()
                        if not existing:
                            session.add(DomainIpModel(
                                domain_id=snapshot_domain_id, ip=ip,
                            ))
                    # Store NS and MX records as dns_records
                    for ns in ns_records:
                        existing = session.query(DnsRecordModel).filter_by(
                            domain_id=snapshot_domain_id, type="NS", value=ns
                        ).first()
                        if not existing:
                            session.add(DnsRecordModel(
                                domain_id=snapshot_domain_id, type="NS", value=ns,
                            ))
                    for mx in mx_records:
                        existing = session.query(DnsRecordModel).filter_by(
                            domain_id=snapshot_domain_id, type="MX", value=mx
                        ).first()
                        if not existing:
                            session.add(DnsRecordModel(
                                domain_id=snapshot_domain_id, type="MX", value=mx,
                            ))
                    session.commit()
        except Exception:
            logger.debug("Failed to store DNS results in DB", exc_info=True)

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=0,
            confidence=0.9,
            tags=tags,
            findings=findings,
        )