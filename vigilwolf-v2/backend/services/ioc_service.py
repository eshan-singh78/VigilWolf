"""IOC Service — Persist and query indicators of compromise.

Handles deduplication, occurrence tracking, role classification, and
relationship building for IOCs extracted by the ioc_extractor plugin.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def _escape_like(q: str) -> str:
    """Escape SQL LIKE wildcards (% and _) in user input."""
    return q.replace("%", "\\%").replace("_", "\\_")


def _normalize_ioc_value(ioc_type: str, value: str) -> str:
    """Normalize IOC values for dedup: lowercase domains/emails/URLs,
    strip leading zeros from IPs, normalize IPv6, normalize Telegram
    handles, lowercase URL path components (preserving query values)."""
    value = value.strip()
    if not value:
        return value
    if ioc_type in ("domain", "email"):
        return value.lower()
    if ioc_type == "url":
        parsed = urlparse(value)
        if parsed.hostname:
            normalized_netloc = parsed.hostname.lower()
            if parsed.port:
                normalized_netloc = f"{normalized_netloc}:{parsed.port}"
            # Lowercase path segments but preserve query parameter values
            normalized_path = parsed.path.lower()
            return parsed._replace(netloc=normalized_netloc, path=normalized_path).geturl()
        return value.lower()
    if ioc_type == "ip":
        # IPv6: use ipaddress module for full normalization
        if ":" in value:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                return value.lower()
        # IPv4: strip leading zeros from each octet (e.g., 192.168.001.001 -> 192.168.1.1)
        parts = value.split(".")
        if len(parts) == 4:
            return ".".join(str(int(p)) for p in parts)
    if ioc_type == "telegram":
        # Strip leading @ and lowercase
        return value.lstrip("@").lower()
    if ioc_type == "phone":
        digits = re.sub(r"\D", "", value)
        if not digits:
            return value
        if len(digits) == 11 and digits.startswith("1"):
            return f"+{digits}"
        if len(digits) == 10:
            return f"+1{digits}"
        return f"+{digits}"
    if ioc_type == "wallet":
        if value.startswith("0x") or value.startswith("0X"):
            return value.lower()
        return value
    return value

# ---------------------------------------------------------------------------
# Type mapping: findings key -> IocModel.type value
# ---------------------------------------------------------------------------

_IOC_TYPE_MAP = {
    "domains": "domain",
    "ips": "ip",
    "urls": "url",
    "emails": "email",
    "telegram_handles": "telegram",
    "crypto_wallets": "wallet",
}

# Maximum same_page relationships per snapshot to prevent O(n^2) explosion.
MAX_SAME_PAGE_RELATIONSHIPS = 50

# ---------------------------------------------------------------------------
# Role classification constants
# ---------------------------------------------------------------------------

_CDN_KEYWORDS = (
    "cdn",
    "cloudfront",
    "akamai",
    "cloudflare",
    "fastly",
    "azureedge",
    "googleapis",
    "amazonaws",
    "jsdelivr",
    "unpkg",
)

_LEGITIMATE_LOGIN_DOMAINS = (
    "login.microsoftonline.com",
    "login.salesforce.com",
    "accounts.google.com",
    "signin.aws.amazon.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "pingidentity.com",
    "login.live.com",
    "login.yahoo.com",
    "login.apple.com",
    "login.twitter.com",
    "login.linkedin.com",
)

_TRACKING_PIXEL_KEYWORDS = (
    "pixel",
    "tracking",
    "analytics",
    "telemetry",
    "beacon",
    "collect",
    "gtm.",
    "google-analytics",
    "googletagmanager",
    "facebook.com/tr",
    "doubleclick",
    "hotjar",
    "mixpanel",
    "segment",
)

# Domains where exfil keywords appear legitimately (F-1).
# These are real brand domains that use "post", "submit", etc. in their paths.
_EXFIL_DOMAIN_DENYLIST = frozenset({
    "postbank.com",
    "deutsche-bank.de",
    "poste.it",
    "canadapost-postescanada.ca",
})


# ---------------------------------------------------------------------------
# Role classification helpers
# ---------------------------------------------------------------------------


def _classify_url_role(url: str) -> str:
    """Classify the role of a URL IOC.

    Returns one of: exfil_endpoint, cdn, tracking, redirect, resource.
    """
    url_lower = url.lower()

    # Check if URL is on a known legitimate login/SSO domain
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if any(hostname == domain or hostname.endswith("." + domain) for domain in _LEGITIMATE_LOGIN_DOMAINS):
        return "resource"

    # F-1: Check exfil domain denylist BEFORE keyword matching.
    # These are legitimate brand domains that happen to use exfil keywords.
    if any(hostname == d or hostname.endswith(f".{d}") for d in _EXFIL_DOMAIN_DENYLIST):
        return "resource"

    # Exfiltration endpoints: POST actions, form submissions — checked BEFORE
    # tracking so that phishing exfil URLs like /api/collect are not misclassified
    # as tracking pixels.
    if any(sig in url_lower for sig in ("post", "submit", "upload", "api/send", "api/login", "api/submit", "capture", "exfil")):
        return "exfil_endpoint"

    # Tracking pixels / analytics — after exfil check so that "collect" URLs
    # are only classified as tracking when the domain matches known analytics providers.
    _ANALYTICS_DOMAINS = (
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "facebook.com", "hotjar.com", "mixpanel.com", "segment.com",
    )
    if any(kw in url_lower for kw in _TRACKING_PIXEL_KEYWORDS):
        # "collect" is ambiguous — only classify as tracking if the domain
        # matches a known analytics provider. Otherwise it may be a phishing
        # exfil endpoint that happens to use "collect" in its path.
        if "collect" in url_lower:
            if any(hostname == ad or hostname.endswith("." + ad) for ad in _ANALYTICS_DOMAINS):
                return "tracking"
            # "collect" on a non-analytics domain is more likely exfil;
            # it was already caught by the exfil check above unless it's
            # a standalone "collect" without other exfil indicators.
            # Re-check as exfil if the path contains it.
            if "/collect" in url_lower:
                return "exfil_endpoint"
        return "tracking"

    # CDN / static asset hosts (parsed/hostname already computed above)
    if any(kw in hostname for kw in _CDN_KEYWORDS):
        return "cdn"

    # Redirect links (common redirect patterns in phishing)
    if any(sig in url_lower for sig in ("redirect", "r/", "go/", "link/", "click", "jump", "redir")):
        return "redirect"

    return "resource"


def _classify_domain_role(domain: str) -> str:
    """Classify the role of a domain IOC.

    Returns one of: cdn, tracking, resource.
    """
    domain_lower = domain.lower()

    # Tracking / analytics domains
    if any(kw in domain_lower for kw in _TRACKING_PIXEL_KEYWORDS):
        return "tracking"

    # CDN domains
    if any(kw in domain_lower for kw in _CDN_KEYWORDS):
        return "cdn"

    return "resource"


def _classify_role(ioc_type: str, value: str) -> str:
    """Dispatch to the correct role classifier for a given IOC."""
    if ioc_type == "url":
        return _classify_url_role(value)
    if ioc_type == "domain":
        return _classify_domain_role(value)
    # IPs, emails, telegram handles, wallets, phones default to resource
    return "resource"


# ---------------------------------------------------------------------------
# Relationship helpers
# ---------------------------------------------------------------------------


def _is_script_src_url(url: str) -> bool:
    """Heuristic: URL that looks like a script resource load."""
    url_lower = url.lower()
    return url_lower.endswith(".js") or ".js?" in url_lower or "script" in url_lower


def _infer_context(ioc_type: str, value: str) -> str:
    """Infer the HTML context in which this IOC was found."""
    if ioc_type == "url":
        url_lower = value.lower()
        if url_lower.endswith(".js") or ".js?" in url_lower:
            return "script"
        if url_lower.endswith(".css") or ".css?" in url_lower:
            return "link"
        if any(sig in url_lower for sig in ("form", "submit", "login", "post")):
            return "form"
        return "link"
    if ioc_type == "domain":
        return "html"
    if ioc_type == "email":
        return "html"
    if ioc_type == "telegram":
        return "link"
    return "html"


# ---------------------------------------------------------------------------
# Core service functions
# ---------------------------------------------------------------------------


def persist_iocs(
    snapshot_id: str,
    findings: dict,
    session: Session,
) -> dict:
    """Persist IOC extraction results into the database.

    For each IOC type in findings:
      1. Create or merge IocModel rows (dedup by type+value via unique constraint
         on IocModel.value).
      2. Create IocOccurrenceModel rows linking each IOC to the snapshot.
      3. Classify IOC roles based on value heuristics.
      4. Build IocRelationshipModel rows: same_page (IOCs co-occurring in a
         snapshot), script_load (script src URLs).

    Args:
        snapshot_id: The snapshot these IOCs were extracted from.
        findings: Dict with keys like 'domains', 'ips', 'urls', 'emails',
                  'telegram_handles', 'crypto_wallets', each mapping to list[str].
        session: Active SQLAlchemy session.

    Returns:
        Dict with counts: {iocs_persisted, occurrences_created, relationships_created}.
    """
    from database import IocModel, IocOccurrenceModel, IocRelationshipModel

    now = datetime.now(timezone.utc)

    iocs_persisted = 0
    occurrences_created = 0
    relationships_created = 0

    # Collect all IOC ids created/found in this run for same_page relationships.
    snapshot_ioc_ids: list[int] = []

    for findings_key, ioc_type in _IOC_TYPE_MAP.items():
        raw_values = findings.get(findings_key) or []
        if not raw_values:
            continue

        for value in raw_values:
            if value is None:
                continue
            value = value.strip()
            if not value:
                continue

            # Dedup: find existing or create new IocModel (savepoint for concurrent safety)
            normalized = _normalize_ioc_value(ioc_type, value)
            value_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

            try:
                with session.begin_nested():
                    existing_check = (
                        session.query(IocModel)
                        .filter(IocModel.value_hash == value_hash)
                        .first()
                    )
                    if existing_check is None:
                        ioc = IocModel(
                            type=ioc_type,
                            value=normalized,
                            value_hash=value_hash,
                            first_seen=now,
                            last_seen=now,
                        )
                        session.add(ioc)
                        session.flush()
                        iocs_persisted += 1
                        ioc_id = ioc.id
                    else:
                        existing_check.last_seen = now
                        ioc_id = existing_check.id
            except Exception:
                # IntegrityError from concurrent insert — query the existing row
                logger.debug("IOC value already exists: %s", normalized[:50])
                existing = (
                    session.query(IocModel)
                    .filter(IocModel.value_hash == value_hash)
                    .first()
                )
                if existing is None:
                    # Shouldn't happen, but skip if it does
                    continue
                existing.last_seen = now
                ioc_id = existing.id

            snapshot_ioc_ids.append(ioc_id)

            # Create occurrence linking IOC to this snapshot (idempotent via unique constraint)
            role = _classify_role(ioc_type, normalized)
            context = _infer_context(ioc_type, normalized)

            try:
                with session.begin_nested():
                    occurrence = IocOccurrenceModel(
                        ioc_id=ioc_id,
                        snapshot_id=snapshot_id,
                        context=context,
                        confidence=1.0,
                        role=role,
                        created_at=now,
                    )
                    session.add(occurrence)
                    session.flush()
                occurrences_created += 1
            except Exception:
                logger.debug("IOC occurrence already exists: ioc_id=%d snapshot=%s", ioc_id, snapshot_id)

    # Build relationships -------------------------------------------------

    # Batch-load all IOCs for this snapshot in a single query (N+1 fix)
    ioc_rows = (
        session.query(IocModel)
        .filter(IocModel.id.in_(snapshot_ioc_ids))
    ) if snapshot_ioc_ids else []
    ioc_by_id = {ioc.id: ioc for ioc in ioc_rows}

    # S-3: Priority-based same_page generation.
    # Classify IOCs as high-value (exfil_endpoint, telegram, wallet) or standard,
    # then generate pairs in priority order with a running cap.
    if len(snapshot_ioc_ids) >= 2:
        # Classify each IOC for priority tiering
        high_value_ids: list[int] = []
        standard_ids: list[int] = []
        for ioc_id in snapshot_ioc_ids:
            ioc = ioc_by_id.get(ioc_id) if ioc_by_id else None
            if ioc is None:
                standard_ids.append(ioc_id)
                continue
            is_high_value = (
                ioc.type in ("telegram", "wallet")
                or (ioc.type == "url" and _classify_role("url", ioc.value) == "exfil_endpoint")
            )
            if is_high_value:
                high_value_ids.append(ioc_id)
            else:
                standard_ids.append(ioc_id)

        # Deduplicate
        high_value_ids = sorted(set(high_value_ids))
        standard_ids = sorted(set(standard_ids))

        pair_count = 0
        max_pairs = MAX_SAME_PAGE_RELATIONSHIPS

        def _add_pair(src_id: int, tgt_id: int) -> bool:
            nonlocal pair_count, relationships_created
            if pair_count >= max_pairs:
                return False
            try:
                with session.begin_nested():
                    rel = IocRelationshipModel(
                        source_ioc_id=src_id,
                        target_ioc_id=tgt_id,
                        relationship_type="same_page",
                        confidence=0.7,
                    )
                    session.add(rel)
                    session.flush()
                relationships_created += 1
                pair_count += 1
                return True
            except Exception:
                logger.debug(
                    "IOC relationship already exists: %d -> %d (same_page)",
                    src_id, tgt_id,
                )
                return True  # Already exists, count as done

        # Priority 1: high-value <-> high-value
        for i in range(len(high_value_ids)):
            for j in range(i + 1, len(high_value_ids)):
                if not _add_pair(high_value_ids[i], high_value_ids[j]):
                    break
            if pair_count >= max_pairs:
                break

        # Priority 2: high-value <-> standard
        if pair_count < max_pairs:
            for hv_id in high_value_ids:
                for std_id in standard_ids:
                    if not _add_pair(hv_id, std_id):
                        break
                if pair_count >= max_pairs:
                    break

        # Priority 3: standard <-> standard
        if pair_count < max_pairs:
            for i in range(len(standard_ids)):
                for j in range(i + 1, len(standard_ids)):
                    if not _add_pair(standard_ids[i], standard_ids[j]):
                        break
                if pair_count >= max_pairs:
                    break

        if pair_count >= max_pairs and len(snapshot_ioc_ids) > 10:
            logger.info(
                "Capped same_page relationships for snapshot %s at %d (total possible: %d)",
                snapshot_id, max_pairs,
                len(snapshot_ioc_ids) * (len(snapshot_ioc_ids) - 1) // 2,
            )

    # script_load: script src URLs are linked to the domain they are loaded on
    # ioc_by_id already loaded above for same_page priority classification

    url_ioc_ids = []
    domain_ioc_ids = []
    for ioc_id in snapshot_ioc_ids:
        ioc = ioc_by_id.get(ioc_id)
        if ioc is None:
            continue
        if ioc.type == "url" and _is_script_src_url(ioc.value):
            url_ioc_ids.append(ioc_id)
        elif ioc.type == "domain":
            domain_ioc_ids.append(ioc_id)

    for url_id in url_ioc_ids:
        url_ioc = ioc_by_id.get(url_id)
        if url_ioc is None:
            continue
        parsed = urlparse(url_ioc.value)
        domain_host = (parsed.hostname or "").lower()
        if not domain_host:
            continue

        for domain_id in domain_ioc_ids:
            domain_ioc = ioc_by_id.get(domain_id)
            if domain_ioc is None:
                continue
            if domain_ioc.value.lower() == domain_host:
                try:
                    with session.begin_nested():
                        rel = IocRelationshipModel(
                            source_ioc_id=domain_id,
                            target_ioc_id=url_id,
                            relationship_type="script_load",
                            confidence=0.9,
                        )
                        session.add(rel)
                        session.flush()
                    relationships_created += 1
                except Exception:
                    logger.debug(
                        "IOC relationship already exists: %d -> %d (script_load)",
                        domain_id, url_id,
                    )

    session.flush()

    logger.info(
        "persist_iocs snapshot=%s: %d iocs, %d occurrences, %d relationships",
        snapshot_id,
        iocs_persisted,
        occurrences_created,
        relationships_created,
    )

    return {
        "iocs_persisted": iocs_persisted,
        "occurrences_created": occurrences_created,
        "relationships_created": relationships_created,
    }


def get_iocs_for_domain(
    domain_id: str,
    session: Session,
) -> list[dict]:
    """Return all IOCs found across all snapshots of a domain.

    Joins ioc_occurrences -> snapshots -> domains to find every IOC that
    appeared in any snapshot of the given domain.

    Args:
        domain_id: The domain to look up IOCs for.
        session: Active SQLAlchemy session.

    Returns:
        List of dicts, each with ioc id, type, value, first_seen, last_seen,
        snapshot_id, role, context, confidence.
    """
    from database import IocModel, IocOccurrenceModel, SnapshotModel

    rows = (
        session.query(
            IocModel.id,
            IocModel.type,
            IocModel.value,
            IocModel.first_seen,
            IocModel.last_seen,
            IocOccurrenceModel.snapshot_id,
            IocOccurrenceModel.role,
            IocOccurrenceModel.context,
            IocOccurrenceModel.confidence,
        )
        .join(IocOccurrenceModel, IocModel.id == IocOccurrenceModel.ioc_id)
        .join(SnapshotModel, IocOccurrenceModel.snapshot_id == SnapshotModel.id)
        .filter(SnapshotModel.domain_id == domain_id)
        .order_by(IocModel.type, IocModel.value)
        .all()
    )

    results = []
    for row in rows:
        results.append({
            "id": row.id,
            "type": row.type,
            "value": row.value,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "snapshot_id": row.snapshot_id,
            "role": row.role,
            "context": row.context,
            "confidence": row.confidence,
        })

    logger.debug("get_iocs_for_domain domain=%s: %d results", domain_id, len(results))
    return results


def get_ioc_details(
    ioc_id: int,
    session: Session,
) -> dict:
    """Return an IOC with all its occurrences and related IOCs.

    Args:
        ioc_id: Primary key of the IocModel.
        session: Active SQLAlchemy session.

    Returns:
        Dict with ioc details, list of occurrences, and list of related IOCs.
        Returns empty dict if the IOC is not found.
    """
    from database import IocModel, IocOccurrenceModel, IocRelationshipModel

    ioc = session.query(IocModel).get(ioc_id)
    if ioc is None:
        return {}

    # Occurrences
    occ_rows = (
        session.query(IocOccurrenceModel)
        .filter(IocOccurrenceModel.ioc_id == ioc_id)
        .order_by(IocOccurrenceModel.created_at.desc())
        .all()
    )

    occurrences = []
    for occ in occ_rows:
        occurrences.append({
            "id": occ.id,
            "snapshot_id": occ.snapshot_id,
            "context": occ.context,
            "confidence": occ.confidence,
            "role": occ.role,
            "created_at": occ.created_at.isoformat() if occ.created_at else None,
        })

    # Related IOCs (both directions of the relationship)
    rel_rows = (
        session.query(IocRelationshipModel)
        .filter(
            (IocRelationshipModel.source_ioc_id == ioc_id)
            | (IocRelationshipModel.target_ioc_id == ioc_id)
        )
        .all()
    )

    # Collect unique related IOC IDs and map relationship info
    seen_ioc_ids = set()
    rel_info: list[tuple[int, str, float]] = []  # (other_ioc_id, relationship_type, confidence)
    for rel in rel_rows:
        if rel.source_ioc_id == ioc_id:
            other_id = rel.target_ioc_id
        else:
            other_id = rel.source_ioc_id

        if other_id in seen_ioc_ids:
            continue
        seen_ioc_ids.add(other_id)
        rel_info.append((other_id, rel.relationship_type, rel.confidence))

    # Batch-load all related IOCs in a single query
    related_iocs = []
    if seen_ioc_ids:
        other_iocs = (
            session.query(IocModel)
            .filter(IocModel.id.in_(seen_ioc_ids))
            .all()
        )
        other_by_id = {ioc.id: ioc for ioc in other_iocs}
        for other_id, rel_type, confidence in rel_info:
            other_ioc = other_by_id.get(other_id)
            if other_ioc is None:
                continue
            related_iocs.append({
                "id": other_ioc.id,
                "type": other_ioc.type,
                "value": other_ioc.value,
                "relationship_type": rel_type,
                "confidence": confidence,
            })

    return {
        "id": ioc.id,
        "type": ioc.type,
        "value": ioc.value,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "occurrences": occurrences,
        "related_iocs": related_iocs,
    }


def search_iocs(
    query: str,
    ioc_type: Optional[str] = None,
    session: Session = None,
) -> list[dict]:
    """Search IOCs by value substring with optional type filter.

    Args:
        query: Substring to search for in IOC values (case-insensitive).
        ioc_type: Optional IOC type filter (domain, ip, url, email, telegram,
                  wallet, phone).
        session: Active SQLAlchemy session.

    Returns:
        List of dicts with ioc id, type, value, first_seen, last_seen, occurrence_count.
    """
    from database import IocModel, IocOccurrenceModel

    q = session.query(
        IocModel.id,
        IocModel.type,
        IocModel.value,
        IocModel.first_seen,
        IocModel.last_seen,
        func.count(IocOccurrenceModel.id).label("occurrence_count"),
    ).outerjoin(
        IocOccurrenceModel, IocModel.id == IocOccurrenceModel.ioc_id
    )

    q = q.filter(IocModel.value.ilike(f"%{_escape_like(query)}%", escape="\\"))

    if ioc_type:
        q = q.filter(IocModel.type == ioc_type)

    q = q.group_by(IocModel.id).order_by(IocModel.value).limit(200)

    rows = q.all()

    results = []
    for row in rows:
        results.append({
            "id": row.id,
            "type": row.type,
            "value": row.value,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "occurrence_count": row.occurrence_count,
        })

    logger.debug("search_iocs query=%r type=%s: %d results", query, ioc_type, len(results))
    return results