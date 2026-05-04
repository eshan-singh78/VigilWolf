"""VigilWolf v2 — Dramatiq Worker Pipeline.

Orchestrator + Fan-Out model:
  capture_domain -> build_context_and_analyze -> orchestrate_analysis
      -> (run plugins per group) -> aggregate_results -> dispatch_alert

When USE_DRAMATIQ_PIPELINE=true, each pipeline stage is a Dramatiq actor
that enqueues the next stage. When false (default), all stages run
synchronously in-process — useful for development and testing.
"""
from __future__ import annotations

import hashlib
import logging
import threading as _threading
import time as _time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from plugins.base import AnalysisPlugin, PluginResult, PluginType, SnapshotContext
from plugins.registry import PLUGIN_REGISTRY, get_execution_groups, circuit_breaker
from services.scoring_service import calculate_score, apply_context_modifiers, DEFAULT_WEIGHTS
from services.pipeline_metrics import pipeline_metrics
import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Periodic reconciliation interval (seconds). Orphaned statuses are cleaned up
# every RECONCILIATION_INTERVAL_S regardless of pipeline activity.
# ---------------------------------------------------------------------------
RECONCILIATION_INTERVAL_S = 15 * 60  # 15 minutes
C2_RANKING_INTERVAL_S = 60 * 60  # 1 hour
ACTOR_PROFILING_INTERVAL_S = 60 * 60  # 1 hour
BATCH_CLUSTERING_INTERVAL_S = config.BATCH_CLUSTERING_INTERVAL_S
BATCH_CAMPAIGN_INTERVAL_S = config.BATCH_CAMPAIGN_INTERVAL_S
BATCH_PHISHKIT_INTERVAL_S = config.BATCH_PHISHKIT_INTERVAL_S
MAX_HTML_SIZE = 10 * 1024 * 1024  # 10 MB — reject HTML payloads larger than this


# ---------------------------------------------------------------------------
# Dramatiq broker — lazily initialised so imports don't fail without Redis
# ---------------------------------------------------------------------------

_dramatiq_broker = None
_dramatiq_actors = {}


def _get_broker():
    """Return (and lazily create) the Dramatiq Redis broker."""
    global _dramatiq_broker
    if _dramatiq_broker is not None:
        return _dramatiq_broker
    import dramatiq
    from dramatiq.brokers.redis import RedisBroker
    _dramatiq_broker = RedisBroker(url=config.DRAMATIQ_BROKER_URL)
    dramatiq.set_broker(_dramatiq_broker)
    return _dramatiq_broker


def _get_actors():
    """Return (and lazily create) the Dramatiq actor wrappers.

    Called only when USE_DRAMATIQ_PIPELINE is True. Each actor wraps the
    corresponding synchronous function and enqueues the next stage.
    """
    global _dramatiq_actors
    if _dramatiq_actors:
        return _dramatiq_actors
    import dramatiq

    broker = _get_broker()

    @dramatiq.actor(broker=broker, max_retries=3, max_age=3600000, time_limit=300000)
    def capture_domain_actor(domain_id: str, url: str, trigger_type: str = "nrd_ingest"):
        result = capture_domain(domain_id=domain_id, url=url, trigger_type=trigger_type)
        return result

    @dramatiq.actor(broker=broker, max_retries=3, max_age=3600000, time_limit=300000)
    def build_context_and_analyze_actor(snapshot_id: str, domain_id: str):
        build_context_and_analyze(snapshot_id=snapshot_id, domain_id=domain_id)

    @dramatiq.actor(broker=broker, max_retries=1, max_age=3600000, time_limit=120000)
    def reconcile_orphaned_statuses():
        """Periodic task to clean up orphaned pipeline statuses."""
        run_periodic_reconciliation()

    @dramatiq.actor(broker=broker, max_retries=1, max_age=3600000, time_limit=300000)
    def rank_c2_candidates_periodic():
        """Periodic task to rank C2 candidates across all snapshots."""
        run_periodic_c2_ranking()

    @dramatiq.actor(broker=broker, max_retries=1, max_age=3600000, time_limit=300000)
    def profile_actors_periodic():
        """Periodic task to profile threat actors across all campaigns."""
        run_periodic_actor_profiling()

    @dramatiq.actor(broker=broker, max_retries=1, max_age=3600000, time_limit=300000)
    def batch_clustering_actor():
        """Periodic task to run clustering across all new snapshots."""
        run_periodic_batch_clustering()

    @dramatiq.actor(broker=broker, max_retries=1, max_age=3600000, time_limit=600000)
    def batch_campaign_actor():
        """Periodic task to run campaign detection across all clusters."""
        run_periodic_batch_campaign()

    @dramatiq.actor(broker=broker, max_retries=1, max_age=3600000, time_limit=300000)
    def batch_phishkit_actor():
        """Periodic task to run phishkit detection across all snapshots."""
        run_periodic_batch_phishkit()

    _dramatiq_actors = {
        "capture_domain": capture_domain_actor,
        "build_context_and_analyze": build_context_and_analyze_actor,
        "reconcile_orphaned_statuses": reconcile_orphaned_statuses,
        "rank_c2_candidates_periodic": rank_c2_candidates_periodic,
        "profile_actors_periodic": profile_actors_periodic,
        "batch_clustering": batch_clustering_actor,
        "batch_campaign": batch_campaign_actor,
        "batch_phishkit": batch_phishkit_actor,
    }
    return _dramatiq_actors


# ---------------------------------------------------------------------------
# Periodic orphan reconciliation
# ---------------------------------------------------------------------------

def run_periodic_reconciliation() -> dict:
    """Synchronous reconciliation runner — manages its own DB session.

    Called by the Dramatiq actor and by the background scheduler thread.
    Returns the reconciliation result dict for logging.
    """
    logger.info("Starting periodic orphan status reconciliation")
    try:
        from database import get_session
        from services.reconciliation_service import reconcile_orphaned_statuses

        with get_session() as session:
            result = reconcile_orphaned_statuses(session)
            session.commit()

        logger.info("Periodic reconciliation complete: %s", result)
    except Exception:
        logger.exception("Periodic reconciliation failed")
        result = {"reconciled_running": 0, "reconciled_pending": 0, "error": True}

    # IOC reconciliation — re-persist IOCs for snapshots that lost them.
    ioc_result = {}
    try:
        from database import get_session
        from services.reconciliation_service import reconcile_ioc_persistence

        with get_session() as session:
            ioc_result = reconcile_ioc_persistence(session)
            session.commit()

        logger.info("IOC reconciliation complete: %s", ioc_result)
    except Exception:
        logger.exception("IOC reconciliation failed")

    # Missing pipeline reconciliation — re-trigger analysis for snapshots that never started.
    pipeline_result = {}
    try:
        from database import get_session
        from services.reconciliation_service import reconcile_missing_pipeline

        with get_session() as session:
            pipeline_result = reconcile_missing_pipeline(session)
            # Note: reconcile_missing_pipeline calls build_context_and_analyze
            # which manages its own session, so we commit the lookup session.
            session.commit()

        logger.info("Missing pipeline reconciliation complete: %s", pipeline_result)
    except Exception:
        logger.exception("Missing pipeline reconciliation failed")

    # Cluster count reconciliation — fix domain_count drift (D-1)
    cluster_result = {}
    try:
        from database import get_session
        from services.reconciliation_service import reconcile_cluster_counts

        with get_session() as session:
            cluster_result = reconcile_cluster_counts(session)
            session.commit()

        logger.info("Cluster count reconciliation complete: %s", cluster_result)
    except Exception:
        logger.exception("Cluster count reconciliation failed")

    return {**result, **ioc_result, **pipeline_result, **cluster_result}


_reconciliation_thread: Optional[_threading.Thread] = None


def _reconciliation_scheduler_loop() -> None:
    """Daemon thread that periodically enqueues reconciliation messages."""
    # Wait briefly for the broker to be available before starting the loop.
    _time.sleep(30)
    while True:
        try:
            if config.USE_DRAMATIQ_PIPELINE:
                actors = _get_actors()
                actors["reconcile_orphaned_statuses"].send()
            else:
                # Sync mode — run directly in the background thread.
                run_periodic_reconciliation()
        except Exception:
            logger.exception("Reconciliation scheduler error; will retry next interval")
        _time.sleep(RECONCILIATION_INTERVAL_S)


def start_periodic_reconciliation() -> None:
    """Start the background reconciliation scheduler (idempotent).

    Call once at worker startup.  The scheduler runs on a daemon thread so it
    exits automatically when the main process stops.  If Dramatiq is enabled,
    the scheduler sends a message to the ``reconcile_orphaned_statuses`` actor
    every ``RECONCILIATION_INTERVAL_S`` seconds.  In sync mode it calls the
    reconciliation function directly.
    """
    global _reconciliation_thread
    if _reconciliation_thread is not None and _reconciliation_thread.is_alive():
        logger.info("Periodic reconciliation scheduler already running; skipping.")
        return

    _reconciliation_thread = _threading.Thread(
        target=_reconciliation_scheduler_loop,
        name="vigilwolf-reconciliation-scheduler",
        daemon=True,
    )
    _reconciliation_thread.start()
    logger.info(
        "Started periodic reconciliation scheduler (interval=%ds)", RECONCILIATION_INTERVAL_S,
    )


# ---------------------------------------------------------------------------
# Periodic C2 ranking (hourly batch, not per-snapshot)
# ---------------------------------------------------------------------------

def run_periodic_c2_ranking() -> dict:
    """Synchronous C2 ranking runner — manages its own DB session.

    Called by the Dramatiq actor and by the background scheduler thread.
    Returns the ranking result dict for logging.
    """
    logger.info("Starting periodic C2 ranking")
    try:
        from database import get_session, C2CandidateModel  # type: ignore[import-untyped]
        from services.c2_service import rank_c2_candidates  # type: ignore[import-untyped]

        with get_session() as session:
            c2_result = rank_c2_candidates(session)
            if c2_result:
                for candidate in c2_result:
                    try:
                        with session.begin_nested():
                            existing = (
                                session.query(C2CandidateModel)
                                .filter(C2CandidateModel.ioc_id == candidate["ioc_id"])
                                .first()
                            )
                            if existing:
                                if candidate["c2_score"] > existing.c2_score:
                                    existing.c2_score = candidate["c2_score"]
                                    existing.signals = candidate.get("signals", [])
                            else:
                                c2_row = C2CandidateModel(
                                    ioc_id=candidate["ioc_id"],
                                    snapshot_id=candidate.get("snapshot_id"),
                                    c2_score=candidate["c2_score"],
                                    signals=candidate.get("signals", []),
                                )
                                session.add(c2_row)
                                session.flush()
                    except Exception:
                        logger.debug("C2 candidate already exists for ioc_id=%d", candidate["ioc_id"])
                session.commit()

        logger.info("Periodic C2 ranking complete: %d candidates", len(c2_result) if c2_result else 0)
        return {"candidates_found": len(c2_result) if c2_result else 0}
    except Exception:
        logger.exception("Periodic C2 ranking failed")
        return {"candidates_found": 0, "error": True}


_c2_ranking_thread: Optional[_threading.Thread] = None


def _c2_ranking_scheduler_loop() -> None:
    """Daemon thread that periodically enqueues C2 ranking messages."""
    _time.sleep(60)  # Initial delay to let pipeline warm up
    while True:
        try:
            if config.USE_DRAMATIQ_PIPELINE:
                actors = _get_actors()
                actors["rank_c2_candidates_periodic"].send()
            else:
                run_periodic_c2_ranking()
        except Exception:
            logger.exception("C2 ranking scheduler error; will retry next interval")
        _time.sleep(C2_RANKING_INTERVAL_S)


def start_periodic_c2_ranking() -> None:
    """Start the background C2 ranking scheduler (idempotent).

    Call once at worker startup.  Runs hourly in a daemon thread.
    """
    global _c2_ranking_thread
    if not config.C2_DETECTION_ENABLED:
        logger.info("C2 detection disabled; skipping periodic C2 ranking scheduler.")
        return
    if _c2_ranking_thread is not None and _c2_ranking_thread.is_alive():
        logger.info("Periodic C2 ranking scheduler already running; skipping.")
        return

    _c2_ranking_thread = _threading.Thread(
        target=_c2_ranking_scheduler_loop,
        name="vigilwolf-c2-ranking-scheduler",
        daemon=True,
    )
    _c2_ranking_thread.start()
    logger.info("Started periodic C2 ranking scheduler (interval=%ds)", C2_RANKING_INTERVAL_S)


# ---------------------------------------------------------------------------
# Periodic actor profiling (hourly batch, not per-snapshot)
# ---------------------------------------------------------------------------

def run_periodic_actor_profiling() -> dict:
    """Synchronous actor profiling runner — manages its own DB session.

    Called by the Dramatiq actor and by the background scheduler thread.
    Returns the profiling result dict for logging.
    """
    logger.info("Starting periodic actor profiling")
    try:
        from database import get_session  # type: ignore[import-untyped]
        from services.actor_service import profile_actors  # type: ignore[import-untyped]

        with get_session() as session:
            actor_result = profile_actors(session)
            session.commit()

        logger.info("Periodic actor profiling complete: %s", actor_result)
        return actor_result if actor_result else {"actors_created": 0, "actors_updated": 0}
    except Exception:
        logger.exception("Periodic actor profiling failed")
        return {"actors_created": 0, "actors_updated": 0, "error": True}


_actor_profiling_thread: Optional[_threading.Thread] = None


def _actor_profiling_scheduler_loop() -> None:
    """Daemon thread that periodically enqueues actor profiling messages."""
    _time.sleep(120)  # Initial delay — actors need campaigns to exist first
    while True:
        try:
            if config.USE_DRAMATIQ_PIPELINE:
                actors = _get_actors()
                actors["profile_actors_periodic"].send()
            else:
                run_periodic_actor_profiling()
        except Exception:
            logger.exception("Actor profiling scheduler error; will retry next interval")
        _time.sleep(ACTOR_PROFILING_INTERVAL_S)


def start_periodic_actor_profiling() -> None:
    """Start the background actor profiling scheduler (idempotent).

    Call once at worker startup.  Runs hourly in a daemon thread.
    """
    global _actor_profiling_thread
    if not config.ACTOR_PROFILING_ENABLED:
        logger.info("Actor profiling disabled; skipping periodic actor profiling scheduler.")
        return
    if _actor_profiling_thread is not None and _actor_profiling_thread.is_alive():
        logger.info("Periodic actor profiling scheduler already running; skipping.")
        return

    _actor_profiling_thread = _threading.Thread(
        target=_actor_profiling_scheduler_loop,
        name="vigilwolf-actor-profiling-scheduler",
        daemon=True,
    )
    _actor_profiling_thread.start()
    logger.info("Started periodic actor profiling scheduler (interval=%ds)", ACTOR_PROFILING_INTERVAL_S)


# ---------------------------------------------------------------------------
# Periodic batch clustering (C-2: replaces per-snapshot clustering)
# ---------------------------------------------------------------------------

def run_periodic_batch_clustering() -> dict:
    """Synchronous batch clustering runner — manages its own DB session."""
    logger.info("Starting periodic batch clustering")
    try:
        from database import get_session
        from services.clustering_service import cluster_by_structural_hash, cluster_by_infrastructure

        with get_session() as session:
            struct_result = cluster_by_structural_hash(session)
            session.commit()
        with get_session() as session:
            infra_result = cluster_by_infrastructure(session)
            session.commit()

        logger.info("Periodic batch clustering complete: struct=%s infra=%s", struct_result, infra_result)
        return {"clustering_struct": struct_result, "clustering_infra": infra_result}
    except Exception:
        logger.exception("Periodic batch clustering failed")
        return {"error": True}


_batch_clustering_thread: Optional[_threading.Thread] = None


def _batch_clustering_scheduler_loop() -> None:
    """Daemon thread that periodically enqueues batch clustering messages."""
    _time.sleep(60)
    while True:
        try:
            if config.USE_DRAMATIQ_PIPELINE:
                actors = _get_actors()
                actors["batch_clustering"].send()
            else:
                run_periodic_batch_clustering()
        except Exception:
            logger.exception("Batch clustering scheduler error; will retry next interval")
        _time.sleep(BATCH_CLUSTERING_INTERVAL_S)


def start_periodic_batch_clustering() -> None:
    """Start the background batch clustering scheduler (idempotent)."""
    global _batch_clustering_thread
    if not config.CLUSTERING_ENABLED or not config.BATCH_CLUSTERING_ENABLED:
        logger.info("Batch clustering disabled; skipping scheduler.")
        return
    if _batch_clustering_thread is not None and _batch_clustering_thread.is_alive():
        logger.info("Periodic batch clustering scheduler already running; skipping.")
        return

    _batch_clustering_thread = _threading.Thread(
        target=_batch_clustering_scheduler_loop,
        name="vigilwolf-batch-clustering-scheduler",
        daemon=True,
    )
    _batch_clustering_thread.start()
    logger.info("Started periodic batch clustering scheduler (interval=%ds)", BATCH_CLUSTERING_INTERVAL_S)


# ---------------------------------------------------------------------------
# Periodic batch campaign detection (C-2: replaces per-snapshot campaign)
# ---------------------------------------------------------------------------

def run_periodic_batch_campaign() -> dict:
    """Synchronous batch campaign detection runner — manages its own DB session."""
    logger.info("Starting periodic batch campaign detection")
    try:
        from database import get_session
        from services.campaign_service import detect_campaigns

        with get_session() as session:
            result = detect_campaigns(session)
            session.commit()

        logger.info("Periodic batch campaign detection complete: %s", result)
        return result
    except Exception:
        logger.exception("Periodic batch campaign detection failed")
        return {"error": True}


_batch_campaign_thread: Optional[_threading.Thread] = None


def _batch_campaign_scheduler_loop() -> None:
    """Daemon thread that periodically enqueues batch campaign messages."""
    _time.sleep(90)
    while True:
        try:
            if config.USE_DRAMATIQ_PIPELINE:
                actors = _get_actors()
                actors["batch_campaign"].send()
            else:
                run_periodic_batch_campaign()
        except Exception:
            logger.exception("Batch campaign scheduler error; will retry next interval")
        _time.sleep(BATCH_CAMPAIGN_INTERVAL_S)


def start_periodic_batch_campaign() -> None:
    """Start the background batch campaign scheduler (idempotent)."""
    global _batch_campaign_thread
    if not config.CAMPAIGN_DETECTION_ENABLED or not config.BATCH_CAMPAIGN_ENABLED:
        logger.info("Batch campaign detection disabled; skipping scheduler.")
        return
    if _batch_campaign_thread is not None and _batch_campaign_thread.is_alive():
        logger.info("Periodic batch campaign scheduler already running; skipping.")
        return

    _batch_campaign_thread = _threading.Thread(
        target=_batch_campaign_scheduler_loop,
        name="vigilwolf-batch-campaign-scheduler",
        daemon=True,
    )
    _batch_campaign_thread.start()
    logger.info("Started periodic batch campaign scheduler (interval=%ds)", BATCH_CAMPAIGN_INTERVAL_S)


# ---------------------------------------------------------------------------
# Periodic batch phishkit detection (C-2: replaces per-snapshot phishkit)
# ---------------------------------------------------------------------------

def run_periodic_batch_phishkit() -> dict:
    """Synchronous batch phishkit detection runner — manages its own DB session."""
    logger.info("Starting periodic batch phishkit detection")
    try:
        from database import get_session
        from services.phishkit_service import detect_phishkits

        with get_session() as session:
            result = detect_phishkits(session)
            session.commit()

        logger.info("Periodic batch phishkit detection complete: %s", result)
        return result
    except Exception:
        logger.exception("Periodic batch phishkit detection failed")
        return {"error": True}


_batch_phishkit_thread: Optional[_threading.Thread] = None


def _batch_phishkit_scheduler_loop() -> None:
    """Daemon thread that periodically enqueues batch phishkit messages."""
    _time.sleep(45)
    while True:
        try:
            if config.USE_DRAMATIQ_PIPELINE:
                actors = _get_actors()
                actors["batch_phishkit"].send()
            else:
                run_periodic_batch_phishkit()
        except Exception:
            logger.exception("Batch phishkit scheduler error; will retry next interval")
        _time.sleep(BATCH_PHISHKIT_INTERVAL_S)


def start_periodic_batch_phishkit() -> None:
    """Start the background batch phishkit scheduler (idempotent)."""
    global _batch_phishkit_thread
    if not config.PHISHKIT_DETECTION_ENABLED or not config.BATCH_PHISHKIT_ENABLED:
        logger.info("Batch phishkit detection disabled; skipping scheduler.")
        return
    if _batch_phishkit_thread is not None and _batch_phishkit_thread.is_alive():
        logger.info("Periodic batch phishkit scheduler already running; skipping.")
        return

    _batch_phishkit_thread = _threading.Thread(
        target=_batch_phishkit_scheduler_loop,
        name="vigilwolf-batch-phishkit-scheduler",
        daemon=True,
    )
    _batch_phishkit_thread.start()
    logger.info("Started periodic batch phishkit scheduler (interval=%ds)", BATCH_PHISHKIT_INTERVAL_S)


# ---------------------------------------------------------------------------
# Prometheus helpers (lazy import so tests without prometheus_client work)
# ---------------------------------------------------------------------------

def _get_plugin_timer(plugin_name: str):
    """Return a context-manager that records Histogram timing for a plugin.

    Returns ``None`` when Prometheus is disabled or prometheus_client is not
    installed, so callers can skip the timing block with ``if timer: ...``.
    """
    if not config.ENABLE_PROMETHEUS:
        return None
    try:
        from main import PIPELINE_DURATION
        if PIPELINE_DURATION is None:
            return None
        return PIPELINE_DURATION.labels(plugin_name=plugin_name).time()
    except ImportError:
        return None


def _inc_domains_processed() -> None:
    """Increment the Prometheus counter for processed domains."""
    if not config.ENABLE_PROMETHEUS:
        return
    try:
        from main import PIPELINE_DOMAINS_PROCESSED
        if PIPELINE_DOMAINS_PROCESSED is not None:
            PIPELINE_DOMAINS_PROCESSED.inc()
    except ImportError:
        pass


def _emit_processing_update(snapshot_id: str, domain: str, plugin_name: str, status: str) -> None:
    """Publish a processing_update event to the event bus (fire-and-forget)."""
    try:
        from services.event_bus import event_bus
        event_bus.publish("processing_update", {
            "snapshot_id": snapshot_id,
            "domain": domain,
            "plugin": plugin_name,
            "status": status,
        })
    except Exception:
        logger.exception("Failed to publish processing_update event")


# ---------------------------------------------------------------------------
# build_snapshot_context
# ---------------------------------------------------------------------------

def build_snapshot_context(
    snapshot_id: str,
    domain: str,
    html: str,
    snapshot_record: dict,
) -> SnapshotContext:
    """Parse raw HTML and build a SnapshotContext for the analysis pipeline.

    Extracts visible text, forms (with password/hidden/action/method),
    links, scripts, and metadata (title + meta tags).
    """
    if len(html.encode("utf-8", errors="replace")) > MAX_HTML_SIZE:
        raise ValueError(
            f"HTML too large ({len(html.encode('utf-8', errors='replace'))} bytes) "
            f"for snapshot_id={snapshot_id}; maximum is {MAX_HTML_SIZE} bytes"
        )

    soup = BeautifulSoup(html, "html.parser")

    # --- Visible text ---
    text = soup.get_text(separator=" ", strip=True)

    # --- Forms ---
    forms: list[dict[str, Any]] = []
    for form_el in soup.find_all("form"):
        form_info: dict[str, Any] = {
            "has_password": any(
                inp.get("type", "").lower() == "password"
                for inp in form_el.find_all("input")
            ),
            "has_hidden": any(
                inp.get("type", "").lower() == "hidden"
                for inp in form_el.find_all("input")
            ),
            "action": form_el.get("action", ""),
            "method": (form_el.get("method", "GET") or "GET").upper(),
        }
        forms.append(form_info)

    # --- Links ---
    links = [
        a_tag.get("href", "")
        for a_tag in soup.find_all("a", href=True)
    ]

    # --- Scripts ---
    scripts: list[dict[str, Any]] = []
    for script_el in soup.find_all("script"):
        src = script_el.get("src")
        inline = script_tag_text(script_el)
        entry: dict[str, Any] = {}
        if src:
            entry["src"] = src
        if inline:
            entry["inline"] = inline
        scripts.append(entry)

    # --- Metadata ---
    metadata: dict[str, Any] = {}
    title_el = soup.find("title")
    if title_el and title_el.string:
        metadata["title"] = title_el.string.strip()

    meta_tags: dict[str, str] = {}
    for meta_el in soup.find_all("meta"):
        name = meta_el.get("name") or meta_el.get("property") or meta_el.get("http-equiv")
        content = meta_el.get("content")
        if name and content:
            meta_tags[name] = content
    if meta_tags:
        metadata["meta"] = meta_tags

    return SnapshotContext(
        snapshot_id=snapshot_id,
        domain=domain,
        html=html,
        text=text,
        forms=forms,
        links=links,
        scripts=scripts,
        metadata=metadata,
        snapshot_record=snapshot_record,
    )


def script_tag_text(script_el) -> str:
    """Extract inline script content, or empty string if external."""
    if script_el.get("src"):
        return ""
    return (script_el.string or "").strip()


# ---------------------------------------------------------------------------
# get_registered_plugins
# ---------------------------------------------------------------------------

def get_registered_plugins() -> list[AnalysisPlugin]:
    """Instantiate and return the plugins listed in config.ENABLED_PLUGINS.

    Plugins that are configured as enabled but not found in the registry
    are logged as warnings and skipped.
    """
    enabled = [name.strip() for name in config.ENABLED_PLUGINS if name.strip()]
    plugins: list[AnalysisPlugin] = []

    for name in enabled:
        cls = PLUGIN_REGISTRY.get(name)
        if cls is None:
            logger.warning("Plugin %r listed in ENABLED_PLUGINS but not registered; skipping.", name)
            continue
        plugins.append(cls())

    return plugins


# ---------------------------------------------------------------------------
# capture_domain  (DB-dependent, lazy imports)
# ---------------------------------------------------------------------------

def capture_domain(domain_id: str, url: str, trigger_type: str = "nrd_ingest") -> Optional[str]:
    """Capture HTML for a domain and kick off the analysis pipeline.

    1. Capture HTML via capture_engine
    2. Compute SHA-256
    3. Check for duplicate snapshot (same domain_id + sha256)
    4. Save to storage, create SnapshotModel
    5. Delegate to build_context_and_analyze()

    Returns the snapshot_id on success, None on failure.
    """
    try:
        from plugins.capture_engine import capture_html, validate_capture_url  # type: ignore[import-untyped]
    except ImportError as exc:
        if config.ENVIRONMENT == "production":
            raise RuntimeError("capture_engine module missing in production") from exc
        logger.error("capture_engine module not available; cannot capture domain.")
        return None

    try:
        validate_capture_url(url)
        # Step 1 — Capture HTML
        capture_result = capture_html(url)
        if not capture_result or not capture_result.get("html"):
            logger.error("capture_html returned no HTML for url=%s", url)
            return None
        html = capture_result["html"]

        if len(html.encode("utf-8", errors="replace")) > MAX_HTML_SIZE:
            logger.error("HTML too large (%d bytes) for url=%s; skipping.", len(html.encode("utf-8", errors="replace")), url)
            return None

        # Step 2 — SHA-256
        sha256 = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()

        # Step 3 — Duplicate check & snapshot insert (single session to prevent race)
        from database import get_session, SnapshotModel
        from sqlalchemy.exc import IntegrityError

        snapshot_id = str(uuid.uuid4())

        # Duplicate check + insert in one session (prevents race condition
        # where a concurrent worker inserts the same snapshot between the check and
        # the insert, causing a silent IntegrityError loss). Storage save is
        # deferred until after uniqueness is confirmed to avoid orphaned files.
        with get_session() as session:
            existing = (
                session.query(SnapshotModel)
                .filter_by(domain_id=domain_id, sha256=sha256)
                .first()
            )
            if existing:
                logger.info(
                    "Duplicate snapshot for domain_id=%s sha256=%s; checking analysis.",
                    domain_id, sha256[:12],
                )
                # Re-trigger analysis if the existing snapshot has no risk score
                from database import RiskScoreModel
                has_score = (
                    session.query(RiskScoreModel)
                    .filter(RiskScoreModel.snapshot_id == existing.id)
                    .first()
                )
                if not has_score:
                    logger.info(
                        "Duplicate snapshot %s has no risk score; re-triggering analysis.",
                        existing.id,
                    )
                    if config.USE_DRAMATIQ_PIPELINE:
                        actors = _get_actors()
                        actors["build_context_and_analyze"].send(
                            snapshot_id=existing.id,
                            domain_id=domain_id,
                        )
                    else:
                        build_context_and_analyze(
                            snapshot_id=existing.id,
                            domain_id=domain_id,
                        )
                return existing.id

            try:
                with session.begin_nested():
                    snapshot = SnapshotModel(
                        id=snapshot_id,
                        domain_id=domain_id,
                        timestamp=datetime.now(timezone.utc),
                        trigger_type=trigger_type,
                        html_path="",
                        sha256=sha256,
                        size_bytes=len(html.encode("utf-8", errors="replace")),
                        success=True,
                    )
                    session.add(snapshot)
                    session.flush()
            except IntegrityError:
                # Concurrent insert won the race — look up the existing snapshot
                existing = (
                    session.query(SnapshotModel)
                    .filter_by(domain_id=domain_id, sha256=sha256)
                    .first()
                )
                if existing:
                    logger.info(
                        "Race condition: duplicate snapshot for domain_id=%s sha256=%s; checking analysis.",
                        domain_id, sha256[:12],
                    )
                    # Re-trigger analysis if the existing snapshot has no risk score
                    from database import RiskScoreModel
                    has_score = (
                        session.query(RiskScoreModel)
                        .filter(RiskScoreModel.snapshot_id == existing.id)
                        .first()
                    )
                    if not has_score:
                        logger.info(
                            "Duplicate snapshot %s has no risk score; re-triggering analysis.",
                            existing.id,
                        )
                        if config.USE_DRAMATIQ_PIPELINE:
                            actors = _get_actors()
                            actors["build_context_and_analyze"].send(
                                snapshot_id=existing.id,
                                domain_id=domain_id,
                            )
                        else:
                            build_context_and_analyze(
                                snapshot_id=existing.id,
                                domain_id=domain_id,
                            )
                    return existing.id
                raise

            # NOW save to storage (after we know the snapshot is unique)
            try:
                from plugins.storage_manager import save_snapshot as _save_snapshot  # type: ignore[import-untyped]
                save_result = _save_snapshot(
                    domain_id=domain_id,
                    snapshot_id=snapshot_id,
                    html=html,
                )
                html_path = save_result.get("html_path", "") if save_result else ""
            except ImportError:
                if config.ENVIRONMENT == "production":
                    raise RuntimeError("storage_manager module missing in production")
                logger.warning("storage_manager not available; marking snapshot as incomplete.")
                snapshot.success = False
                snapshot.error_message = "storage_manager not available in development"
                html_path = ""

            if config.ENVIRONMENT == "production" and not html_path:
                raise RuntimeError("storage_manager returned empty html_path in production")

            # Update snapshot html_path
            snapshot.html_path = html_path
            session.commit()

        # Step 5 — Build context and analyze (sync or Dramatiq)
        if config.USE_DRAMATIQ_PIPELINE:
            actors = _get_actors()
            actors["build_context_and_analyze"].send(
                snapshot_id=snapshot_id,
                domain_id=domain_id,
            )
        else:
            build_context_and_analyze(
                snapshot_id=snapshot_id,
                domain_id=domain_id,
            )

        return snapshot_id

    except Exception:
        logger.exception("capture_domain failed for url=%s", url)
        return None


# ---------------------------------------------------------------------------
# build_context_and_analyze  (DB-dependent, lazy imports)
# ---------------------------------------------------------------------------

def build_context_and_analyze(
    snapshot_id: str,
    domain_id: str,
) -> None:
    """Build a SnapshotContext and run the full analysis pipeline.

    Loads HTML from storage and the domain URL from the database so that
    Dramatiq messages only need to carry ``snapshot_id`` and ``domain_id``
    — never the (potentially large) HTML payload.
    """
    from database import get_session, SnapshotModel, DomainModel

    # Look up the snapshot and domain to get the URL and html_path.
    with get_session() as session:
        snapshot = session.query(SnapshotModel).filter_by(id=snapshot_id).first()
        if snapshot is None:
            logger.error("Snapshot %s not found; aborting analysis.", snapshot_id)
            return
        domain_obj = session.query(DomainModel).filter_by(id=domain_id).first()
        if domain_obj is None:
            logger.error("Domain %s not found; aborting analysis for snapshot %s.", domain_id, snapshot_id)
            return
        url = domain_obj.url
        snapshot_record = {"id": snapshot_id, "domain_id": domain_id}

    # Load HTML from storage.
    html = ""
    html_load_failed = False
    try:
        from plugins.storage_manager import load_snapshot as _load_snapshot  # type: ignore[import-untyped]
        loaded = _load_snapshot(domain_id=domain_id, snapshot_id=snapshot_id)
        html = loaded.get("html", "") if loaded else ""
    except ImportError:
        logger.warning("storage_manager not available; cannot load HTML for snapshot %s", snapshot_id)
        html_load_failed = True
    except Exception:
        logger.exception("Failed to load HTML from storage for snapshot %s", snapshot_id)
        html_load_failed = True

    if not html:
        logger.error("No HTML available for snapshot_id=%s; aborting analysis.", snapshot_id)
        # Mark all pending plugin statuses as "failed" so the pipeline
        # doesn't appear stuck in "pending" indefinitely.
        try:
            from database import SnapshotPluginStatusModel, get_session
            with get_session() as fail_session:
                pending = (
                    fail_session.query(SnapshotPluginStatusModel)
                    .filter_by(snapshot_id=snapshot_id, status="pending")
                    .all()
                )
                for row in pending:
                    row.status = "failed"
                    row.error_message = "HTML load failed — no content available for analysis"
                    row.completed_at = datetime.now(timezone.utc)
                fail_session.commit()
        except Exception:
            logger.exception("Failed to update plugin statuses for snapshot_id=%s", snapshot_id)
        return

    # Extract domain from URL for the context
    parsed = urlparse(url)
    domain = parsed.netloc or url

    ctx = build_snapshot_context(
        snapshot_id=snapshot_id,
        domain=domain,
        html=html,
        snapshot_record=snapshot_record,
    )

    orchestrate_analysis(ctx)


# ---------------------------------------------------------------------------
# orchestrate_analysis  (DB-dependent, lazy imports)
# ---------------------------------------------------------------------------

def orchestrate_analysis(ctx: SnapshotContext) -> None:
    """Run all enabled plugins grouped by execution order, then aggregate.

    For each execution group, run every plugin sequentially (Phase 1).
    Skip plugins that the circuit breaker rejects.
    """
    _start = _time.time()

    from database import get_session, SnapshotPluginStatusModel, AnalysisResultModel

    try:
        execution_groups = get_execution_groups()
        plugins_by_name = {p.name: p for p in get_registered_plugins()}
        all_results: list[PluginResult] = []

        # Create pending status rows for every enabled plugin
        with get_session() as session:
            for group in execution_groups:
                for plugin_name, _priority in group.plugins:
                    existing = (
                        session.query(SnapshotPluginStatusModel)
                        .filter_by(snapshot_id=ctx.snapshot_id, plugin_name=plugin_name)
                        .first()
                    )
                    if existing is None:
                        status_row = SnapshotPluginStatusModel(
                            snapshot_id=ctx.snapshot_id,
                            plugin_name=plugin_name,
                            status="pending",
                        )
                        session.add(status_row)
            session.commit()

        # Run each group sequentially
        for group in execution_groups:
            for plugin_name, _priority in group.plugins:
                plugin = plugins_by_name.get(plugin_name)
                if plugin is None:
                    logger.warning("Plugin %r not found in registry; skipping.", plugin_name)
                    continue

                # Check circuit breaker
                if not circuit_breaker.should_run(plugin_name, plugin.plugin_type, queue_depth=pipeline_metrics.queue_depth):
                    logger.info("Circuit breaker skipping plugin %r.", plugin_name)
                    continue

                # Update status -> running
                with get_session() as session:
                    status_row = (
                        session.query(SnapshotPluginStatusModel)
                        .filter_by(snapshot_id=ctx.snapshot_id, plugin_name=plugin_name)
                        .first()
                    )
                    if status_row:
                        status_row.status = "running"
                        status_row.started_at = datetime.now(timezone.utc)
                        session.commit()

                # Publish processing_update event for SSE streaming
                _emit_processing_update(ctx.snapshot_id, ctx.domain, plugin_name, "running")

                # Run the plugin with Prometheus timing
                _timer = _get_plugin_timer(plugin_name)
                try:
                    if _timer is not None:
                        with _timer:
                            result = plugin.run(ctx)
                    else:
                        result = plugin.run(ctx)
                    all_results.append(result)

                    # Inject enrichment findings into context for downstream plugins
                    if result.plugin_name == "whois_enricher" and result.findings:
                        if "registrar" in result.findings:
                            ctx.metadata["registrar"] = result.findings["registrar"]
                            # Persist registrar to DomainModel
                            try:
                                from database import get_session as _gs, DomainModel as _DM  # type: ignore[import-untyped]
                                with _gs() as reg_session:
                                    domain_obj = reg_session.query(_DM).filter_by(id=ctx.snapshot_record.get("domain_id")).first()
                                    if domain_obj is not None and not domain_obj.registrar:
                                        domain_obj.registrar = result.findings["registrar"]
                                        reg_session.commit()
                            except Exception:
                                logger.debug("Failed to persist registrar for domain_id=%s", ctx.snapshot_record.get("domain_id", "")[:8])
                        if "creation_date" in result.findings:
                            ctx.metadata["creation_date"] = result.findings["creation_date"]
                        # Also update snapshot_record for scoring modifiers
                        ctx.snapshot_record["registrar"] = result.findings.get("registrar", "")
                    elif result.plugin_name == "dns_enricher" and result.findings:
                        ctx.metadata["dns_records"] = result.findings

                    # Store AnalysisResultModel (idempotent on retry)
                    with get_session() as session:
                        existing_result = (
                            session.query(AnalysisResultModel)
                            .filter_by(snapshot_id=ctx.snapshot_id, plugin_name=result.plugin_name)
                            .first()
                        )
                        if existing_result is not None:
                            logger.debug(
                                "AnalysisResultModel already exists for snapshot_id=%s plugin=%s; skipping insert",
                                ctx.snapshot_id, result.plugin_name,
                            )
                        else:
                            analysis_row = AnalysisResultModel(
                                snapshot_id=ctx.snapshot_id,
                                plugin_name=result.plugin_name,
                                plugin_version=result.plugin_version,
                                plugin_type=result.plugin_type.value,
                                result_json={
                                    "tags": result.tags,
                                    "findings": result.findings,
                                    "error": result.error,
                                },
                                score_contribution=result.score_contribution,
                                confidence=result.confidence,
                                tags=result.tags,
                            )
                            session.add(analysis_row)
                        session.commit()

                    # Update status -> done
                    with get_session() as session:
                        status_row = (
                            session.query(SnapshotPluginStatusModel)
                            .filter_by(snapshot_id=ctx.snapshot_id, plugin_name=plugin_name)
                            .first()
                        )
                        if status_row:
                            status_row.status = "done"
                            status_row.completed_at = datetime.now(timezone.utc)
                            session.commit()

                    # Publish processing_update event for SSE streaming
                    _emit_processing_update(ctx.snapshot_id, ctx.domain, plugin_name, "done")

                except Exception:
                    logger.exception("Plugin %r failed for snapshot_id=%s", plugin_name, ctx.snapshot_id)

                    # Update status -> failed
                    try:
                        with get_session() as session:
                            status_row = (
                                session.query(SnapshotPluginStatusModel)
                                .filter_by(snapshot_id=ctx.snapshot_id, plugin_name=plugin_name)
                                .first()
                            )
                            if status_row:
                                status_row.status = "failed"
                                status_row.completed_at = datetime.now(timezone.utc)
                                status_row.error_message = "Plugin execution error"
                                session.commit()
                    except Exception:
                        logger.exception("Failed to update plugin status for %r", plugin_name)

                    # Publish processing_update event for SSE streaming
                    _emit_processing_update(ctx.snapshot_id, ctx.domain, plugin_name, "failed")

        # Aggregate results and score
        scoring_failed = False
        try:
            aggregate_results(ctx, all_results)
        except Exception:
            scoring_failed = True
            logger.exception("Scoring failed for snapshot_id=%s; continuing with IOC persist + intelligence pipeline", ctx.snapshot_id)

        # Persist IOC extraction results if ioc_extractor ran successfully
        # This runs regardless of scoring success — IOC data is needed by
        # downstream intelligence services (clustering, campaigns).
        ioc_results = [r for r in all_results if r.plugin_name == "ioc_extractor" and not r.error]
        ioc_persisted = False
        if ioc_results:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    from services.ioc_service import persist_iocs
                    with get_session() as ioc_session:
                        for ioc_result in ioc_results:
                            persist_iocs(
                                snapshot_id=ctx.snapshot_id,
                                findings=ioc_result.findings,
                                session=ioc_session,
                            )
                        ioc_session.commit()
                        logger.info("Persisted IOC results for snapshot_id=%s", ctx.snapshot_id)
                        ioc_persisted = True
                        break
                except Exception:
                    if attempt < max_retries - 1:
                        _time.sleep(1 + attempt)  # 1s, 2s, 3s backoff
                        logger.warning("IOC persistence attempt %d failed for snapshot_id=%s; retrying", attempt + 1, ctx.snapshot_id)
                    else:
                        logger.exception("Failed to persist IOCs for snapshot_id=%s after %d attempts", ctx.snapshot_id, max_retries)

        # Increment Prometheus counter for domains processed
        _inc_domains_processed()

        # Always enqueue the intelligence pipeline when enabled.
        # Even if IOC persistence failed, clustering and phishkit detection
        # can still run (they depend on html_hasher results, not IOC data).
        # Campaign detection and actor profiling will produce partial results
        # without IOC data, but this is better than skipping them entirely.
        # A reconciliation pass can recover missed IOC data later.
        if config.INTELLIGENCE_PIPELINE_ENABLED:
            try:
                from intelligence_worker import enqueue_intelligence_pipeline
                enqueue_intelligence_pipeline(ctx.snapshot_id)
            except Exception:
                logger.exception("Failed to enqueue intelligence pipeline for snapshot_id=%s", ctx.snapshot_id)

        # If IOC persistence failed but we have IOC results, log a warning
        # so the reconciliation service can pick them up later.
        if ioc_results and not ioc_persisted:
            logger.warning(
                "IOC persistence failed for snapshot_id=%s; intelligence pipeline enqueued without IOC data. "
                "Reconciliation will attempt to recover.",
                ctx.snapshot_id,
            )

        # Record pipeline success/failure metric
        if scoring_failed:
            pipeline_metrics.record_failure()
        else:
            pipeline_metrics.record_success(_time.time() - _start)

    except Exception:
        pipeline_metrics.record_failure()
        raise


# ---------------------------------------------------------------------------
# aggregate_results  (DB-dependent, lazy imports)
# ---------------------------------------------------------------------------

def aggregate_results(ctx: SnapshotContext, results: list[PluginResult]) -> dict:
    """Load weights, calculate the risk score, persist RiskScoreModel, and
    dispatch an alert if high risk.

    Returns the score outcome dict.
    """
    from database import get_session, PluginWeightModel, RiskScoreModel

    # Load weights from DB, fall back to defaults
    weights: dict[str, float] = DEFAULT_WEIGHTS.copy()
    try:
        with get_session() as session:
            rows = session.query(PluginWeightModel).all()
            if rows:
                weights = {row.plugin_name: row.weight for row in rows}
                logger.info("Loaded %d plugin weights from DB.", len(rows))
    except Exception:
        logger.warning("Could not load plugin weights from DB; using defaults.")

    score_outcome = calculate_score(results, weights)

    # Apply context-aware scoring modifiers (before hard signal re-check)
    mod_result = apply_context_modifiers(
        score_outcome["score"], ctx, score_outcome.get("reasons", [])
    )
    score_outcome["score"] = mod_result["score"]
    score_outcome["risk_level"] = mod_result["risk_level"]
    score_outcome["severity"] = mod_result["severity"]
    score_outcome["reasons"].extend(mod_result["modifier_reasons"])

    # Hard signal overrides context modifiers
    if score_outcome.get("hard_signal"):
        score_outcome["severity"] = "critical"
        score_outcome["risk_level"] = "high"

    # Persist RiskScoreModel (savepoint isolates the insert so an
    # IntegrityError doesn't lose the entire session state)
    with get_session() as session:
        try:
            with session.begin_nested():
                risk_score = RiskScoreModel(
                    snapshot_id=ctx.snapshot_id,
                    total_score=score_outcome["score"],
                    normalized_score=score_outcome["normalized_score"],
                    risk_level=score_outcome["risk_level"],
                    severity=score_outcome["severity"],
                    reasons=score_outcome["reasons"],
                    dominant_signals=score_outcome["dominant_signals"],
                    plugin_breakdown=score_outcome["plugin_breakdown"],
                    overall_confidence=score_outcome["overall_confidence"],
                )
                session.add(risk_score)
                session.flush()
        except Exception:
            logger.exception("Failed to persist RiskScoreModel for snapshot_id=%s", ctx.snapshot_id)
        else:
            session.commit()

    # Publish threat_detected event for SSE streaming
    if score_outcome["risk_level"] in ("high", "medium"):
        try:
            from services.event_bus import event_bus
            event_bus.publish("threat_detected", {
                "snapshot_id": ctx.snapshot_id,
                "domain": ctx.domain,
                "risk_level": score_outcome["risk_level"],
                "severity": score_outcome.get("severity", ""),
                "score": score_outcome["score"],
                "dominant_signals": score_outcome.get("dominant_signals", []),
            })
        except Exception:
            logger.exception("Failed to publish threat_detected event")

    # Alert dispatch
    if score_outcome["risk_level"] in ("high", "medium") and config.ALERTS_ENABLED:
        dispatch_alert(ctx, score_outcome)

    return score_outcome


# ---------------------------------------------------------------------------
# dispatch_alert  (may depend on AlertService, not yet implemented)
# ---------------------------------------------------------------------------

def dispatch_alert(ctx: SnapshotContext, score_outcome: dict) -> None:
    """Dispatch an alert for a high-risk snapshot.

    If ALERTS_DRY_RUN is true, log a dry-run message and return.
    Otherwise, delegate to AlertService.send_alert().
    """
    if config.ALERTS_DRY_RUN:
        logger.info(
            "[DRY RUN] Would dispatch alert for snapshot_id=%s risk_level=%s score=%s",
            ctx.snapshot_id, score_outcome["risk_level"], score_outcome["score"],
        )
        return

    try:
        from database import get_session  # type: ignore[import-untyped]
        from services.alert_service import AlertService  # type: ignore[import-untyped]
        alert_service = AlertService()
        with get_session() as session:
            alert_service.send_alert(ctx, score_outcome, session)

        # Publish alert_dispatched event for SSE streaming
        try:
            from services.event_bus import event_bus
            event_bus.publish("alert_dispatched", {
                "snapshot_id": ctx.snapshot_id,
                "domain": ctx.domain,
                "risk_level": score_outcome["risk_level"],
                "severity": score_outcome["severity"],
            })
        except Exception:
            logger.exception("Failed to publish alert_dispatched event")

    except ImportError:
        logger.warning("AlertService not available; skipping alert dispatch.")
    except Exception:
        logger.exception("Failed to dispatch alert for snapshot_id=%s", ctx.snapshot_id)


# ---------------------------------------------------------------------------
# Public entry point — chooses sync vs Dramatiq path
# ---------------------------------------------------------------------------

def enqueue_capture(domain_id: str, url: str, trigger_type: str = "nrd_ingest") -> Optional[str]:
    """Entry point for the analysis pipeline.

    When USE_DRAMATIQ_PIPELINE is True, enqueues a Dramatiq message and
    returns None immediately (processing is async). When False (default),
    runs capture_domain synchronously and returns the snapshot_id.
    """
    if config.USE_DRAMATIQ_PIPELINE:
        actors = _get_actors()
        actors["capture_domain"].send(domain_id=domain_id, url=url, trigger_type=trigger_type)
        logger.info("Enqueued Dramatiq capture for domain_id=%s url=%s", domain_id, url)
        # Queue depth not directly exposed by Dramatiq; placeholder
        pipeline_metrics.set_queue_depth(0)
        return None
    return capture_domain(domain_id=domain_id, url=url, trigger_type=trigger_type)