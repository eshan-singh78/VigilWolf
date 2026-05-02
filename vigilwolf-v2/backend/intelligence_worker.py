"""VigilWolf v2 — Intelligence Pipeline Worker.

Orchestrates the Phase 2/3 intelligence pipeline after domain scoring completes:
  clustering -> campaign detection -> phishkit detection -> C2 detection -> actor profiling

Each step is gated by its feature flag and runs independently — a failure in one
step does not prevent subsequent steps from executing.  When
USE_DRAMATIQ_PIPELINE is enabled, the pipeline is dispatched as a Dramatiq
actor; otherwise it runs synchronously in-process.
"""
from __future__ import annotations

import logging
import time as _time
from typing import Any, Optional

import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dramatiq actor (lazily initialised)
# ---------------------------------------------------------------------------

_intelligence_actor = None


def _get_intelligence_actor():
    """Return (and lazily create) the Dramatiq actor for the intelligence pipeline."""
    global _intelligence_actor
    if _intelligence_actor is not None:
        return _intelligence_actor

    import dramatiq
    from worker import _get_broker

    broker = _get_broker()

    @dramatiq.actor(broker=broker, max_retries=3, max_age=3600000, time_limit=300000)
    def run_intelligence_pipeline_actor(snapshot_id: str) -> None:
        run_intelligence_pipeline(snapshot_id)

    _intelligence_actor = run_intelligence_pipeline_actor
    return _intelligence_actor


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------


def run_intelligence_pipeline(snapshot_id: str) -> Optional[dict]:
    """Execute the intelligence pipeline for a single snapshot.

    Chains five stages, each gated by its feature flag:
      1. Clustering          (CLUSTERING_ENABLED)
      2. Campaign detection  (CAMPAIGN_DETECTION_ENABLED)
      3. PhishKit detection  (PHISHKIT_DETECTION_ENABLED)
      4. C2 detection        (C2_DETECTION_ENABLED)
      5. Actor profiling     (ACTOR_PROFILING_ENABLED)

    Each stage catches its own exceptions and logs them without aborting the
    remaining stages.  On completion (whether all stages ran or not), an
    ``intelligence_update`` event is published to the event bus.

    Args:
        snapshot_id: The snapshot that triggered this pipeline run.

    Returns:
        Dict with results from each stage that ran, or None if the
        intelligence pipeline is disabled.
    """
    if not config.INTELLIGENCE_PIPELINE_ENABLED:
        logger.debug(
            "Intelligence pipeline disabled; skipping for snapshot_id=%s",
            snapshot_id,
        )
        return None

    _start = _time.time()
    results: dict[str, Any] = {
        "snapshot_id": snapshot_id,
        "stages": {},
    }

    # Reconcile orphaned plugin statuses from crashed pipelines
    try:
        from database import get_session  # type: ignore[import-untyped]
        from services.reconciliation_service import reconcile_orphaned_statuses  # type: ignore[import-untyped]

        with get_session() as recon_session:
            recon_result = reconcile_orphaned_statuses(recon_session)
            recon_session.commit()
        if recon_result.get("reconciled_running", 0) > 0 or recon_result.get("reconciled_pending", 0) > 0:
            logger.info(
                "Reconciled orphaned statuses: %s", recon_result,
            )
    except Exception:
        logger.exception("Failed to reconcile orphaned plugin statuses")

    logger.info("Starting intelligence pipeline for snapshot_id=%s", snapshot_id)

    # --- Stage 1: Clustering ---
    if config.CLUSTERING_ENABLED:
        try:
            from services.clustering_service import cluster_snapshot  # type: ignore[import-untyped]

            cluster_count = cluster_snapshot(snapshot_id)
            results["stages"]["clustering"] = {"clusters_created_or_updated": cluster_count}

            logger.info(
                "Clustering complete for snapshot_id=%s: %d clusters created/updated",
                snapshot_id, cluster_count,
            )
        except Exception:
            logger.exception(
                "Clustering failed for snapshot_id=%s; continuing.", snapshot_id,
            )
            results["stages"]["clustering"] = {"error": True}
    else:
        logger.debug("Clustering disabled; skipping for snapshot_id=%s", snapshot_id)

    # --- Stage 2: Campaign detection ---
    if config.CAMPAIGN_DETECTION_ENABLED:
        try:
            from services.campaign_service import detect_campaigns_for_snapshot  # type: ignore[import-untyped]

            campaign_count = detect_campaigns_for_snapshot(snapshot_id)
            results["stages"]["campaign_detection"] = {"campaigns_created_or_updated": campaign_count}

            logger.info(
                "Campaign detection complete for snapshot_id=%s: %d campaigns created/updated",
                snapshot_id, campaign_count,
            )
        except Exception:
            logger.exception(
                "Campaign detection failed for snapshot_id=%s; continuing.",
                snapshot_id,
            )
            results["stages"]["campaign_detection"] = {"error": True}
    else:
        logger.debug(
            "Campaign detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    # --- Stage 3: PhishKit detection ---
    if config.PHISHKIT_DETECTION_ENABLED:
        try:
            from services.phishkit_service import detect_phishkits_for_snapshot  # type: ignore[import-untyped]

            phishkit_count = detect_phishkits_for_snapshot(snapshot_id)
            results["stages"]["phishkit_detection"] = {"phishkits_created_or_updated": phishkit_count}

            logger.info(
                "PhishKit detection complete for snapshot_id=%s: %d phishkits created/updated",
                snapshot_id, phishkit_count,
            )
        except Exception:
            logger.exception(
                "PhishKit detection failed for snapshot_id=%s; continuing.",
                snapshot_id,
            )
            results["stages"]["phishkit_detection"] = {"error": True}
    else:
        logger.debug(
            "PhishKit detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    # --- Stage 4: C2 detection ---
    if config.C2_DETECTION_ENABLED:
        try:
            from database import get_session, C2CandidateModel  # type: ignore[import-untyped]
            from services.c2_service import rank_c2_candidates  # type: ignore[import-untyped]

            with get_session() as session:
                c2_result = rank_c2_candidates(session)
                if c2_result:
                    # Persist top C2 candidates
                    for candidate in c2_result:
                        try:
                            with session.begin_nested():
                                c2_row = C2CandidateModel(
                                    ioc_id=candidate["ioc_id"],
                                    snapshot_id=snapshot_id,
                                    c2_score=candidate["c2_score"],
                                    signals=candidate.get("signals", []),
                                )
                                session.add(c2_row)
                                session.flush()
                        except Exception:
                            logger.debug("C2 candidate already exists for ioc_id=%d", candidate["ioc_id"])
                    session.commit()
            results["stages"]["c2_detection"] = {
                "candidates_found": len(c2_result) if c2_result else 0,
            }

            logger.info(
                "C2 detection complete for snapshot_id=%s: %d candidates",
                snapshot_id, len(c2_result) if c2_result else 0,
            )
        except Exception:
            logger.exception(
                "C2 detection failed for snapshot_id=%s; continuing.",
                snapshot_id,
            )
            results["stages"]["c2_detection"] = {"error": True}
    else:
        logger.debug(
            "C2 detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    # --- Stage 5: Actor profiling ---
    if config.ACTOR_PROFILING_ENABLED:
        try:
            from database import get_session  # type: ignore[import-untyped]
            from services.actor_service import profile_actors  # type: ignore[import-untyped]

            with get_session() as session:
                actor_result = profile_actors(session)
                session.commit()
            results["stages"]["actor_profiling"] = actor_result

            logger.info(
                "Actor profiling complete for snapshot_id=%s: %s",
                snapshot_id, actor_result,
            )
        except Exception:
            logger.exception(
                "Actor profiling failed for snapshot_id=%s; continuing.",
                snapshot_id,
            )
            results["stages"]["actor_profiling"] = {"error": True}
    else:
        logger.debug(
            "Actor profiling disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    elapsed = _time.time() - _start
    results["elapsed_s"] = round(elapsed, 4)

    logger.info(
        "Intelligence pipeline finished for snapshot_id=%s in %.2fs (stages: %s)",
        snapshot_id,
        elapsed,
        list(results["stages"].keys()),
    )

    # Publish intelligence_update event
    _emit_intelligence_update(snapshot_id, results)

    return results


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def _emit_intelligence_update(snapshot_id: str, results: dict) -> None:
    """Publish an intelligence_update event to the event bus (fire-and-forget)."""
    try:
        from services.event_bus import event_bus

        # Summarise stage outcomes for SSE consumers.
        stage_summary = {}
        for stage_name, stage_result in results.get("stages", {}).items():
            if isinstance(stage_result, dict) and stage_result.get("error"):
                stage_summary[stage_name] = "error"
            else:
                stage_summary[stage_name] = "done"

        event_bus.publish("intelligence_update", {
            "snapshot_id": snapshot_id,
            "stages": stage_summary,
            "elapsed_s": results.get("elapsed_s", 0),
        })
    except Exception:
        logger.exception("Failed to publish intelligence_update event")


# ---------------------------------------------------------------------------
# Public entry point — sync vs Dramatiq dispatch
# ---------------------------------------------------------------------------


def enqueue_intelligence_pipeline(snapshot_id: str) -> None:
    """Enqueue or run the intelligence pipeline for a snapshot.

    When USE_DRAMATIQ_PIPELINE is True, dispatches the pipeline as a Dramatiq
    actor (asynchronous).  When False (default), runs synchronously in-process.

    When INTELLIGENCE_PIPELINE_ENABLED is False, returns immediately without
    doing anything.

    Args:
        snapshot_id: The snapshot that triggered this pipeline run.
    """
    if not config.INTELLIGENCE_PIPELINE_ENABLED:
        logger.debug(
            "Intelligence pipeline disabled; skipping enqueue for snapshot_id=%s",
            snapshot_id,
        )
        return

    if config.USE_DRAMATIQ_PIPELINE:
        actor = _get_intelligence_actor()
        actor.send(snapshot_id=snapshot_id)
        logger.info(
            "Enqueued Dramatiq intelligence pipeline for snapshot_id=%s",
            snapshot_id,
        )
    else:
        run_intelligence_pipeline(snapshot_id)