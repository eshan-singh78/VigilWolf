"""VigilWolf v2 — Intelligence Pipeline Worker.

Orchestrates the per-snapshot intelligence pipeline after domain scoring completes:
  clustering -> campaign detection -> phishkit detection

C2 detection and actor profiling run as hourly batch jobs (see worker.py) and
are no longer per-snapshot stages. Each step is gated by its feature flag and
runs independently — a failure in one step does not prevent subsequent steps
from executing. When USE_DRAMATIQ_PIPELINE is enabled, the pipeline is dispatched
as a Dramatiq actor; otherwise it runs synchronously in-process.
"""
from __future__ import annotations

import logging
import time as _time
from typing import Any, Optional

import config

logger = logging.getLogger(__name__)

# Stage names used for status tracking
STAGE_CLUSTERING = "clustering"
STAGE_CAMPAIGN = "campaign_detection"
STAGE_PHISHKIT = "phishkit_detection"


def _record_stage_status(
    snapshot_id: str,
    stage: str,
    status: str,
    error_message: str | None = None,
) -> None:
    """Record the completion status of an intelligence pipeline stage.

    Persists to IntelligencePipelineStatusModel for monitoring and retry.
    Failures are logged but never raise — this is a best-effort recording.
    """
    try:
        from database import IntelligencePipelineStatusModel, get_session  # type: ignore[import-untyped]
        from datetime import datetime, timezone

        with get_session() as session:
            # Upsert: if a row already exists for this snapshot+stage, update it
            existing = (
                session.query(IntelligencePipelineStatusModel)
                .filter(
                    IntelligencePipelineStatusModel.snapshot_id == snapshot_id,
                    IntelligencePipelineStatusModel.stage == stage,
                )
                .first()
            )
            if existing is not None:
                existing.status = status
                existing.error_message = error_message
                existing.started_at = existing.started_at or datetime.now(timezone.utc)
                existing.completed_at = datetime.now(timezone.utc)
            else:
                row = IntelligencePipelineStatusModel(
                    snapshot_id=snapshot_id,
                    stage=stage,
                    status=status,
                    error_message=error_message,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                )
                session.add(row)
            session.commit()
    except Exception:
        logger.debug("Failed to record pipeline status for %s/%s", snapshot_id, stage)


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

    Records queued status for each intelligence stage and emits an
    intelligence_update event. The actual batch processing is handled by
    periodic schedulers in worker.py (C-2 fix).

    C2 detection and actor profiling are handled by hourly batch schedulers
    (see worker.py) and are not part of this per-snapshot pipeline.

    Args:
        snapshot_id: The snapshot that triggered this pipeline run.

    Returns:
        Dict with snapshot_id and stages dict, or None if the
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

    logger.info("Recording queued status for snapshot_id=%s", snapshot_id)

    # --- Stage 1: Clustering ---
    if config.CLUSTERING_ENABLED:
        if config.BATCH_CLUSTERING_ENABLED:
            _record_stage_status(snapshot_id, STAGE_CLUSTERING, "queued")
            results["stages"]["clustering"] = {"queued": True}
            logger.info(
                "Clustering queued for snapshot_id=%s (batch scheduler will process)",
                snapshot_id,
            )
        else:
            # Legacy per-snapshot path (disabled by default)
            try:
                from services.clustering_service import cluster_snapshot

                cluster_count = cluster_snapshot(snapshot_id)
                results["stages"]["clustering"] = {"clusters_created_or_updated": cluster_count}
                _record_stage_status(snapshot_id, STAGE_CLUSTERING, "done")
            except Exception:
                logger.exception("Clustering failed for snapshot_id=%s; continuing.", snapshot_id)
                results["stages"]["clustering"] = {"error": True}
                _record_stage_status(snapshot_id, STAGE_CLUSTERING, "error", "Clustering stage failed")
    else:
        logger.debug("Clustering disabled; skipping for snapshot_id=%s", snapshot_id)
        _record_stage_status(snapshot_id, STAGE_CLUSTERING, "skipped")

    # --- Stage 2: Campaign detection ---
    if config.CAMPAIGN_DETECTION_ENABLED:
        if config.BATCH_CAMPAIGN_ENABLED:
            _record_stage_status(snapshot_id, STAGE_CAMPAIGN, "queued")
            results["stages"]["campaign_detection"] = {"queued": True}
            logger.info(
                "Campaign detection queued for snapshot_id=%s (batch scheduler will process)",
                snapshot_id,
            )
        else:
            try:
                from services.campaign_service import detect_campaigns_for_snapshot

                campaign_count = detect_campaigns_for_snapshot(snapshot_id)
                results["stages"]["campaign_detection"] = {"campaigns_created_or_updated": campaign_count}
                _record_stage_status(snapshot_id, STAGE_CAMPAIGN, "done")
            except Exception:
                logger.exception("Campaign detection failed for snapshot_id=%s; continuing.", snapshot_id)
                results["stages"]["campaign_detection"] = {"error": True}
                _record_stage_status(snapshot_id, STAGE_CAMPAIGN, "error", "Campaign detection stage failed")
    else:
        logger.debug(
            "Campaign detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )
        _record_stage_status(snapshot_id, STAGE_CAMPAIGN, "skipped")

    # --- Stage 3: PhishKit detection ---
    if config.PHISHKIT_DETECTION_ENABLED:
        if config.BATCH_PHISHKIT_ENABLED:
            _record_stage_status(snapshot_id, STAGE_PHISHKIT, "queued")
            results["stages"]["phishkit_detection"] = {"queued": True}
            logger.info(
                "PhishKit detection queued for snapshot_id=%s (batch scheduler will process)",
                snapshot_id,
            )
        else:
            try:
                from services.phishkit_service import detect_phishkits_for_snapshot

                phishkit_count = detect_phishkits_for_snapshot(snapshot_id)
                results["stages"]["phishkit_detection"] = {"phishkits_created_or_updated": phishkit_count}
                _record_stage_status(snapshot_id, STAGE_PHISHKIT, "done")
            except Exception:
                logger.exception("PhishKit detection failed for snapshot_id=%s; continuing.", snapshot_id)
                results["stages"]["phishkit_detection"] = {"error": True}
                _record_stage_status(snapshot_id, STAGE_PHISHKIT, "error", "PhishKit detection stage failed")
    else:
        logger.debug(
            "PhishKit detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )
        _record_stage_status(snapshot_id, STAGE_PHISHKIT, "skipped")

    elapsed = _time.time() - _start
    results["elapsed_s"] = round(elapsed, 4)

    logger.info(
        "Intelligence pipeline queued for snapshot_id=%s in %.2fs (stages: %s)",
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
            elif isinstance(stage_result, dict) and stage_result.get("queued"):
                stage_summary[stage_name] = "queued"
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