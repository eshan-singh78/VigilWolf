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
from datetime import datetime, timezone
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
# Stage status helpers
# ---------------------------------------------------------------------------


def _record_stage_status(
    snapshot_id: str,
    stage: str,
    status: str,
    error_message: str | None = None,
) -> None:
    """Record or update the intelligence pipeline stage status for a snapshot.

    Uses ``session.merge()`` so that retries and re-runs update the existing
    row rather than failing on the unique constraint.
    """
    from database import get_session, IntelligencePipelineStatusModel  # type: ignore[import-untyped]

    with get_session() as session:
        row = IntelligencePipelineStatusModel(
            snapshot_id=snapshot_id,
            stage=stage,
            status=status,
            started_at=datetime.now(timezone.utc) if status in ("running", "queued") else None,
            completed_at=datetime.now(timezone.utc) if status in ("done", "failed") else None,
            error_message=error_message,
        )
        # Find existing row to preserve started_at if transitioning to done/failed
        existing = (
            session.query(IntelligencePipelineStatusModel)
            .filter_by(snapshot_id=snapshot_id, stage=stage)
            .first()
        )
        if existing:
            existing.status = status
            if status == "running" and not existing.started_at:
                existing.started_at = datetime.now(timezone.utc)
            if status in ("done", "failed"):
                existing.completed_at = datetime.now(timezone.utc)
            if error_message:
                existing.error_message = error_message
        else:
            # Adjust timestamps based on status
            if status == "running":
                row.started_at = datetime.now(timezone.utc)
                row.completed_at = None
            elif status in ("done", "failed"):
                row.started_at = datetime.now(timezone.utc)
                row.completed_at = datetime.now(timezone.utc)
            session.add(row)
        session.commit()


_STALE_RUNNING_MINUTES = 30


def _stage_already_done(snapshot_id: str, stage: str) -> bool:
    """Check if an intelligence pipeline stage has already completed for this snapshot.

    Returns True if a row exists with status ``done``, meaning the stage
    should be skipped for idempotency.  Also returns True if a row is
    stuck in ``running`` status for longer than ``_STALE_RUNNING_MINUTES``
    (indicating a crashed worker), marking the row as failed so it can
    be retried.
    """
    from database import get_session, IntelligencePipelineStatusModel  # type: ignore[import-untyped]

    with get_session() as session:
        existing = (
            session.query(IntelligencePipelineStatusModel)
            .filter_by(snapshot_id=snapshot_id, stage=stage)
            .first()
        )
        if existing is None:
            return False

        if existing.status == "done":
            return True

        if existing.status in ("running", "queued"):
            # Check for staleness — if a stage has been running for too long,
            # the worker likely crashed. Mark it as failed so it can be retried.
            if existing.started_at is not None:
                age = (datetime.now(timezone.utc) - existing.started_at.replace(tzinfo=timezone.utc) if existing.started_at.tzinfo is None else existing.started_at).total_seconds()
                if age > _STALE_RUNNING_MINUTES * 60:
                    logger.warning(
                        "Stale %s status for snapshot_id=%s stage=%s (age=%.0fs); marking as failed",
                        existing.status, snapshot_id, stage, age,
                    )
                    existing.status = "failed"
                    existing.error_message = f"Stale {existing.status} status after {age:.0f}s"
                    existing.completed_at = datetime.now(timezone.utc)
                    session.commit()
                    return False
            # Still actively running — skip to avoid duplicate processing.
            logger.info(
                "Stage %s is %s for snapshot_id=%s; skipping.",
                stage, existing.status, snapshot_id,
            )
            return True

        # Status is "failed" — allow retry.
        return False


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

    # C-3: Mark the overall pipeline as "running" so dedup guards in
    # orchestrate_analysis can detect in-flight pipelines.
    _record_stage_status(snapshot_id, "pipeline", "running")

    _start = _time.time()
    results: dict[str, Any] = {
        "snapshot_id": snapshot_id,
        "stages": {},
    }

    logger.info("Starting intelligence pipeline for snapshot_id=%s", snapshot_id)

    # --- Stage 1: Clustering ---
    if config.CLUSTERING_ENABLED:
        if _stage_already_done(snapshot_id, "clustering"):
            logger.info("Clustering already done for snapshot_id=%s; skipping.", snapshot_id)
        else:
            try:
                _record_stage_status(snapshot_id, "clustering", "running")
                from services.clustering_service import cluster_snapshot  # type: ignore[import-untyped]

                cluster_count = cluster_snapshot(snapshot_id)
                results["stages"]["clustering"] = {"clusters_created_or_updated": cluster_count}
                _record_stage_status(snapshot_id, "clustering", "done")

                logger.info(
                    "Clustering complete for snapshot_id=%s: %d clusters created/updated",
                    snapshot_id, cluster_count,
                )
            except Exception:
                logger.exception(
                    "Clustering failed for snapshot_id=%s; continuing.", snapshot_id,
                )
                results["stages"]["clustering"] = {"error": True}
                _record_stage_status(snapshot_id, "clustering", "failed", error_message="Clustering stage failed")
    else:
        logger.debug("Clustering disabled; skipping for snapshot_id=%s", snapshot_id)

    # --- Stage 2: Campaign detection ---
    if config.CAMPAIGN_DETECTION_ENABLED:
        if _stage_already_done(snapshot_id, "campaign_detection"):
            logger.info("Campaign detection already done for snapshot_id=%s; skipping.", snapshot_id)
        else:
            try:
                _record_stage_status(snapshot_id, "campaign_detection", "running")
                from services.campaign_service import detect_campaigns_for_snapshot  # type: ignore[import-untyped]

                campaign_count = detect_campaigns_for_snapshot(snapshot_id)
                results["stages"]["campaign_detection"] = {"campaigns_created_or_updated": campaign_count}
                _record_stage_status(snapshot_id, "campaign_detection", "done")

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
                _record_stage_status(snapshot_id, "campaign_detection", "failed", error_message="Campaign detection stage failed")
    else:
        logger.debug(
            "Campaign detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    # --- Stage 3: PhishKit detection ---
    if config.PHISHKIT_DETECTION_ENABLED:
        if _stage_already_done(snapshot_id, "phishkit_detection"):
            logger.info("PhishKit detection already done for snapshot_id=%s; skipping.", snapshot_id)
        else:
            try:
                _record_stage_status(snapshot_id, "phishkit_detection", "running")
                from services.phishkit_service import detect_phishkits_for_snapshot  # type: ignore[import-untyped]

                phishkit_count = detect_phishkits_for_snapshot(snapshot_id)
                results["stages"]["phishkit_detection"] = {"phishkits_created_or_updated": phishkit_count}
                _record_stage_status(snapshot_id, "phishkit_detection", "done")

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
                _record_stage_status(snapshot_id, "phishkit_detection", "failed", error_message="PhishKit detection stage failed")
    else:
        logger.debug(
            "PhishKit detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    # --- Stage 4: C2 detection ---
    if config.C2_DETECTION_ENABLED:
        if _stage_already_done(snapshot_id, "c2_detection"):
            logger.info("C2 detection already done for snapshot_id=%s; skipping.", snapshot_id)
        else:
            try:
                _record_stage_status(snapshot_id, "c2_detection", "running")
                from database import get_session, C2CandidateModel  # type: ignore[import-untyped]
                from sqlalchemy.exc import IntegrityError
                from services.c2_service import rank_c2_candidates  # type: ignore[import-untyped]

                with get_session() as session:
                    c2_result = rank_c2_candidates(session, snapshot_id=snapshot_id)
                    if c2_result:
                        for candidate in c2_result:
                            try:
                                with session.begin_nested():
                                    # Check if this IOC already has a C2 candidate
                                    existing = (
                                        session.query(C2CandidateModel)
                                        .filter(C2CandidateModel.ioc_id == candidate["ioc_id"])
                                        .first()
                                    )
                                    if existing:
                                        # Apply time-based decay to existing score
                                        # before comparing with the new score.
                                        # Decay: halve the score for every 7 days of age.
                                        if existing.last_seen:
                                            age_days = (
                                                datetime.now(timezone.utc)
                                                - (existing.last_seen.replace(tzinfo=timezone.utc) if existing.last_seen.tzinfo is None else existing.last_seen)
                                            ).total_seconds() / 86400
                                            decay_factor = 0.5 ** (age_days / 7.0)
                                            decayed_score = existing.c2_score * decay_factor
                                        else:
                                            decayed_score = existing.c2_score

                                        # Update if new score exceeds decayed old score
                                        if candidate["c2_score"] > decayed_score:
                                            existing.c2_score = candidate["c2_score"]
                                            existing.signals = candidate.get("signals", [])
                                            existing.snapshot_id = snapshot_id
                                        continue
                                    c2_row = C2CandidateModel(
                                        ioc_id=candidate["ioc_id"],
                                        snapshot_id=snapshot_id,
                                        c2_score=candidate["c2_score"],
                                        signals=candidate.get("signals", []),
                                    )
                                    session.add(c2_row)
                                    session.flush()
                            except IntegrityError:
                                logger.debug("C2 candidate already exists for ioc_id=%d", candidate["ioc_id"])
                            except Exception:
                                logger.error(
                                    "Unexpected error inserting C2 candidate for ioc_id=%d",
                                    candidate["ioc_id"],
                                    exc_info=True,
                                )
                                results["stages"]["c2_detection"] = {"error": True}
                        session.commit()
                if "c2_detection" not in results["stages"] or not results["stages"]["c2_detection"].get("error"):
                    results["stages"]["c2_detection"] = {
                        "candidates_found": len(c2_result) if c2_result else 0,
                    }
                _record_stage_status(snapshot_id, "c2_detection", "done")

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
                _record_stage_status(snapshot_id, "c2_detection", "failed", error_message="C2 detection stage failed")
    else:
        logger.debug(
            "C2 detection disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    # --- Stage 5: Actor profiling ---
    if config.ACTOR_PROFILING_ENABLED:
        if _stage_already_done(snapshot_id, "actor_profiling"):
            logger.info("Actor profiling already done for snapshot_id=%s; skipping.", snapshot_id)
        else:
            try:
                _record_stage_status(snapshot_id, "actor_profiling", "running")
                from database import get_session  # type: ignore[import-untyped]
                from services.actor_service import profile_actors  # type: ignore[import-untyped]

                with get_session() as session:
                    actor_result = profile_actors(session)
                    session.commit()
                results["stages"]["actor_profiling"] = actor_result
                _record_stage_status(snapshot_id, "actor_profiling", "done")

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
                _record_stage_status(snapshot_id, "actor_profiling", "failed", error_message="Actor profiling stage failed")
    else:
        logger.debug(
            "Actor profiling disabled; skipping for snapshot_id=%s", snapshot_id,
        )

    elapsed = _time.time() - _start
    results["elapsed_s"] = round(elapsed, 4)

    # Mark overall pipeline as done
    _record_stage_status(snapshot_id, "pipeline", "done")

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