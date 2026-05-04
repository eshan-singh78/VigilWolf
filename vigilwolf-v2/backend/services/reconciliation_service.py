"""Reconciliation service — Clean up orphaned plugin statuses.

When the analysis pipeline crashes mid-execution, SnapshotPluginStatusModel rows
can be left in "pending" or "running" status indefinitely. This service marks
them as "failed" so they don't block downstream processing.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

import config

logger = logging.getLogger(__name__)

# Plugins left in "running" status for longer than this are considered orphaned.
ORPHANED_THRESHOLD_MINUTES = 5


def reconcile_orphaned_statuses(session) -> dict:
    """Mark orphaned plugin statuses as "failed".

    A status row is considered orphaned if:
    - Its status is "running" and started_at is older than ORPHANED_THRESHOLD_MINUTES
    - Its status is "pending" and the snapshot was created more than 30 minutes ago

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with reconciled_running and reconciled_pending counts.
    """
    from database import SnapshotPluginStatusModel, SnapshotModel  # type: ignore[import-untyped]

    cutoff_running = datetime.now(timezone.utc) - timedelta(minutes=ORPHANED_THRESHOLD_MINUTES)
    cutoff_pending = datetime.now(timezone.utc) - timedelta(minutes=30)

    # Reconcile "running" statuses that have been stuck for too long
    running_orphans = (
        session.query(SnapshotPluginStatusModel)
        .filter(
            SnapshotPluginStatusModel.status == "running",
            SnapshotPluginStatusModel.started_at < cutoff_running,
        )
        .all()
    )

    reconciled_running = 0
    for status_row in running_orphans:
        status_row.status = "failed"
        status_row.completed_at = datetime.now(timezone.utc)
        status_row.error_message = "Reconciled: pipeline did not complete within timeout"
        reconciled_running += 1

    if reconciled_running:
        logger.info("Reconciled %d running plugin statuses to failed", reconciled_running)

    # Reconcile "pending" statuses whose snapshots are older than the cutoff
    reconciled_pending = (
        session.query(SnapshotPluginStatusModel)
        .join(SnapshotModel, SnapshotModel.id == SnapshotPluginStatusModel.snapshot_id)
        .filter(
            SnapshotPluginStatusModel.status == "pending",
            SnapshotModel.timestamp < cutoff_pending,
        )
        .all()
    )

    for status_row in reconciled_pending:
        status_row.status = "failed"
        status_row.completed_at = datetime.now(timezone.utc)
        status_row.error_message = "Reconciled: plugin was never started within timeout"

    if reconciled_pending:
        logger.info("Reconciled %d pending plugin statuses to failed", len(reconciled_pending))

    return {
        "reconciled_running": reconciled_running,
        "reconciled_pending": len(reconciled_pending),
    }


def reconcile_ioc_persistence(session) -> dict:
    """Re-attempt IOC persistence for snapshots that have ioc_extractor results
    but no IocOccurrenceModel rows.

    This catches snapshots where IOC persistence failed (e.g., DB connection
    pool exhaustion) and the intelligence pipeline ran without IOC data.

    Returns:
        Dict with reconciled_ioc_snapshots count.
    """
    from database import (  # type: ignore[import-untyped]
        AnalysisResultModel,
        IocOccurrenceModel,
        SnapshotModel,
    )

    # Find snapshots that have ioc_extractor analysis results but no IOC occurrences.
    # Use a subquery to find snapshot_ids with IOC occurrences.
    ioc_snapshot_ids = (
        session.query(IocOccurrenceModel.snapshot_id)
        .distinct()
        .subquery()
    )

    # Find ioc_extractor results for snapshots NOT in the IOC occurrences subquery.
    orphaned_results = (
        session.query(AnalysisResultModel.snapshot_id, AnalysisResultModel.result_json)
        .filter(
            AnalysisResultModel.plugin_name == "ioc_extractor",
            AnalysisResultModel.snapshot_id.notin_(ioc_snapshot_ids),
        )
        .limit(config.RECONCILE_IOC_BATCH)
        .all()
    )

    if not orphaned_results:
        return {"reconciled_ioc_snapshots": 0}

    if len(orphaned_results) >= config.RECONCILE_IOC_BATCH:
        logger.warning(
            "IOC reconciliation hit batch limit (%d); backlog may be growing",
            config.RECONCILE_IOC_BATCH,
        )

    reconciled = 0
    for snapshot_id, result_json in orphaned_results:
        if not result_json:
            continue
        try:
            from services.ioc_service import persist_iocs
            persist_iocs(
                snapshot_id=snapshot_id,
                findings=result_json,
                session=session,
            )
            reconciled += 1
        except Exception:
            logger.exception("IOC reconciliation failed for snapshot_id=%s", snapshot_id)

    if reconciled:
        logger.info("IOC reconciliation: re-persisted IOCs for %d snapshots", reconciled)

    return {"reconciled_ioc_snapshots": reconciled}


def reconcile_missing_pipeline(session) -> dict:
    """Find snapshots that have no plugin status rows and re-trigger analysis.

    This catches snapshots that were created (HTML captured) but never had
    their analysis pipeline started — e.g., due to a Dramatiq enqueue failure
    or worker crash before plugin status rows were created.

    Returns:
        Dict with reconciled_missing_snapshots count.
    """
    from database import (  # type: ignore[import-untyped]
        SnapshotModel,
        SnapshotPluginStatusModel,
    )

    # Find snapshots with no plugin status rows at all.
    # These snapshots were captured but never analyzed.
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)  # Only snapshots older than 10 min
    snapshots_with_status = (
        session.query(SnapshotPluginStatusModel.snapshot_id)
        .distinct()
        .subquery()
    )

    orphaned_snapshots = (
        session.query(SnapshotModel.id, SnapshotModel.domain_id)
        .filter(
            SnapshotModel.id.notin_(snapshots_with_status),
            SnapshotModel.success.is_(True),
            SnapshotModel.timestamp < cutoff,
        )
        .limit(config.RECONCILE_PIPELINE_BATCH)
        .all()
    )

    if not orphaned_snapshots:
        return {"reconciled_missing_snapshots": 0}

    if len(orphaned_snapshots) >= config.RECONCILE_PIPELINE_BATCH:
        logger.warning(
            "Pipeline reconciliation hit batch limit (%d); backlog may be growing",
            config.RECONCILE_PIPELINE_BATCH,
        )

    reconciled = 0
    for snapshot_id, domain_id in orphaned_snapshots:
        try:
            from worker import build_context_and_analyze
            build_context_and_analyze(snapshot_id=snapshot_id, domain_id=domain_id)
            reconciled += 1
        except Exception:
            logger.exception("Pipeline reconciliation failed for snapshot_id=%s", snapshot_id)

    if reconciled:
        logger.info("Pipeline reconciliation: re-triggered analysis for %d snapshots", reconciled)

    return {"reconciled_missing_snapshots": reconciled}


def reconcile_cluster_counts(session) -> dict:
    """Fix domain_count drift in ClusterModel rows.

    For each cluster where domain_count != actual COUNT(*) of cluster_members,
    update the count. This addresses D-1 drift caused by concurrent inserts.
    """
    from database import ClusterMemberModel, ClusterModel  # type: ignore[import-untyped]
    from sqlalchemy import func as sa_func

    # Find clusters where domain_count is stale
    actual_counts = (
        session.query(
            ClusterMemberModel.cluster_id,
            sa_func.count(ClusterMemberModel.domain_id).label("count"),
        )
        .group_by(ClusterMemberModel.cluster_id)
        .subquery()
    )

    stale_clusters = (
        session.query(ClusterModel)
        .join(actual_counts, ClusterModel.id == actual_counts.c.cluster_id)
        .filter(ClusterModel.domain_count != actual_counts.c.count)
        .all()
    )

    reconciled = 0
    for cluster in stale_clusters:
        actual = (
            session.query(sa_func.count(ClusterMemberModel.domain_id))
            .filter(ClusterMemberModel.cluster_id == cluster.id)
            .scalar()
        )
        if actual is not None and cluster.domain_count != actual:
            logger.info(
                "Cluster %s domain_count drift: %d -> %d",
                cluster.id[:8], cluster.domain_count, actual,
            )
            cluster.domain_count = actual
            reconciled += 1

    if reconciled:
        logger.info("Reconciled domain_count for %d clusters", reconciled)

    return {"reconciled_cluster_counts": reconciled}