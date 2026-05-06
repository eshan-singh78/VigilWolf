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
# Configurable via RECONCILE_ORPHAN_THRESHOLD_MINUTES env var.
ORPHANED_THRESHOLD_MINUTES = config.RECONCILE_ORPHAN_THRESHOLD_MINUTES


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