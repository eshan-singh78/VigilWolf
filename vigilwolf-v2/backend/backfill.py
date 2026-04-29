"""Backfill risk scores for existing snapshots.

Processes all existing snapshots through the v2 analysis pipeline to generate
risk scores. Supports dry-run mode for safe validation before live processing.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def backfill_snapshots(dry_run: bool = True, limit: Optional[int] = None):
    """Process all existing snapshots through the analysis pipeline.

    Args:
        dry_run: If True, log what would be processed without actually processing.
        limit: Maximum number of snapshots to process (None = all).

    Returns:
        Dict with processed count, skipped count, and error count.
    """
    from database import get_session, SnapshotModel, DomainModel
    from sqlalchemy import select

    with get_session() as session:
        snapshots = session.execute(
            select(SnapshotModel).where(SnapshotModel.success == True)  # noqa: E712
        ).scalars().all()

    if limit:
        snapshots = snapshots[:limit]

    logger.info(f"Backfill: {len(snapshots)} snapshots to process")

    processed = 0
    skipped = 0
    errors = 0

    for snapshot in snapshots:
        if not snapshot.html_path:
            # Skip snapshots with no html_path (None or empty string)
            skipped += 1
            continue

        try:
            # Get domain info
            with get_session() as session:
                domain = session.get(DomainModel, snapshot.domain_id)
                if not domain:
                    skipped += 1
                    continue

            # Read HTML from storage
            html = _load_html(snapshot.html_path)
            if not html:
                skipped += 1
                continue

            if dry_run:
                logger.info(f"[DRY RUN] Would process snapshot {snapshot.id} for domain {domain.url}")
            else:
                from worker import build_snapshot_context, orchestrate_analysis

                ctx = build_snapshot_context(
                    snapshot_id=snapshot.id,
                    domain=domain.url,
                    html=html,
                    snapshot_record={"id": snapshot.id, "domain_id": snapshot.domain_id},
                )
                # Run analysis (this also stores results in DB)
                orchestrate_analysis(ctx)
                logger.info(f"Processed snapshot {snapshot.id}")

            processed += 1
        except Exception as e:
            logger.error(f"Backfill failed for snapshot {snapshot.id}: {e}")
            errors += 1

    result = {"processed": processed, "skipped": skipped, "errors": errors}
    logger.info(f"Backfill complete: {result}")
    return result


def _load_html(html_path: str) -> Optional[str]:
    """Load HTML content from a snapshot file path.

    For Phase 1, reads from local filesystem.
    Returns None if file doesn't exist or can't be read.
    """
    import os
    from config import MONITORING_DATA_DIR

    full_path = os.path.join(MONITORING_DATA_DIR, html_path)
    if not os.path.exists(full_path):
        return None

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.warning(f"Could not read HTML from {full_path}: {e}")
        return None


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Backfill risk scores for existing snapshots")
    parser.add_argument("--live", action="store_true", help="Run in live mode (default is dry-run)")
    parser.add_argument("--limit", type=int, help="Maximum number of snapshots to process")
    args = parser.parse_args()

    result = backfill_snapshots(dry_run=not args.live, limit=args.limit)
    print(f"Result: {result}")