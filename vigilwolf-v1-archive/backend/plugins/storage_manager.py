"""Storage manager for the Domain Monitoring System.

Uses SQLAlchemy/SQLite for metadata persistence and the filesystem
for snapshot content (HTML, screenshots, assets).
"""
import os
import json
import shutil
from datetime import datetime, timezone
from typing import List, Optional
from pathlib import Path

from database import (
    get_session, init_db, reset_db,
    GroupModel, DomainModel, SnapshotModel,
    PingLogModel, DumpLogModel
)
from sqlalchemy import select
from models import Group, Domain, Snapshot, PingLogEntry, DumpLogEntry
from config import MONITORING_DATA_DIR, SNAPSHOTS_DIR


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    """Convert ISO 8601 string to timezone-aware datetime."""
    if not dt_str:
        return None
    dt_str = dt_str.replace('Z', '+00:00')
    return datetime.fromisoformat(dt_str)


def _format_iso(dt: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO 8601 string with Z suffix."""
    if not dt:
        return None
    return dt.isoformat().replace('+00:00', 'Z')


class StorageManager:
    """Manages all storage operations for the monitoring system."""

    def __init__(self, data_dir: str = MONITORING_DATA_DIR):
        """Initialize storage manager with data directory."""
        self.data_dir = Path(data_dir)
        self.snapshots_dir = self.data_dir / "snapshots"
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def _get_db(self):
        """Get a new database session."""
        return get_session()

    # --- Group operations ---

    def save_group(self, group: Group) -> None:
        with self._get_db() as db:
            existing = db.get(GroupModel, group.id)
            if existing:
                existing.name = group.name
                existing.created_at = _parse_iso(group.created_at)
            else:
                db.add(GroupModel(
                    id=group.id,
                    name=group.name,
                    created_at=_parse_iso(group.created_at)
                ))
            db.commit()

    def load_groups(self) -> List[Group]:
        with self._get_db() as db:
            rows = db.execute(select(GroupModel)).scalars().all()
            return [self._row_to_group(r) for r in rows]

    def get_group(self, group_id: str) -> Optional[Group]:
        with self._get_db() as db:
            row = db.get(GroupModel, group_id)
            return self._row_to_group(row) if row else None

    def _row_to_group(self, row: GroupModel) -> Group:
        return Group(
            id=row.id,
            name=row.name,
            created_at=_format_iso(row.created_at),
            domain_ids=[d.id for d in row.domains]
        )

    # --- Domain operations ---

    def save_domain(self, domain: Domain) -> None:
        with self._get_db() as db:
            existing = db.get(DomainModel, domain.id)
            if existing:
                existing.group_id = domain.group_id
                existing.url = domain.url
                existing.dump_mode = domain.dump_mode
                existing.frequency_seconds = domain.frequency_seconds
                existing.last_checked_at = _parse_iso(domain.last_checked_at)
                existing.active = domain.active
            else:
                db.add(DomainModel(
                    id=domain.id,
                    group_id=domain.group_id,
                    url=domain.url,
                    dump_mode=domain.dump_mode,
                    frequency_seconds=domain.frequency_seconds,
                    created_at=_parse_iso(domain.created_at),
                    last_checked_at=_parse_iso(domain.last_checked_at),
                    active=domain.active
                ))
            db.commit()

    def load_domains(self) -> List[Domain]:
        with self._get_db() as db:
            rows = db.execute(select(DomainModel)).scalars().all()
            return [self._row_to_domain(r) for r in rows]

    def get_domain(self, domain_id: str) -> Optional[Domain]:
        with self._get_db() as db:
            row = db.get(DomainModel, domain_id)
            return self._row_to_domain(row) if row else None

    def get_domains_by_group(self, group_id: str) -> List[Domain]:
        with self._get_db() as db:
            rows = db.execute(
                select(DomainModel).where(DomainModel.group_id == group_id)
            ).scalars().all()
            return [self._row_to_domain(r) for r in rows]

    def _row_to_domain(self, row: DomainModel) -> Domain:
        return Domain(
            id=row.id,
            group_id=row.group_id,
            url=row.url,
            dump_mode=row.dump_mode,
            frequency_seconds=row.frequency_seconds,
            created_at=_format_iso(row.created_at),
            last_checked_at=_format_iso(row.last_checked_at),
            active=row.active
        )

    # --- Snapshot operations ---

    def create_snapshot_directory(self, domain_id: str, timestamp: str) -> str:
        domain_dir = self.snapshots_dir / domain_id
        domain_dir.mkdir(parents=True, exist_ok=True)
        clean_timestamp = timestamp.replace(':', '-').replace('.', '-')
        snapshot_dir = domain_dir / clean_timestamp
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        return str(snapshot_dir)

    def save_snapshot_metadata(self, snapshot: Snapshot) -> None:
        with self._get_db() as db:
            db.add(SnapshotModel(
                id=snapshot.id,
                domain_id=snapshot.domain_id,
                timestamp=_parse_iso(snapshot.timestamp),
                trigger_type=snapshot.trigger_type,
                html_path=snapshot.html_path,
                screenshot_path=snapshot.screenshot_path,
                assets_dir=snapshot.assets_dir,
                asset_count=snapshot.asset_count,
                success=snapshot.success,
                error_message=snapshot.error_message
            ))
            db.commit()

    def load_snapshots_for_domain(self, domain_id: str) -> List[Snapshot]:
        with self._get_db() as db:
            rows = db.execute(
                select(SnapshotModel)
                .where(SnapshotModel.domain_id == domain_id)
                .order_by(SnapshotModel.timestamp)
            ).scalars().all()
            return [self._row_to_snapshot(r) for r in rows]

    def get_latest_snapshot_for_domain(self, domain_id: str) -> Optional[Snapshot]:
        with self._get_db() as db:
            row = db.execute(
                select(SnapshotModel)
                .where(SnapshotModel.domain_id == domain_id)
                .order_by(SnapshotModel.timestamp.desc())
                .limit(1)
            ).scalar_one_or_none()
            return self._row_to_snapshot(row) if row else None

    def get_snapshot(self, snapshot_id: str) -> Optional[Snapshot]:
        with self._get_db() as db:
            row = db.get(SnapshotModel, snapshot_id)
            return self._row_to_snapshot(row) if row else None

    def _row_to_snapshot(self, row: SnapshotModel) -> Snapshot:
        return Snapshot(
            id=row.id,
            domain_id=row.domain_id,
            timestamp=_format_iso(row.timestamp),
            trigger_type=row.trigger_type,
            html_path=row.html_path,
            screenshot_path=row.screenshot_path,
            assets_dir=row.assets_dir,
            asset_count=row.asset_count,
            success=row.success,
            error_message=row.error_message
        )

    def validate_snapshot(self, snapshot: Snapshot) -> tuple[bool, list[str]]:
        return snapshot.validate_integrity(str(self.data_dir))

    # --- HTML storage ---

    def save_html(self, snapshot_dir: str, html_content: str) -> str:
        html_file = Path(snapshot_dir) / "page.html"
        with open(html_file, 'w', encoding='utf-8', newline='') as f:
            f.write(html_content)
        return str(html_file.relative_to(self.data_dir))

    def load_html(self, html_path: str) -> str:
        full_path = self.data_dir / html_path
        with open(full_path, 'r', encoding='utf-8', newline='') as f:
            return f.read()

    # --- Log operations ---

    def append_ping_log(self, domain_id: str, entry: PingLogEntry) -> None:
        with self._get_db() as db:
            db.add(PingLogModel(
                domain_id=domain_id,
                timestamp=_parse_iso(entry.timestamp),
                reachable=entry.reachable,
                status_code=entry.status_code,
                change_detected=entry.change_detected,
                message=entry.message
            ))
            db.commit()

    def read_ping_log(self, domain_id: str) -> List[PingLogEntry]:
        with self._get_db() as db:
            rows = db.execute(
                select(PingLogModel)
                .where(PingLogModel.domain_id == domain_id)
                .order_by(PingLogModel.timestamp)
            ).scalars().all()
            return [self._row_to_ping_log(r) for r in rows]

    def get_latest_ping_log(self, domain_id: str) -> Optional[PingLogEntry]:
        with self._get_db() as db:
            row = db.execute(
                select(PingLogModel)
                .where(PingLogModel.domain_id == domain_id)
                .order_by(PingLogModel.timestamp.desc())
                .limit(1)
            ).scalar_one_or_none()
            return self._row_to_ping_log(row) if row else None

    def _row_to_ping_log(self, row: PingLogModel) -> PingLogEntry:
        return PingLogEntry(
            timestamp=_format_iso(row.timestamp),
            reachable=row.reachable,
            status_code=row.status_code,
            change_detected=row.change_detected,
            message=row.message
        )

    def append_dump_log(self, domain_id: str, entry: DumpLogEntry) -> None:
        with self._get_db() as db:
            db.add(DumpLogModel(
                domain_id=domain_id,
                timestamp=_parse_iso(entry.timestamp),
                trigger_type=entry.trigger_type,
                snapshot_id=entry.snapshot_id,
                success=entry.success,
                error_message=entry.error_message,
                message=entry.message
            ))
            db.commit()

    def read_dump_log(self, domain_id: str) -> List[DumpLogEntry]:
        with self._get_db() as db:
            rows = db.execute(
                select(DumpLogModel)
                .where(DumpLogModel.domain_id == domain_id)
                .order_by(DumpLogModel.timestamp)
            ).scalars().all()
            return [self._row_to_dump_log(r) for r in rows]

    def _row_to_dump_log(self, row: DumpLogModel) -> DumpLogEntry:
        return DumpLogEntry(
            timestamp=_format_iso(row.timestamp),
            trigger_type=row.trigger_type,
            snapshot_id=row.snapshot_id,
            success=row.success,
            error_message=row.error_message,
            message=row.message
        )

    # --- Reset ---

    def reset_environment(self) -> dict:
        with self._get_db() as db:
            group_count = len(db.execute(select(GroupModel)).scalars().all())
            domain_count = len(db.execute(select(DomainModel)).scalars().all())
            snapshot_count = len(db.execute(select(SnapshotModel)).scalars().all())

        reset_db()

        if self.snapshots_dir.exists():
            shutil.rmtree(self.snapshots_dir)
        self._ensure_directories()

        return {
            'groups_deleted': group_count or 0,
            'domains_deleted': domain_count or 0,
            'snapshots_deleted': snapshot_count or 0
        }


_storage_manager = None


def get_storage_manager() -> StorageManager:
    """Get the global storage manager instance."""
    global _storage_manager
    if _storage_manager is None:
        _storage_manager = StorageManager()
    return _storage_manager
