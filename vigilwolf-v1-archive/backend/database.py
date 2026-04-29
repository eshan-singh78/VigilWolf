"""SQLAlchemy database layer for the Domain Monitoring System.

Replaces JSON file storage with SQLite for atomicity, concurrency safety,
and query performance.
"""
from datetime import datetime, timezone
from typing import List, Optional
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, String, Integer, Boolean, Text,
    ForeignKey, DateTime, select, delete, event, text
)
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

import config

Base = declarative_base()


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class GroupModel(Base):
    __tablename__ = 'groups'

    id = Column(String(36), primary_key=True)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    domains = relationship('DomainModel', back_populates='group',
                         cascade='all, delete-orphan', lazy='selectin')


class DomainModel(Base):
    __tablename__ = 'domains'

    id = Column(String(36), primary_key=True)
    group_id = Column(String(36), ForeignKey('groups.id', ondelete='CASCADE'), nullable=False)
    url = Column(Text, nullable=False)
    dump_mode = Column(String(20), nullable=False)
    frequency_seconds = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    active = Column(Boolean, default=True)

    group = relationship('GroupModel', back_populates='domains')
    snapshots = relationship('SnapshotModel', back_populates='domain',
                            cascade='all, delete-orphan', lazy='selectin',
                            order_by='SnapshotModel.timestamp')
    ping_logs = relationship('PingLogModel', back_populates='domain',
                            cascade='all, delete-orphan', lazy='selectin',
                            order_by='PingLogModel.timestamp')
    dump_logs = relationship('DumpLogModel', back_populates='domain',
                            cascade='all, delete-orphan', lazy='selectin',
                            order_by='DumpLogModel.timestamp')


class SnapshotModel(Base):
    __tablename__ = 'snapshots'

    id = Column(String(36), primary_key=True)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now)
    trigger_type = Column(String(20), nullable=False)
    html_path = Column(Text, nullable=False)
    screenshot_path = Column(Text, nullable=True)
    assets_dir = Column(Text, nullable=True)
    asset_count = Column(Integer, default=0)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)

    domain = relationship('DomainModel', back_populates='snapshots')


class PingLogModel(Base):
    __tablename__ = 'ping_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now)
    reachable = Column(Boolean, nullable=False)
    status_code = Column(Integer, nullable=True)
    change_detected = Column(Boolean, nullable=False)
    message = Column(Text, nullable=False)

    domain = relationship('DomainModel', back_populates='ping_logs')


class DumpLogModel(Base):
    __tablename__ = 'dump_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now)
    trigger_type = Column(String(20), nullable=False)
    snapshot_id = Column(String(36), nullable=False)
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    message = Column(Text, nullable=False)

    domain = relationship('DomainModel', back_populates='dump_logs')


_engine = None
_SessionLocal = None


def get_engine():
    """Return the global SQLAlchemy engine."""
    global _engine
    if _engine is None:
        is_sqlite = config.DATABASE_URL.startswith('sqlite')
        is_memory = is_sqlite and ':memory:' in config.DATABASE_URL
        connect_args = {'check_same_thread': False} if is_sqlite else {}
        _engine = create_engine(
            config.DATABASE_URL,
            echo=False,
            connect_args=connect_args,
            poolclass=StaticPool if is_memory else None
        )
        if is_sqlite and not is_memory:
            # Enable WAL mode for better concurrency
            with _engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))
                conn.commit()
    return _engine


def get_session() -> Session:
    """Return a new database session."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal()


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=get_engine())


def reset_db():
    """Drop and recreate all tables."""
    Base.metadata.drop_all(bind=get_engine())
    Base.metadata.create_all(bind=get_engine())
