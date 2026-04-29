"""One-time migration from SQLite to PostgreSQL with validation.

Usage: python migrate_sqlite_to_pg.py <source_sqlite_url> <target_pg_url>

Example:
  python migrate_sqlite_to_pg.py sqlite:///./monitoring/data/vigilwolf.db \
    postgresql://vigilwolf:changeme@localhost:5432/vigilwolf
"""
import os
import sys
import logging
from typing import List

from sqlalchemy import create_engine, select, text, inspect
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

# Tables to migrate (in order of foreign key dependencies)
MIGRATION_TABLES = [
    "groups",
    "domains",
    "snapshots",
    "ping_logs",
    "dump_logs",
]

# Boolean columns in the schema that need 0/1 → True/False conversion
# when moving from SQLite (which stores booleans as integers) to PostgreSQL.
BOOLEAN_COLUMNS = {
    "domains": {"active"},
    "snapshots": {"success"},
    "ping_logs": {"reachable", "change_detected"},
    "dump_logs": {"success"},
}


def migrate_table(source_engine, target_engine, table_name: str, batch_size: int = 1000) -> int:
    """Copy all rows of a table from source to target DB in batches.

    Returns:
        Number of rows migrated.
    """
    with source_engine.connect() as source_conn:
        total = source_conn.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
        logger.info(f"Migrating {table_name}: {total} rows")

        if total == 0:
            logger.info(f"  {table_name}: 0 rows, skipping")
            return 0

        columns = [c["name"] for c in inspect(source_engine).get_columns(table_name)]
        col_list = ", ".join(columns)
        placeholders = ", ".join([f":{c}" for c in columns])

        bool_cols = BOOLEAN_COLUMNS.get(table_name, set())

        offset = 0
        migrated = 0
        while offset < total:
            rows = source_conn.execute(
                text(f"SELECT {col_list} FROM {table_name} LIMIT :limit OFFSET :offset"),
                {"limit": batch_size, "offset": offset},
            ).fetchall()

            with target_engine.connect() as target_conn:
                for row in rows:
                    row_dict = dict(row._mapping)
                    # Convert SQLite booleans (0/1) to Python bool for PG
                    for col in columns:
                        if col in bool_cols:
                            val = row_dict[col]
                            if isinstance(val, int):
                                row_dict[col] = bool(val)
                    target_conn.execute(
                        text(f"INSERT INTO {table_name} ({col_list}) VALUES ({placeholders})"),
                        row_dict,
                    )
                target_conn.commit()

            migrated += len(rows)
            offset += batch_size
            logger.info(f"  Migrated {migrated}/{total}")

        return migrated


def validate_migration(source_engine, target_engine) -> List[str]:
    """Validate that row counts match between source and target.

    Returns:
        List of error strings. Empty = success.
    """
    errors = []
    for table_name in MIGRATION_TABLES:
        try:
            with source_engine.connect() as src:
                src_count = src.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
            with target_engine.connect() as tgt:
                tgt_count = tgt.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()

            if src_count != tgt_count:
                errors.append(f"{table_name}: source={src_count}, target={tgt_count}")
            else:
                logger.info(f"  {table_name}: {src_count} rows OK")
        except Exception as e:
            errors.append(f"{table_name}: validation error: {e}")

    return errors


def run_migration(source_url: str, target_url: str) -> bool:
    """Execute full migration with validation."""
    source_engine = create_engine(source_url)
    target_engine = create_engine(target_url)

    logger.info("Starting SQLite to PostgreSQL migration")

    for table_name in MIGRATION_TABLES:
        try:
            migrate_table(source_engine, target_engine, table_name)
        except Exception as e:
            logger.error(f"Migration failed for {table_name}: {e}")
            return False

    errors = validate_migration(source_engine, target_engine)

    if errors:
        logger.error(f"Migration validation FAILED: {errors}")
        return False

    logger.info("Migration completed successfully")
    return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    if len(sys.argv) < 3:
        print("Usage: python migrate_sqlite_to_pg.py <source_sqlite_url> <target_pg_url>")
        print("Example: python migrate_sqlite_to_pg.py sqlite:///./vigilwolf.db postgresql://vigilwolf:pass@localhost:5432/vigilwolf")
        sys.exit(1)

    source_url = sys.argv[1]
    target_url = sys.argv[2]

    success = run_migration(source_url, target_url)
    sys.exit(0 if success else 1)