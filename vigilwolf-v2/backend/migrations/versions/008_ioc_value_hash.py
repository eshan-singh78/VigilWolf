"""Add value_hash column to iocs table for efficient deduplication.

Replaces the expensive unique index on the text `value` column with a
SHA-256 hash column that is cheaper to index and compare.

Revision ID: 008_ioc_value_hash
Revises: 007_c2_unique
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa

revision = "008_ioc_value_hash"
down_revision = "007_c2_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add value_hash column as nullable first (so existing rows can coexist)
    op.add_column("iocs", sa.Column("value_hash", sa.String(64), nullable=True))

    # 2. Backfill: compute SHA-256 of the value column for every existing row.
    #    Use a dialect-aware approach: PostgreSQL can use encode(sha256(...)),
    #    SQLite has no built-in sha256 so we handle it in Python via a batch.
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        bind.execute(
            sa.text(
                "UPDATE iocs SET value_hash = encode(sha256(value::bytea), 'hex')"
            )
        )
    else:
        # SQLite fallback: compute SHA-256 in Python and update row by row
        import hashlib

        result = bind.execute(sa.text("SELECT id, value FROM iocs"))
        rows = result.fetchall()
        for row in rows:
            h = hashlib.sha256(row[1].encode("utf-8")).hexdigest()
            bind.execute(
                sa.text("UPDATE iocs SET value_hash = :hash WHERE id = :id"),
                {"hash": h, "id": row[0]},
            )

    # 3. Make value_hash NOT NULL
    op.alter_column("iocs", "value_hash", nullable=False)

    # 4. Create unique constraint on value_hash
    op.create_unique_constraint("uq_ioc_value_hash", "iocs", ["value_hash"])

    # 5. Drop the old unique constraint on value (if it exists)
    #    SQLAlchemy named it based on the column: "iocs_value_key" on PostgreSQL
    #    or the implicit index on SQLite.
    #    We inspect first to avoid errors if it doesn't exist.
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(bind)
    constraints = inspector.get_unique_constraints("iocs")
    for uc in constraints:
        if uc["column_names"] == ["value"]:
            op.drop_constraint(uc["name"], "iocs", type_="unique")
            break
    else:
        # Also check indexes — SQLite may have created a unique index instead
        indexes = inspector.get_indexes("iocs")
        for idx in indexes:
            if idx.get("unique") and idx["column_names"] == ["value"]:
                op.drop_index(idx["name"], table_name="iocs")
                break


def downgrade() -> None:
    # Restore the original unique constraint on value
    op.create_unique_constraint("iocs_value_key", "iocs", ["value"])

    # Drop the value_hash unique constraint and column
    op.drop_constraint("uq_ioc_value_hash", "iocs", type_="unique")
    op.drop_column("iocs", "value_hash")