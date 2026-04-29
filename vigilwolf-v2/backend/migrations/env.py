"""VigilWolf v2 — Alembic migration environment.

This module configures Alembic to:
  - Use the ORM models defined in database.py (via Base.metadata)
  - Pull the database URL from the app's config module rather than alembic.ini
  - Support both online (connected) and offline (SQL script) migration modes
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ---------------------------------------------------------------------------
# Application imports — must happen before referencing Base / config
# ---------------------------------------------------------------------------
import config as app_config  # noqa: E402  — app config module
from database import Base  # noqa: E402  — ORM declarative base

# ---------------------------------------------------------------------------
# Alembic Config object — provides access to values in alembic.ini
# ---------------------------------------------------------------------------
config = context.config

# Override the placeholder URL in alembic.ini with the real one from the app.
# This ensures environment variables (DATABASE_URL) are always respected.
config.set_main_option("sqlalchemy.url", app_config.DATABASE_URL)

# Set up Python logging from alembic.ini if the config section is present.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Target metadata for autogenerate support
# ---------------------------------------------------------------------------
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine.  Calls to
    context.execute() emit the given SQL as string to the output stream.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    This creates an Engine and associates a connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


# ---------------------------------------------------------------------------
# Entry point — Alembic invokes this when running migration commands.
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()