#!/usr/bin/env sh
set -eu

# In production we enforce migration-managed schema before app boot.
if [ "${ENVIRONMENT:-development}" = "production" ]; then
  echo "[entrypoint] running alembic migrations..."
  alembic upgrade head
fi

echo "[entrypoint] starting: $*"
exec "$@"
