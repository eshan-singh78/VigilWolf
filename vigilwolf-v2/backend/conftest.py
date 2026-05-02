"""Pytest bootstrap: tune security middleware and rate limits for TestClient."""

import os

# Load before test modules import `main` → `config` (Starlette TestClient uses Host: testserver).
os.environ.setdefault("TRUSTED_HOSTS", "localhost,127.0.0.1,testserver")
os.environ.setdefault("FORCE_HTTPS", "false")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "100000")
