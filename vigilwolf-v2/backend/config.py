"""Configuration management for VigilWolf v2.

This module centralizes all configuration settings for the monitoring system,
loading values from environment variables with sensible defaults.
"""
import os
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
MONITORING_DATA_DIR = os.getenv("MONITORING_DATA_DIR", "./monitoring/data")
SNAPSHOTS_DIR = os.path.join(MONITORING_DATA_DIR, "snapshots")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(MONITORING_DATA_DIR, 'vigilwolf.db')}"
)

# ---------------------------------------------------------------------------
# Concurrency & Timeouts
# ---------------------------------------------------------------------------
MAX_CONCURRENT_CHECKS = int(os.getenv("MAX_CONCURRENT_CHECKS", "10"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "30"))

# ---------------------------------------------------------------------------
# Screenshots
# ---------------------------------------------------------------------------
SCREENSHOT_ENABLED = os.getenv("SCREENSHOT_ENABLED", "true").lower() == "true"
SCREENSHOT_WIDTH = int(os.getenv("SCREENSHOT_WIDTH", "1920"))
SCREENSHOT_HEIGHT = int(os.getenv("SCREENSHOT_HEIGHT", "1080"))
SCREENSHOT_FORMAT = os.getenv("SCREENSHOT_FORMAT", "png")
BROWSER_TYPE = os.getenv("BROWSER_TYPE", "chromium")
BROWSER_HEADLESS = os.getenv("BROWSER_HEADLESS", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Limits & Retention
# ---------------------------------------------------------------------------
MAX_DOMAINS_PER_GROUP = int(os.getenv("MAX_DOMAINS_PER_GROUP", "100"))
SNAPSHOT_RETENTION_DAYS = int(os.getenv("SNAPSHOT_RETENTION_DAYS", "90"))
MIN_CHECK_FREQUENCY_SECONDS = int(os.getenv("MIN_CHECK_FREQUENCY_SECONDS", "60"))
MAX_ASSET_SIZE_BYTES = int(os.getenv("MAX_ASSET_SIZE_BYTES", "52428800"))  # 50MB default

# ---------------------------------------------------------------------------
# Retry / Error Handling
# ---------------------------------------------------------------------------
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY_SECONDS = float(os.getenv("RETRY_DELAY_SECONDS", "1.0"))
RETRY_BACKOFF_MULTIPLIER = float(os.getenv("RETRY_BACKOFF_MULTIPLIER", "2.0"))
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "5"))

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
SCHEDULER_TIMEZONE = os.getenv("SCHEDULER_TIMEZONE", "UTC")
SCHEDULER_MAX_INSTANCES = int(os.getenv("SCHEDULER_MAX_INSTANCES", "3"))
SCHEDULER_COALESCE = os.getenv("SCHEDULER_COALESCE", "true").lower() == "true"

# ---------------------------------------------------------------------------
# API / Networking
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
TRUSTED_PROXIES = [p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "")
JSON_LOGGING = os.getenv("JSON_LOGGING", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY", "")
if ENVIRONMENT == "production" and not API_KEY:
    import logging
    logging.getLogger(__name__).critical(
        "API_KEY is not set in production. Refusing to start without authentication. "
        "Set the API_KEY environment variable."
    )

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
TRUSTED_HOSTS = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "")

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------
ENABLE_PROMETHEUS = os.getenv("ENABLE_PROMETHEUS", "true").lower() == "true"
REQUEST_ID_HEADER = os.getenv("REQUEST_ID_HEADER", "X-Request-ID")

# ---------------------------------------------------------------------------
# v2 — Feature flags (migration safety)
# ---------------------------------------------------------------------------
USE_DRAMATIQ_PIPELINE = os.getenv("USE_DRAMATIQ_PIPELINE", "false").lower() == "true"
CLUSTERING_ENABLED = os.getenv("CLUSTERING_ENABLED", "false").lower() == "true"
ALERTS_ENABLED = os.getenv("ALERTS_ENABLED", "false").lower() == "true"
ALERTS_DRY_RUN = os.getenv("ALERTS_DRY_RUN", "false").lower() == "true"

# ---------------------------------------------------------------------------
# v2 — Intelligence pipeline flags (Phase 2 & 3)
# ---------------------------------------------------------------------------
INTELLIGENCE_PIPELINE_ENABLED = os.getenv("INTELLIGENCE_PIPELINE_ENABLED", "false").lower() == "true"
CAMPAIGN_DETECTION_ENABLED = os.getenv("CAMPAIGN_DETECTION_ENABLED", "false").lower() == "true"
PHISHKIT_DETECTION_ENABLED = os.getenv("PHISHKIT_DETECTION_ENABLED", "false").lower() == "true"
ACTOR_PROFILING_ENABLED = os.getenv("ACTOR_PROFILING_ENABLED", "false").lower() == "true"
C2_DETECTION_ENABLED = os.getenv("C2_DETECTION_ENABLED", "false").lower() == "true"

# ---------------------------------------------------------------------------
# v2 — Batch scheduler flags (C-2: per-snapshot → periodic batch)
# ---------------------------------------------------------------------------
BATCH_CLUSTERING_ENABLED = os.getenv("BATCH_CLUSTERING_ENABLED", "true").lower() == "true"
BATCH_CAMPAIGN_ENABLED = os.getenv("BATCH_CAMPAIGN_ENABLED", "true").lower() == "true"
BATCH_PHISHKIT_ENABLED = os.getenv("BATCH_PHISHKIT_ENABLED", "true").lower() == "true"

# ---------------------------------------------------------------------------
# v2 — Per-plugin feature flags
# ---------------------------------------------------------------------------
ENABLED_PLUGINS = os.getenv(
    "ENABLED_PLUGINS",
    "whois_enricher,dns_enricher,login_detector,keyword_detector,brand_match,external_js_detector,nrd_age_scorer,html_hasher,ioc_extractor"
).split(",")

# ---------------------------------------------------------------------------
# v2 — Risk thresholds
# ---------------------------------------------------------------------------
RISK_THRESHOLD_HIGH = int(os.getenv("RISK_THRESHOLD_HIGH", "70"))
RISK_THRESHOLD_MEDIUM = int(os.getenv("RISK_THRESHOLD_MEDIUM", "40"))

# ---------------------------------------------------------------------------
# v2 — High-risk registrars
# ---------------------------------------------------------------------------
HIGH_RISK_REGISTRARS = os.getenv(
    "HIGH_RISK_REGISTRARS",
    "namecheap,godaddy,dynadot"
).split(",")

# ---------------------------------------------------------------------------
# v2 — Dramatiq
# ---------------------------------------------------------------------------
DRAMATIQ_BROKER_URL = os.getenv("DRAMATIQ_BROKER_URL", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# v2 — Redis logical separation
# ---------------------------------------------------------------------------
REDIS_CACHE_DB = int(os.getenv("REDIS_CACHE_DB", "1"))
REDIS_RATE_LIMIT_DB = int(os.getenv("REDIS_RATE_LIMIT_DB", "2"))

# ---------------------------------------------------------------------------
# v2 — Pipeline
# ---------------------------------------------------------------------------
PIPELINE_TIMEOUT_SECONDS = int(os.getenv("PIPELINE_TIMEOUT_SECONDS", "120"))

# ---------------------------------------------------------------------------
# v2 — Batch scheduler intervals (seconds)
# ---------------------------------------------------------------------------
BATCH_CLUSTERING_INTERVAL_S = int(os.getenv("BATCH_CLUSTERING_INTERVAL_S", "300"))
BATCH_CAMPAIGN_INTERVAL_S = int(os.getenv("BATCH_CAMPAIGN_INTERVAL_S", "600"))
BATCH_PHISHKIT_INTERVAL_S = int(os.getenv("BATCH_PHISHKIT_INTERVAL_S", "300"))

# ---------------------------------------------------------------------------
# v2 — Reconciliation batch limits (H-4: scale from hardcoded values)
# ---------------------------------------------------------------------------
RECONCILE_IOC_BATCH = int(os.getenv("RECONCILE_IOC_BATCH", "200"))
RECONCILE_PIPELINE_BATCH = int(os.getenv("RECONCILE_PIPELINE_BATCH", "100"))


def ensure_directories() -> None:
    """Create necessary directories if they don't exist."""
    Path(MONITORING_DATA_DIR).mkdir(parents=True, exist_ok=True)
    Path(SNAPSHOTS_DIR).mkdir(parents=True, exist_ok=True)


def get_config_summary() -> dict:
    """Get a summary of current configuration settings.

    Returns:
        Dictionary containing all configuration values
    """
    return {
        "directories": {
            "monitoring_data_dir": MONITORING_DATA_DIR,
            "snapshots_dir": SNAPSHOTS_DIR,
        },
        "database": {
            "database_url": re.sub(r"(://[^:]+:)([^@]+)(@)", r"\1<hidden>\3", DATABASE_URL) if "://" in DATABASE_URL else DATABASE_URL,
        },
        "monitoring": {
            "max_concurrent_checks": MAX_CONCURRENT_CHECKS,
            "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "screenshot_enabled": SCREENSHOT_ENABLED,
            "max_domains_per_group": MAX_DOMAINS_PER_GROUP,
            "snapshot_retention_days": SNAPSHOT_RETENTION_DAYS,
            "min_check_frequency_seconds": MIN_CHECK_FREQUENCY_SECONDS,
            "max_asset_size_bytes": MAX_ASSET_SIZE_BYTES,
        },
        "error_handling": {
            "max_retries": MAX_RETRIES,
            "retry_delay_seconds": RETRY_DELAY_SECONDS,
            "retry_backoff_multiplier": RETRY_BACKOFF_MULTIPLIER,
            "alert_threshold": ALERT_THRESHOLD,
        },
        "screenshot": {
            "width": SCREENSHOT_WIDTH,
            "height": SCREENSHOT_HEIGHT,
            "format": SCREENSHOT_FORMAT,
            "browser_type": BROWSER_TYPE,
            "browser_headless": BROWSER_HEADLESS,
        },
        "scheduler": {
            "timezone": SCHEDULER_TIMEZONE,
            "max_instances": SCHEDULER_MAX_INSTANCES,
            "coalesce": SCHEDULER_COALESCE,
        },
        "api": {
            "allowed_origins": ALLOWED_ORIGINS,
            "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
            "trusted_proxies": TRUSTED_PROXIES,
            "api_key_configured": bool(API_KEY),
        },
        "logging": {
            "log_level": LOG_LEVEL,
            "log_file": LOG_FILE,
            "json_logging": JSON_LOGGING,
        },
        "security": {
            "environment": ENVIRONMENT,
            "force_https": FORCE_HTTPS,
            "trusted_hosts": TRUSTED_HOSTS,
        },
        "v2_features": {
            "use_dramatiq_pipeline": USE_DRAMATIQ_PIPELINE,
            "clustering_enabled": CLUSTERING_ENABLED,
            "alerts_enabled": ALERTS_ENABLED,
            "alerts_dry_run": ALERTS_DRY_RUN,
            "enabled_plugins": ENABLED_PLUGINS,
            "intelligence_pipeline_enabled": INTELLIGENCE_PIPELINE_ENABLED,
            "campaign_detection_enabled": CAMPAIGN_DETECTION_ENABLED,
            "phishkit_detection_enabled": PHISHKIT_DETECTION_ENABLED,
            "actor_profiling_enabled": ACTOR_PROFILING_ENABLED,
            "c2_detection_enabled": C2_DETECTION_ENABLED,
            "batch_clustering_enabled": BATCH_CLUSTERING_ENABLED,
            "batch_campaign_enabled": BATCH_CAMPAIGN_ENABLED,
            "batch_phishkit_enabled": BATCH_PHISHKIT_ENABLED,
        },
        "v2_risk": {
            "risk_threshold_high": RISK_THRESHOLD_HIGH,
            "risk_threshold_medium": RISK_THRESHOLD_MEDIUM,
            "high_risk_registrars": HIGH_RISK_REGISTRARS,
        },
        "v2_pipeline": {
            "dramatiq_broker_url": DRAMATIQ_BROKER_URL,
            "redis_cache_db": REDIS_CACHE_DB,
            "redis_rate_limit_db": REDIS_RATE_LIMIT_DB,
            "pipeline_timeout_seconds": PIPELINE_TIMEOUT_SECONDS,
            "batch_clustering_interval_s": BATCH_CLUSTERING_INTERVAL_S,
            "batch_campaign_interval_s": BATCH_CAMPAIGN_INTERVAL_S,
            "batch_phishkit_interval_s": BATCH_PHISHKIT_INTERVAL_S,
            "reconcile_ioc_batch": RECONCILE_IOC_BATCH,
            "reconcile_pipeline_batch": RECONCILE_PIPELINE_BATCH,
        },
    }