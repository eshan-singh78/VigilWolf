"""Configuration management for the Domain Monitoring System.

This module centralizes all configuration settings for the monitoring system,
loading values from environment variables with sensible defaults.
"""
import os
from pathlib import Path

MONITORING_DATA_DIR = os.getenv("MONITORING_DATA_DIR", "./monitoring/data")
SNAPSHOTS_DIR = os.path.join(MONITORING_DATA_DIR, "snapshots")
GROUPS_FILE = os.path.join(MONITORING_DATA_DIR, "groups.json")
DOMAINS_FILE = os.path.join(MONITORING_DATA_DIR, "domains.json")

MAX_CONCURRENT_CHECKS = int(os.getenv("MAX_CONCURRENT_CHECKS", "10"))

DEFAULT_TIMEOUT_SECONDS = int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "30"))

SCREENSHOT_ENABLED = os.getenv("SCREENSHOT_ENABLED", "true").lower() == "true"

MAX_DOMAINS_PER_GROUP = int(os.getenv("MAX_DOMAINS_PER_GROUP", "100"))

SNAPSHOT_RETENTION_DAYS = int(os.getenv("SNAPSHOT_RETENTION_DAYS", "90"))

MIN_CHECK_FREQUENCY_SECONDS = int(os.getenv("MIN_CHECK_FREQUENCY_SECONDS", "60"))

MAX_ASSET_SIZE_BYTES = int(os.getenv("MAX_ASSET_SIZE_BYTES", "52428800"))  # 50MB default

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

RETRY_DELAY_SECONDS = float(os.getenv("RETRY_DELAY_SECONDS", "1.0"))

RETRY_BACKOFF_MULTIPLIER = float(os.getenv("RETRY_BACKOFF_MULTIPLIER", "2.0"))

ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "5"))

SCREENSHOT_WIDTH = int(os.getenv("SCREENSHOT_WIDTH", "1920"))
SCREENSHOT_HEIGHT = int(os.getenv("SCREENSHOT_HEIGHT", "1080"))

SCREENSHOT_FORMAT = os.getenv("SCREENSHOT_FORMAT", "png")

BROWSER_TYPE = os.getenv("BROWSER_TYPE", "chromium")

BROWSER_HEADLESS = os.getenv("BROWSER_HEADLESS", "true").lower() == "true"

SCHEDULER_TIMEZONE = os.getenv("SCHEDULER_TIMEZONE", "UTC")

SCHEDULER_MAX_INSTANCES = int(os.getenv("SCHEDULER_MAX_INSTANCES", "3"))

SCHEDULER_COALESCE = os.getenv("SCHEDULER_COALESCE", "true").lower() == "true"

ALLOWED_ORIGINS = os.getenv(
    'ALLOWED_ORIGINS', 
    'http://localhost:3000,http://127.0.0.1:3000'
).split(',')

RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "0"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

LOG_FILE = os.getenv("LOG_FILE", "")

JSON_LOGGING = os.getenv("JSON_LOGGING", "false").lower() == "true"

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
        'directories': {
            'monitoring_data_dir': MONITORING_DATA_DIR,
            'snapshots_dir': SNAPSHOTS_DIR,
            'groups_file': GROUPS_FILE,
            'domains_file': DOMAINS_FILE,
        },
        'monitoring': {
            'max_concurrent_checks': MAX_CONCURRENT_CHECKS,
            'default_timeout_seconds': DEFAULT_TIMEOUT_SECONDS,
            'screenshot_enabled': SCREENSHOT_ENABLED,
            'max_domains_per_group': MAX_DOMAINS_PER_GROUP,
            'snapshot_retention_days': SNAPSHOT_RETENTION_DAYS,
            'min_check_frequency_seconds': MIN_CHECK_FREQUENCY_SECONDS,
            'max_asset_size_bytes': MAX_ASSET_SIZE_BYTES,
        },
        'error_handling': {
            'max_retries': MAX_RETRIES,
            'retry_delay_seconds': RETRY_DELAY_SECONDS,
            'retry_backoff_multiplier': RETRY_BACKOFF_MULTIPLIER,
            'alert_threshold': ALERT_THRESHOLD,
        },
        'screenshot': {
            'width': SCREENSHOT_WIDTH,
            'height': SCREENSHOT_HEIGHT,
            'format': SCREENSHOT_FORMAT,
            'browser_type': BROWSER_TYPE,
            'browser_headless': BROWSER_HEADLESS,
        },
        'scheduler': {
            'timezone': SCHEDULER_TIMEZONE,
            'max_instances': SCHEDULER_MAX_INSTANCES,
            'coalesce': SCHEDULER_COALESCE,
        },
        'api': {
            'allowed_origins': ALLOWED_ORIGINS,
            'rate_limit_per_minute': RATE_LIMIT_PER_MINUTE,
        },
        'logging': {
            'log_level': LOG_LEVEL,
            'log_file': LOG_FILE,
            'json_logging': JSON_LOGGING,
        }
    }
