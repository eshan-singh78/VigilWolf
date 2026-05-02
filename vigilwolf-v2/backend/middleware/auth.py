"""Shared authentication dependency for VigilWolf v2 API routes."""
import hmac
import logging
from typing import Optional

from fastapi import Header, HTTPException

from config import API_KEY, ENVIRONMENT

logger = logging.getLogger(__name__)


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """FastAPI dependency that enforces API key authentication.

    In production, API_KEY MUST be set — the server refuses to start without it.
    In development, a missing API_KEY is allowed but a warning is logged.
    """
    if not API_KEY:
        if ENVIRONMENT == "production":
            raise HTTPException(
                status_code=500,
                detail="API_KEY is not configured. Set the API_KEY environment variable.",
            )
        logger.warning("API_KEY is empty — authentication is DISABLED. Set API_KEY in production.")
        return ""

    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header is required")

    if not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return x_api_key


def optional_api_key(x_api_key: Optional[str] = Header(None)) -> Optional[str]:
    """Non-raising auth dependency for health/metrics endpoints."""
    if not API_KEY:
        return None
    if x_api_key and hmac.compare_digest(x_api_key, API_KEY):
        return x_api_key
    return None