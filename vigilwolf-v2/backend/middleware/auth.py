"""Shared authentication dependency for VigilWolf v2 API routes."""
import hmac
from typing import Optional

from fastapi import Header, HTTPException

from config import API_KEY


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """FastAPI dependency that enforces API key authentication.

    When API_KEY is configured (non-empty), requests must include a matching
    X-API-Key header. Uses hmac.compare_digest for timing-safe comparison.
    When API_KEY is empty (development default), auth is disabled.
    """
    if not API_KEY:
        return ""

    if not x_api_key or not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return x_api_key


def optional_api_key(x_api_key: Optional[str] = Header(None)) -> Optional[str]:
    """Non-raising auth dependency for health/metrics endpoints."""
    if not API_KEY:
        return None
    if x_api_key and hmac.compare_digest(x_api_key, API_KEY):
        return x_api_key
    return None