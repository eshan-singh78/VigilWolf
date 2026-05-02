"""Tests for middleware.auth.verify_api_key."""

import pytest
from unittest.mock import patch
from fastapi import HTTPException

from middleware.auth import verify_api_key


@patch("middleware.auth.API_KEY", "valid-secret-key")
def test_missing_key_returns_401_when_api_key_set():
    """When API_KEY is set, missing X-API-Key header returns 401 with 'required' in detail."""
    with pytest.raises(HTTPException) as exc_info:
        verify_api_key(x_api_key=None)

    assert exc_info.value.status_code == 401
    assert "required" in exc_info.value.detail.lower()


@patch("middleware.auth.API_KEY", "valid-secret-key")
def test_wrong_key_returns_401():
    """When API_KEY is set, wrong key returns 401 with 'invalid' in detail."""
    with pytest.raises(HTTPException) as exc_info:
        verify_api_key(x_api_key="wrong-key")

    assert exc_info.value.status_code == 401
    assert "invalid" in exc_info.value.detail.lower()


@patch("middleware.auth.API_KEY", "valid-secret-key")
def test_correct_key_returns_key():
    """When API_KEY matches, returns the key string."""
    result = verify_api_key(x_api_key="valid-secret-key")

    assert result == "valid-secret-key"


@patch("middleware.auth.ENVIRONMENT", "development")
@patch("middleware.auth.API_KEY", "")
def test_empty_api_key_bypasses_in_dev():
    """In development, empty API_KEY allows requests — returns empty string."""
    result = verify_api_key(x_api_key=None)

    assert result == ""


@patch("middleware.auth.ENVIRONMENT", "production")
@patch("middleware.auth.API_KEY", "")
def test_empty_api_key_raises_in_production():
    """In production, empty API_KEY raises 500."""
    with pytest.raises(HTTPException) as exc_info:
        verify_api_key(x_api_key=None)

    assert exc_info.value.status_code == 500