"""Tests for whois_query module."""
import pytest
from unittest.mock import Mock, patch

from plugins.whois_query import _validate_domain, get_whois_info


class TestDomainValidation:
    """Test domain name validation for security."""

    def test_valid_domain(self):
        assert _validate_domain("example.com") is True
        assert _validate_domain("sub.example.co.uk") is True
        assert _validate_domain("xn--example.com") is True

    def test_rejects_shell_metacharacters(self):
        assert _validate_domain("example.com; rm -rf /") is False
        assert _validate_domain("example.com|cat /etc/passwd") is False
        assert _validate_domain("example.com&&whoami") is False
        assert _validate_domain("example.com`id`") is False
        assert _validate_domain("example.com$(id)") is False
        assert _validate_domain("example.com\nwhoami") is False
        assert _validate_domain("example.com\r\nwhoami") is False
        assert _validate_domain("example.com<!DOCTYPE") is False

    def test_rejects_empty_domain(self):
        assert _validate_domain("") is False
        assert _validate_domain(None) is False

    def test_rejects_invalid_characters(self):
        assert _validate_domain("example com") is False
        assert _validate_domain("example\\com") is False


class TestGetWhoisInfo:
    """Test WHOIS info retrieval with mocked dependencies."""

    @patch("plugins.whois_query._validate_domain")
    @patch("plugins.whois_query.get_whois_info_python_whois")
    def test_uses_python_whois_first(self, mock_python_whois, mock_validate):
        mock_validate.return_value = True
        mock_python_whois.return_value = {"domain_name": "example.com"}

        result = get_whois_info("example.com")

        mock_validate.assert_called_once_with("example.com")
        mock_python_whois.assert_called_once_with("example.com")
        assert result["domain_name"] == "example.com"

    @patch("plugins.whois_query._validate_domain")
    def test_rejects_invalid_domain(self, mock_validate):
        mock_validate.return_value = False

        result = get_whois_info("example.com; rm -rf /")

        assert "error" in result
        assert "Invalid domain" in result["error"]

    @patch("plugins.whois_query._validate_domain")
    @patch("plugins.whois_query.get_whois_info_python_whois")
    @patch("plugins.whois_query.get_whois_info_subprocess")
    def test_fallback_to_subprocess(self, mock_subprocess, mock_python_whois, mock_validate):
        mock_validate.return_value = True
        mock_python_whois.side_effect = Exception("whois not found")
        mock_subprocess.return_value = {"domain_name": "example.com"}

        result = get_whois_info("example.com")

        mock_python_whois.assert_called_once_with("example.com")
        mock_subprocess.assert_called_once_with("example.com")
        assert result["domain_name"] == "example.com"

    @patch("plugins.whois_query._validate_domain")
    @patch("plugins.whois_query.get_whois_info_python_whois")
    @patch("plugins.whois_query.get_whois_info_subprocess")
    def test_both_methods_fail(self, mock_subprocess, mock_python_whois, mock_validate):
        mock_validate.return_value = True
        mock_python_whois.side_effect = Exception("whois not found")
        mock_subprocess.return_value = {"error": "whois command failed"}

        result = get_whois_info("example.com")

        assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
