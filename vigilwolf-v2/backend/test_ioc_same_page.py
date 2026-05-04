"""Tests for priority-based same_page relationship generation (S-3)."""
from services.ioc_service import _classify_role, MAX_SAME_PAGE_RELATIONSHIPS


def test_high_value_exfil_endpoint():
    assert _classify_role("url", "https://evil.com/api/post") == "exfil_endpoint"


def test_high_value_telegram():
    assert _classify_role("telegram", "@phishbot") == "resource"  # telegram type is high-value


def test_high_value_wallet():
    assert _classify_role("wallet", "0xdeadbeef") == "resource"  # wallet type is high-value


def test_standard_cdn():
    assert _classify_role("url", "https://cdn.example.com/script.js") == "cdn"


def test_standard_domain():
    assert _classify_role("domain", "evil.com") == "resource"


def test_max_same_page_relationships_is_reasonable():
    assert 1 <= MAX_SAME_PAGE_RELATIONSHIPS <= 200