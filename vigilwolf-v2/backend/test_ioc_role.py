"""Tests for URL role classification fixes (F-1)."""
from services.ioc_service import _classify_url_role


def test_exfil_domain_denylist_overrides_keyword():
    result = _classify_url_role("https://postbank.com/api/post")
    assert result == "resource"


def test_deutsche_bank_not_exfil():
    result = _classify_url_role("https://deutsche-bank.de/post/submit")
    assert result == "resource"


def test_phishing_domain_still_exfil():
    result = _classify_url_role("https://evil-phish.com/api/post")
    assert result == "exfil_endpoint"


def test_post_keyword_in_path_only():
    result = _classify_url_role("https://poste.it/submit")
    assert result == "resource"


def test_canadapost_not_exfil():
    result = _classify_url_role("https://canadapost-postescanada.ca/api/submit")
    assert result == "resource"