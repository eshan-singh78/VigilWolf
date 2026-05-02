"""Tests for the IOC extractor plugin."""
import pytest
from plugins.base import SnapshotContext, PluginType
from plugins.ioc_extractor import IOCExtractor


def _make_ctx(**overrides):
    """Build a SnapshotContext with sensible defaults, allowing overrides."""
    defaults = dict(
        snapshot_id="snap-001",
        domain="evil.com",
        html="",
        text="",
        forms=[],
        links=[],
        scripts=[],
        metadata={},
        snapshot_record={},
    )
    defaults.update(overrides)
    return SnapshotContext(**defaults)


# --- Test cases ---


def test_ioc_extractor_extracts_domains():
    ctx = _make_ctx(
        html='<a href="https://evil.com/phish">Login</a>',
        links=["https://evil.com/phish"],
        text="Visit evil.com now",
    )
    result = IOCExtractor().run(ctx)
    assert "evil.com" in result.findings["domains"]


def test_ioc_extractor_extracts_ips():
    ctx = _make_ctx(
        text="Servers at 8.8.8.8 and 192.168.1.1 and 10.0.0.1 and 172.16.5.5",
    )
    result = IOCExtractor().run(ctx)
    ips = result.findings["ips"]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips
    assert "10.0.0.1" not in ips
    assert "172.16.5.5" not in ips


def test_ioc_extractor_extracts_emails():
    ctx = _make_ctx(text="Contact admin@evil.com or support@phish.net")
    result = IOCExtractor().run(ctx)
    emails = result.findings["emails"]
    assert "admin@evil.com" in emails
    assert "support@phish.net" in emails


def test_ioc_extractor_extracts_urls():
    ctx = _make_ctx(
        links=["https://evil.com/login", "https://phish.com/steal"],
        html='<a href="https://extra.com/page">link</a>',
    )
    result = IOCExtractor().run(ctx)
    urls = result.findings["urls"]
    assert "https://evil.com/login" in urls
    assert "https://phish.com/steal" in urls
    assert "https://extra.com/page" in urls


def test_ioc_extractor_extracts_telegram():
    ctx = _make_ctx(
        text="Follow @phish_channel and visit t.me/badactor",
    )
    result = IOCExtractor().run(ctx)
    handles = result.findings["telegram_handles"]
    assert "@phish_channel" in handles
    assert "t.me/badactor" in handles


def test_ioc_extractor_extracts_crypto():
    btc_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    eth_addr = "0x" + "a" * 40
    ctx = _make_ctx(text=f"Send BTC to {btc_addr} or ETH to {eth_addr}")
    result = IOCExtractor().run(ctx)
    wallets = result.findings["crypto_wallets"]
    assert btc_addr in wallets
    assert eth_addr in wallets


def test_ioc_extractor_extracts_all():
    btc_addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    eth_addr = "0x" + "b" * 40
    ctx = _make_ctx(
        domain="phish.com",
        html=(
            '<a href="https://evil.com/login">Login</a>'
            '<a href="mailto:admin@evil.com">email</a>'
        ),
        text=(
            "Go to evil.com, contact admin@evil.com, "
            "IP 93.184.216.34, follow @darkchat99, "
            f"t.me/badgrp, BTC {btc_addr}, ETH {eth_addr}"
        ),
        links=["https://evil.com/login"],
    )
    result = IOCExtractor().run(ctx)
    assert "evil.com" in result.findings["domains"]
    assert "93.184.216.34" in result.findings["ips"]
    assert "https://evil.com/login" in result.findings["urls"]
    assert "admin@evil.com" in result.findings["emails"]
    assert "@darkchat99" in result.findings["telegram_handles"]
    assert "t.me/badgrp" in result.findings["telegram_handles"]
    assert btc_addr in result.findings["crypto_wallets"]
    assert eth_addr in result.findings["crypto_wallets"]


def test_ioc_extractor_clean_page():
    ctx = _make_ctx(text="Hello world, nothing suspicious here.")
    result = IOCExtractor().run(ctx)
    for key in ("domains", "ips", "urls", "emails", "telegram_handles", "crypto_wallets"):
        assert result.findings[key] == [], f"Expected empty list for {key}"


def test_ioc_extractor_zero_score():
    ctx = _make_ctx(text="evil.com 8.8.8.8 admin@evil.com")
    result = IOCExtractor().run(ctx)
    assert result.score_contribution == 0


def test_ioc_extractor_type_is_extraction():
    plugin = IOCExtractor()
    assert plugin.plugin_type == PluginType.EXTRACTION
    ctx = _make_ctx(text="test")
    result = plugin.run(ctx)
    assert result.plugin_type == PluginType.EXTRACTION