"""Login form detection plugin for VigilWolf v2.

Detects credential forms (password fields, hidden inputs, external form
actions).  Applies a legitimate-domain gate so that login forms on known
brand domains (e.g. paypal.com, chase.com) are scored as weak signals
rather than strong phishing indicators.
"""
import re
from urllib.parse import urlparse
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin


def _is_known_brand_domain(domain: str) -> bool:
    """Check if the domain belongs to a known brand's legitimate infrastructure.

    Uses the same BRAND_LEGIT_DOMAINS map as brand_match to avoid
    duplicating the whitelist.
    """
    try:
        from plugins.brand_match import BRAND_LEGIT_DOMAINS
    except ImportError:
        return False

    domain_lower = domain.lower()
    for _brand, legit_domains in BRAND_LEGIT_DOMAINS.items():
        for legit in legit_domains:
            if domain_lower == legit or domain_lower.endswith("." + legit):
                return True
    return False


@register_plugin
class LoginDetector(AnalysisPlugin):
    name = "login_detector"
    version = "2.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        score = 0
        tags = []
        findings = {}

        # Get page domain for external action detection
        domain = ctx.domain
        if "://" in domain:
            domain = urlparse(domain).netloc

        is_legit = _is_known_brand_domain(domain)

        # Check parsed forms for password fields
        has_password = any(f.get("has_password") for f in ctx.forms)
        has_hidden = any(f.get("has_hidden") for f in ctx.forms)
        external_action = False
        for f in ctx.forms:
            action = f.get("action", "")
            if action and action.startswith("http"):
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != domain:
                    external_action = True

        if has_password:
            if is_legit:
                # Login form on a known legit domain — weak signal only
                score += 5
                tags.append("login_form_legit_domain")
            else:
                score += 30
                tags.append("login_form_detected")
            findings["has_password_field"] = True

        if has_hidden:
            score += 5
            tags.append("hidden_field_detected")
            findings["has_hidden_fields"] = True

        if external_action:
            score += 5
            tags.append("external_form_action")
            findings["external_form_action"] = True

        # Hard signal: credential exfiltration (only on non-legit domains)
        if has_password and external_action and not is_legit:
            tags.append("credential_exfil")

        # Fallback: scan raw HTML for password fields
        if not has_password and 'type="password"' in ctx.html.lower():
            if is_legit:
                score += 5
                tags.append("login_form_legit_domain")
            else:
                score += 30
                tags.append("login_form_detected")
            findings["has_password_field"] = True

        if is_legit and score > 0:
            confidence = 0.20
        elif has_password:
            confidence = 0.95
        elif score > 0:
            confidence = 0.70
        else:
            confidence = 1.0

        return PluginResult(
            plugin_name=self.name, plugin_version=self.version,
            plugin_type=self.plugin_type, score_contribution=min(40, score),
            confidence=confidence, tags=tags, findings=findings,
        )