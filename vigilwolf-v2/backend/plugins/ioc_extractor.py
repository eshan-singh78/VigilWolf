"""IOC extraction plugin for VigilWolf v2.

Extracts indicators of compromise (domains, IPs, URLs, emails,
Telegram handles, crypto wallets) from snapshot context.
"""
import re
from urllib.parse import urlparse
from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

# --- Regex patterns ---

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)
_URL_HREF_RE = re.compile(r'href=["\']?(https?://[^\s"\'<>]+)', re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TELEGRAM_HANDLE_RE = re.compile(r"@[\w]{5,}")
_TELEGRAM_LINK_RE = re.compile(r"t\.me/[\w]+")
_BTC_RE = re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}")
_ETH_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP falls in a private / reserved range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True  # malformed, filter it out
    try:
        o1, o2 = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    # 10.0.0.0/8
    if o1 == 10:
        return True
    # 172.16.0.0/12
    if o1 == 172 and 16 <= o2 <= 31:
        return True
    # 192.168.0.0/16
    if o1 == 192 and o2 == 168:
        return True
    # 127.0.0.0/8
    if o1 == 127:
        return True
    return False


@register_plugin
class IOCExtractor(AnalysisPlugin):
    name = "ioc_extractor"
    version = "1.0.0"
    plugin_type = PluginType.EXTRACTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        domains = set()
        ips = set()
        urls = set()
        emails = set()
        telegram_handles = set()
        crypto_wallets = set()

        # --- Domains ---
        # From ctx.links (URLs)
        for link in ctx.links:
            parsed = urlparse(link)
            if parsed.hostname:
                domains.add(parsed.hostname)
        # From ctx.text via regex
        domains.update(_DOMAIN_RE.findall(ctx.text))

        # --- IPs ---
        for match in _IPV4_RE.findall(ctx.text):
            if not _is_private_ip(match):
                ips.add(match)

        # --- URLs ---
        # All URLs from ctx.links
        urls.update(ctx.links)
        # href patterns from ctx.html
        urls.update(_URL_HREF_RE.findall(ctx.html))

        # --- Emails ---
        emails.update(_EMAIL_RE.findall(ctx.text))
        # Also scan html for emails
        emails.update(_EMAIL_RE.findall(ctx.html))

        # --- Telegram handles ---
        for handle in _TELEGRAM_HANDLE_RE.findall(ctx.text):
            telegram_handles.add(handle)
        for link in _TELEGRAM_LINK_RE.findall(ctx.text):
            telegram_handles.add(link)
        # Also scan html
        for handle in _TELEGRAM_HANDLE_RE.findall(ctx.html):
            telegram_handles.add(handle)
        for link in _TELEGRAM_LINK_RE.findall(ctx.html):
            telegram_handles.add(link)

        # --- Crypto wallets ---
        crypto_wallets.update(_BTC_RE.findall(ctx.text))
        crypto_wallets.update(_ETH_RE.findall(ctx.text))
        # Also scan html
        crypto_wallets.update(_BTC_RE.findall(ctx.html))
        crypto_wallets.update(_ETH_RE.findall(ctx.html))

        findings = {
            "domains": sorted(domains),
            "ips": sorted(ips),
            "urls": sorted(urls),
            "emails": sorted(emails),
            "telegram_handles": sorted(telegram_handles),
            "crypto_wallets": sorted(crypto_wallets),
        }

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=0,
            confidence=1.0,
            tags=["ioc_extracted"],
            findings=findings,
        )