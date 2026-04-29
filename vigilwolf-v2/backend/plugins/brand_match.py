"""Brand Impersonation Engine for VigilWolf v2.

Detects brand impersonation by composing multiple signals rather than
treating brand presence alone as a strong indicator.

Signals composed:
  1. Legitimate Domain Filter (hard gate) — known legit domains get score=0
  2. Brand presence — weak signal only (5 points)
  3. Impersonation signals — login form, suspicious keywords, typosquatting
  4. Combined impersonation score — strong signal when 2+ signals align
"""
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from plugins.base import AnalysisPlugin, PluginResult, SnapshotContext, PluginType
from plugins.registry import register_plugin

MAJOR_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix",
    "facebook", "chase", "bankofamerica", "wellsfargo", "citibank",
    "amex", "visa", "mastercard", "adobe", "dropbox", "shopify",
    "stripe", "dhl",
]

HOMOGLYPH_MAP = {"1": "l", "0": "o", "3": "e", "nn": "m", "rn": "m"}

# Known legitimate domains for each brand.  Subdomains of these are also
# considered legitimate (e.g. mail.google.com, login.microsoftonline.com).
BRAND_LEGIT_DOMAINS: dict[str, list[str]] = {
    "google": ["google.com", "google.co.uk", "google.ca", "google.de",
               "googleapis.com", "googlecloud.com", "google.dev",
               "android.com", "youtube.com", "g.co", "goo.gl"],
    "apple": ["apple.com", "icloud.com", "mzstatic.com",
              "apps.apple.com", "podcasts.apple.com", "support.apple.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca",
               "amazonaws.com", "aws.amazon.com", "docs.aws.amazon.com",
               "cloudfront.net", "aws.amazon.com"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "microsoftstore.com",
                  "office.com", "office365.com", "azure.com",
                  "live.com", "outlook.com", "onenote.com", "skype.com",
                  "visualstudio.com", "github.com", "linkedin.com",
                  "xbox.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "fbcdn.net", "instagram.com",
                 "whatsapp.com", "meta.com"],
    "chase": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com", "ml.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citibank.com", "citibankonline.com", "citi.com"],
    "amex": ["americanexpress.com", "aexp-static.com"],
    "visa": ["visa.com"],
    "mastercard": ["mastercard.com", "mastercard.us"],
    "adobe": ["adobe.com", "adobe.io", "behance.net", "typekit.com"],
    "dropbox": ["dropbox.com", "dropboxapi.com", "dropboxstatic.com"],
    "shopify": ["shopify.com", "myshopify.com", "shopifycdn.com"],
    "stripe": ["stripe.com", "stripecdn.com"],
    "dhl": ["dhl.com", "dhl.de", "dhl.co.uk"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
}

IMPERSONATION_KEYWORDS = [
    "verify", "secure", "login", "signin", "sign in", "update",
    "confirm", "account", "unlock", "suspend", "restore", "recover",
    "password", "credential", "authenticate", "immediately",
]

TYPOSQUAT_SIMILARITY_THRESHOLD = 0.80


def _normalize(text: str) -> str:
    """Apply homoglyph normalization to text for brand matching."""
    result = text.lower()
    for src, dst in sorted(HOMOGLYPH_MAP.items(), key=lambda x: -len(x[0])):
        result = result.replace(src, dst)
    return result


def is_legit_domain(domain: str, brand: str) -> bool:
    """Check whether a domain is a known legitimate domain for a brand.

    Matches exact domain or any subdomain of a legit domain.
    e.g. mail.google.com matches google.com
         google-secure-login.com does NOT match google.com
    """
    legit_domains = BRAND_LEGIT_DOMAINS.get(brand, [])
    domain_lower = domain.lower()
    for legit in legit_domains:
        if domain_lower == legit or domain_lower.endswith("." + legit):
            return True
    return False


def _domain_similarity(domain: str, brand: str) -> float:
    """Compute similarity between a domain's base name and a brand name.

    Strips TLD and compares the second-level domain against the brand.
    e.g. paypa1.com vs paypal → high similarity
         google.com vs google → 1.0
    """
    parts = domain.lower().split(".")
    if len(parts) < 2:
        sld = parts[0] if parts else ""
    else:
        sld = parts[-2]

    normalized_sld = _normalize(sld)
    return SequenceMatcher(None, normalized_sld, brand).ratio()


def _has_login_form(ctx: SnapshotContext) -> bool:
    """Check if the page contains a login/credential form."""
    for form in ctx.forms:
        if form.get("has_password"):
            return True
    return False


def _has_impersonation_keywords(ctx: SnapshotContext) -> bool:
    """Check if the page text contains impersonation-related keywords."""
    text_lower = ctx.text.lower()
    count = sum(1 for kw in IMPERSONATION_KEYWORDS if kw in text_lower)
    return count >= 2


@register_plugin
class BrandMatch(AnalysisPlugin):
    name = "brand_match"
    version = "2.0.0"
    plugin_type = PluginType.DETECTION

    def run(self, ctx: SnapshotContext) -> PluginResult:
        tags = []
        findings: dict = {}
        score = 0
        confidence = 1.0
        matched_brands = []
        is_legit = False

        # Normalize the domain for matching
        domain = ctx.domain
        if "://" in domain:
            domain = urlparse(domain).netloc
        normalized_domain = _normalize(domain)

        # Normalize page text for matching
        normalized_text = _normalize(ctx.text)

        for brand in MAJOR_BRANDS:
            brand_in_domain = brand in normalized_domain
            content_mentions = len(re.findall(rf"\b{re.escape(brand)}\b", normalized_text))
            brand_in_content = content_mentions >= 2

            if not (brand_in_domain or brand_in_content):
                continue

            # ── Hard gate: legitimate domain check (runs first) ─────────
            if is_legit_domain(domain, brand):
                is_legit = True
                tags.append(f"legit_brand_domain:{brand}")
                continue

            # ── Brand detected on non-legit domain ──────────────────────
            matched_brands.append(brand)
            tags.append(f"{brand}_detected")

            # Brand alone is a weak signal
            brand_score = 5

            # ── Compose impersonation signals ───────────────────────────
            impersonation_score = 0

            has_login = _has_login_form(ctx)
            if has_login:
                impersonation_score += 15
                tags.append("brand_on_login_page")

            has_keywords = _has_impersonation_keywords(ctx)
            if has_keywords:
                impersonation_score += 10
                tags.append("brand_with_intent_keywords")

            # Typosquatting check (domain name similarity to brand)
            similarity = _domain_similarity(domain, brand)
            if similarity > TYPOSQUAT_SIMILARITY_THRESHOLD:
                impersonation_score += 15
                tags.append(f"typosquat:{brand}")
                findings["typosquat_similarity"] = round(similarity, 3)
            elif brand_in_domain and similarity > 0.5:
                # Brand string in domain but low structural similarity
                # (e.g. "paypal" in "paypal-confirm-2024.xyz" — keyword stuffing)
                impersonation_score += 5

            # Brand on non-legit domain with external domain bonus
            if brand_in_content and not brand_in_domain:
                impersonation_score += 5
                tags.append("brand_mismatch_domain")

            # ── Combine: strong signal when 2+ impersonation signals ────
            if impersonation_score >= 20:
                score += 25
                confidence = 0.90
            elif impersonation_score >= 10:
                score += 15
                confidence = 0.80
            else:
                score += brand_score
                confidence = 0.50

        # ── Final adjustment ────────────────────────────────────────────
        if matched_brands:
            tags.append("brand_match")
            findings["matched_brands"] = matched_brands
        elif is_legit:
            # Legit brand domain — explicitly zero score, low confidence
            score = 0
            confidence = 0.10
            tags = [t for t in tags if t != "brand_match"]

        return PluginResult(
            plugin_name=self.name,
            plugin_version=self.version,
            plugin_type=self.plugin_type,
            score_contribution=score,
            confidence=confidence,
            tags=tags,
            findings=findings,
        )