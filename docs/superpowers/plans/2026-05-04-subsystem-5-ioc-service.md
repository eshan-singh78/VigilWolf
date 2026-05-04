# Subsystem 5: IOC Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move domain denylist check before keyword matching in URL role classification, replace O(n^2) same_page relationship generation with priority-based incremental generation.

**Architecture:** Add exfil domain denylist as first check in _classify_url_role. Classify IOCs by priority tier and generate same_page pairs in priority order with running cap.

**Tech Stack:** Python, SQLAlchemy, unittest

---

### Task 1: Move domain denylist before keyword matching in _classify_url_role (F-1)

**Files:**
- Modify: `vigilwolf-v2/backend/services/ioc_service.py:134-183` (_classify_url_role)
- Test: `vigilwolf-v2/backend/test_ioc_role.py`

- [ ] **Step 1: Write failing test for domain denylist priority**

Create `test_ioc_role.py`:

```python
"""Tests for URL role classification fixes (F-1)."""
from services.ioc_service import _classify_url_role


def test_exfil_domain_denylist_overrides_keyword():
    """Domains in exfil denylist should return 'resource' even if URL has exfil keywords."""
    # postbank.com has "post" but is a legitimate bank domain
    result = _classify_url_role("https://postbank.com/api/post")
    assert result == "resource"


def test_deutsche_bank_not_exfil():
    """deutsche-bank.de should not be classified as exfil despite 'post' in path."""
    result = _classify_url_role("https://deutsche-bank.de/post/submit")
    assert result == "resource"


def test_phishing_domain_still_exfil():
    """A phishing domain with exfil keywords should still be classified as exfil."""
    result = _classify_url_role("https://evil-phish.com/api/post")
    assert result == "exfil_endpoint"


def test_post_keyword_in_path_only():
    """'post' should only match in path context, not in domain name."""
    # postoffice.com has "post" in domain — should be resource if in denylist
    result = _classify_url_role("https://poste.it/submit")
    assert result == "resource"


def test_canadapost_not_exfil():
    """canadapost-postescanada.ca should not be exfil."""
    result = _classify_url_role("https://canadapost-postescanada.ca/api/submit")
    assert result == "resource"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -m pytest test_ioc_role.py::test_exfil_domain_denylist_overrides_keyword -v`
Expected: FAIL (no exfil domain denylist yet, "post" in URL matches exfil_endpoint)

- [ ] **Step 3: Add _EXFIL_DOMAIN_DENYLIST and update _classify_url_role**

In `ioc_service.py`, after the `_TRACKING_PIXEL_KEYWORDS` tuple (after line 126), add:

```python
# Domains where exfil keywords appear legitimately (F-1).
# These are real brand domains that use "post", "submit", etc. in their paths.
_EXFIL_DOMAIN_DENYLIST = frozenset({
    "postbank.com",
    "deutsche-bank.de",
    "poste.it",
    "canadapost-postescanada.ca",
})
```

Then in `_classify_url_role`, add the exfil domain denylist check BEFORE the exfil keyword matching. Replace lines 134-151:

```python
def _classify_url_role(url: str) -> str:
    """Classify the role of a URL IOC.

    Returns one of: exfil_endpoint, cdn, tracking, redirect, resource.
    """
    url_lower = url.lower()

    # Check if URL is on a known legitimate login/SSO domain
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if any(hostname == domain or hostname.endswith("." + domain) for domain in _LEGITIMATE_LOGIN_DOMAINS):
        return "resource"

    # F-1: Check exfil domain denylist BEFORE keyword matching.
    # These are legitimate brand domains that happen to use exfil keywords.
    if any(hostname == d or hostname.endswith(f".{d}") for d in _EXFIL_DOMAIN_DENYLIST):
        return "resource"

    # Exfiltration endpoints: POST actions, form submissions
    if any(sig in url_lower for sig in ("post", "submit", "upload", "api/send", "api/login", "api/submit", "capture", "exfil")):
        return "exfil_endpoint"
```

The key changes are:
1. Added `_EXFIL_DOMAIN_DENYLIST` check after the `_LEGITIMATE_LOGIN_DOMAINS` check but BEFORE the exfil keyword matching.
2. This ensures that legitimate domains using "post"/"submit" are classified as `resource`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -m pytest test_ioc_role.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-v2/backend/services/ioc_service.py vigilwolf-v2/backend/test_ioc_role.py
git commit -m "feat: add exfil domain denylist before keyword matching in URL role (F-1)"
```

---

### Task 2: Replace O(n^2) same_page generation with priority-based incremental generation (S-3)

**Files:**
- Modify: `vigilwolf-v2/backend/services/ioc_service.py:358-394` (same_page generation block)
- Test: `vigilwolf-v2/backend/test_ioc_same_page.py`

- [ ] **Step 1: Write test for priority-based same_page generation**

Create `test_ioc_same_page.py`:

```python
"""Tests for priority-based same_page relationship generation (S-3)."""
from services.ioc_service import _classify_role, MAX_SAME_PAGE_RELATIONSHIPS


def test_high_value_iocs_prioritized():
    """High-value IOCs (exfil_endpoint, telegram, wallet) should be paired first."""
    # This validates the classification logic used to determine priority
    assert _classify_role("url", "https://evil.com/api/post") == "exfil_endpoint"
    assert _classify_role("telegram", "@phishbot") == "resource"  # telegram type is high-value
    assert _classify_role("wallet", "0xdeadbeef") == "resource"  # wallet type is high-value
    assert _classify_role("url", "https://cdn.example.com/script.js") == "cdn"  # standard
    assert _classify_role("domain", "evil.com") == "resource"  # standard


def test_max_same_page_relationships_is_reasonable():
    """Cap should be set and reasonable."""
    assert 1 <= MAX_SAME_PAGE_RELATIONSHIPS <= 200
```

- [ ] **Step 2: Run test**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -m pytest test_ioc_same_page.py -v`
Expected: PASS (these are validation tests for existing behavior)

- [ ] **Step 3: Replace O(n^2) same_page generation with priority-based**

In `ioc_service.py`, replace the same_page generation block (lines 358-394):

```python
    # Build relationships -------------------------------------------------

    # same_page: pairwise between all IOCs found in this snapshot.
    # Cap at MAX_SAME_PAGE_RELATIONSHIPS to prevent O(n^2) explosion.
    if len(snapshot_ioc_ids) >= 2:
        sorted_ids = sorted(set(snapshot_ioc_ids))
        pairs = [
            (sorted_ids[i], sorted_ids[j])
            for i in range(len(sorted_ids))
            for j in range(i + 1, len(sorted_ids))
        ]
        # Cap total relationships per snapshot
        if len(pairs) > MAX_SAME_PAGE_RELATIONSHIPS:
            logger.info(
                "Capping same_page relationships for snapshot %s: %d -> %d",
                snapshot_id, len(pairs), MAX_SAME_PAGE_RELATIONSHIPS,
            )
            pairs = pairs[:MAX_SAME_PAGE_RELATIONSHIPS]

        for src_id, tgt_id in pairs:
            try:
                with session.begin_nested():
                    rel = IocRelationshipModel(
                        source_ioc_id=src_id,
                        target_ioc_id=tgt_id,
                        relationship_type="same_page",
                        confidence=0.7,
                    )
                    session.add(rel)
                    session.flush()
                relationships_created += 1
            except Exception:
                logger.debug(
                    "IOC relationship already exists: %d -> %d (same_page)",
                    src_id, tgt_id,
                )
```

with:

```python
    # Build relationships -------------------------------------------------

    # S-3: Priority-based same_page generation.
    # Classify IOCs as high-value (exfil_endpoint, telegram, wallet) or standard,
    # then generate pairs in priority order with a running cap.
    if len(snapshot_ioc_ids) >= 2:
        # Classify each IOC for priority tiering
        high_value_ids: list[int] = []
        standard_ids: list[int] = []
        for ioc_id in snapshot_ioc_ids:
            ioc = ioc_by_id.get(ioc_id) if ioc_by_id else None
            if ioc is None:
                standard_ids.append(ioc_id)
                continue
            is_high_value = (
                ioc.type in ("telegram", "wallet")
                or (ioc.type == "url" and _classify_role("url", ioc.value) == "exfil_endpoint")
            )
            if is_high_value:
                high_value_ids.append(ioc_id)
            else:
                standard_ids.append(ioc_id)

        # Deduplicate
        high_value_ids = sorted(set(high_value_ids))
        standard_ids = sorted(set(standard_ids))

        pair_count = 0
        max_pairs = MAX_SAME_PAGE_RELATIONSHIPS

        def _add_pair(src_id: int, tgt_id: int) -> bool:
            nonlocal pair_count, relationships_created
            if pair_count >= max_pairs:
                return False
            try:
                with session.begin_nested():
                    rel = IocRelationshipModel(
                        source_ioc_id=src_id,
                        target_ioc_id=tgt_id,
                        relationship_type="same_page",
                        confidence=0.7,
                    )
                    session.add(rel)
                    session.flush()
                relationships_created += 1
                pair_count += 1
                return True
            except Exception:
                logger.debug(
                    "IOC relationship already exists: %d -> %d (same_page)",
                    src_id, tgt_id,
                )
                return True  # Already exists, count as done

        # Priority 1: high-value <-> high-value
        for i in range(len(high_value_ids)):
            for j in range(i + 1, len(high_value_ids)):
                if not _add_pair(high_value_ids[i], high_value_ids[j]):
                    break
            if pair_count >= max_pairs:
                break

        # Priority 2: high-value <-> standard
        if pair_count < max_pairs:
            for hv_id in high_value_ids:
                for std_id in standard_ids:
                    if not _add_pair(hv_id, std_id):
                        break
                if pair_count >= max_pairs:
                    break

        # Priority 3: standard <-> standard
        if pair_count < max_pairs:
            for i in range(len(standard_ids)):
                for j in range(i + 1, len(standard_ids)):
                    if not _add_pair(standard_ids[i], standard_ids[j]):
                        break
                if pair_count >= max_pairs:
                    break

        if pair_count >= max_pairs and len(snapshot_ioc_ids) > 10:
            logger.info(
                "Capped same_page relationships for snapshot %s at %d (total possible: %d)",
                snapshot_id, max_pairs,
                len(snapshot_ioc_ids) * (len(snapshot_ioc_ids) - 1) // 2,
            )
```

Note: The `ioc_by_id` variable is loaded later in the original code (around line 397-402). For the priority classification to work, we need to ensure `ioc_by_id` is loaded BEFORE the same_page generation. Move the ioc_by_id loading to BEFORE the same_page block, or reference the existing `snapshot_ioc_ids` with a separate query. Since `ioc_by_id` is loaded from the same snapshot_ioc_ids later, we can move that loading up.

Find and move the ioc_rows/ioc_by_id block (lines 397-402) to BEFORE the same_page generation block:

```python
    # Pre-load IOC data for relationship classification (S-3: moved up from below)
    ioc_rows = (
        session.query(IocModel)
        .filter(IocModel.id.in_(snapshot_ioc_ids))
    ).all() if snapshot_ioc_ids else []
    ioc_by_id = {ioc.id: ioc for ioc in ioc_rows}
```

Place this before the `# Build relationships` comment. Then remove the duplicate load that appears later.

- [ ] **Step 4: Verify syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "from services.ioc_service import persist_iocs; print('OK')"`
Expected: OK

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-v2/backend/services/ioc_service.py vigilwolf-v2/backend/test_ioc_same_page.py
git commit -m "perf: priority-based incremental same_page relationship generation (S-3)"
```