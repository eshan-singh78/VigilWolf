# Subsystem 4: C2 & Actor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix C2 score monotonic increase bug with decay, add actor merge pass to deduplicate fragment actors, optimize actor profiling memory usage.

**Architecture:** Replace monotonic C2 score condition with unconditional update + 14-day decay. Add post-comparison actor merge pass. Add latest-snapshot-only filter and yield_per for memory optimization.

**Tech Stack:** SQLAlchemy, Python stdlib, unittest

---

### Task 1: Fix C2 score bidirectional updates with confidence decay (H-3)

**Files:**
- Modify: `vigilwolf-v2/backend/worker.py:237-239` (C2 score update condition)
- Modify: `vigilwolf-v2/backend/services/c2_service.py:229-267` (score computation)

- [ ] **Step 1: Add confidence decay constants to c2_service.py**

In `c2_service.py`, after line 36 (`MAX_C2_IOC_CANDIDATES = 2000`), add:

```python
# Confidence decay: IOCs not seen within this many days get a decay multiplier.
C2_DECAY_THRESHOLD_DAYS = 14
C2_DECAY_MULTIPLIER = 0.7
```

- [ ] **Step 2: Add decay logic to rank_c2_candidates**

In `c2_service.py`, inside the `rank_c2_candidates` function, after line 230 (`for ioc in iocs:`) and the score/signals initialization (lines 231-232), add decay before signal accumulation:

Replace lines 230-254:

```python
    for ioc in iocs:
        score = 0.0
        signals: list[str] = []

        # Signal 1: POST/form target URL
        if _is_post_form_target(ioc.value, ioc.type):
            score += SCORE_POST_FORM_TARGET
            signals.append("post_form_target")

        # Signal 2: Used in 5+ domains (from bulk pre-load)
        domain_count = ioc_domain_count.get(ioc.id, 0)
        if domain_count >= MULTI_DOMAIN_THRESHOLD:
            score += SCORE_MULTI_DOMAIN
            signals.append(f"multi_domain:{domain_count}")

        # Signal 3: Linked to phishkit (from bulk pre-load)
        if ioc.id in ioc_has_phishkit:
            score += SCORE_LINKED_PHISHKIT
            signals.append("phishkit_linked")

        # Signal 4: Receives POST data / exfil_endpoint role (from bulk pre-load)
        if ioc_roles.get(ioc.id) == "exfil_endpoint":
            score += SCORE_RECEIVES_POST
            signals.append("receives_post_data")

        # Apply confidence decay for stale IOCs (H-3)
        if ioc.last_seen and (cutoff - ioc.last_seen).days > C2_DECAY_THRESHOLD_DAYS:
            score *= C2_DECAY_MULTIPLIER
            signals.append("decayed")

        # Only include IOCs with at least one signal.
        if score > 0.0:
```

Note: Only the decay block (4 lines after Signal 4) is new. The rest is existing code kept for context.

- [ ] **Step 3: Fix C2 score update to be unconditional in worker.py**

In `worker.py`, replace lines 237-240:

```python
                            if existing:
                                if candidate["c2_score"] > existing.c2_score:
                                    existing.c2_score = candidate["c2_score"]
                                    existing.signals = candidate.get("signals", [])
```

with:

```python
                            if existing:
                                # H-3: Unconditional update — decayed scores must be able
                                # to go down, not just up.
                                existing.c2_score = candidate["c2_score"]
                                existing.signals = candidate.get("signals", [])
```

- [ ] **Step 4: Verify syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "from services.c2_service import rank_c2_candidates; print('OK')"`
Expected: OK

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-v2/backend/services/c2_service.py vigilwolf-v2/backend/worker.py
git commit -m "fix: C2 score bidirectional updates with 14-day confidence decay (H-3)"
```

---

### Task 2: Add actor merge pass to deduplicate fragment actors (D-2)

**Files:**
- Modify: `vigilwolf-v2/backend/services/actor_service.py:419-560` (after pairwise loop)

- [ ] **Step 1: Add merge pass after pairwise comparison loop**

In `actor_service.py`, after the pairwise comparison loop ends (after line 560, where `actors_created` and `actors_updated` are accumulated), add the merge pass before the final return:

Find the line `logger.info(` or the `return` statement at the end of `profile_actors`. Add before the return:

```python
    # D-2: Merge pass — deduplicate actors that share the same campaign.
    # When multiple actors are created for the same campaign (due to
    # pairwise comparisons), merge them into a single survivor.
    campaign_to_actors: dict[str, list[str]] = {}
    all_actor_links = session.query(ActorCampaignModel).filter(
        ActorCampaignModel.campaign_id.in_(campaign_ids)
    ).all()
    for link in all_actor_links:
        campaign_to_actors.setdefault(link.campaign_id, []).append(link.actor_id)

    actors_merged = 0
    for campaign_id, actor_ids in campaign_to_actors.items():
        if len(actor_ids) < 2:
            continue

        # Load all actors sharing this campaign
        merge_actors = (
            session.query(ActorModel)
            .filter(ActorModel.id.in_(actor_ids))
            .all()
        )
        if len(merge_actors) < 2:
            continue

        # Pick survivor: highest confidence_score
        survivor = max(merge_actors, key=lambda a: a.confidence_score or 0.0)
        non_survivors = [a for a in merge_actors if a.id != survivor.id]

        for ns in non_survivors:
            try:
                with session.begin_nested():
                    # Re-link all campaigns from non-survivor to survivor
                    ns_links = session.query(ActorCampaignModel).filter(
                        ActorCampaignModel.actor_id == ns.id
                    ).all()
                    for link in ns_links:
                        # Check if survivor already has this campaign
                        existing = session.query(ActorCampaignModel).filter(
                            ActorCampaignModel.actor_id == survivor.id,
                            ActorCampaignModel.campaign_id == link.campaign_id,
                        ).first()
                        if existing is None:
                            session.add(ActorCampaignModel(
                                actor_id=survivor.id,
                                campaign_id=link.campaign_id,
                            ))
                        session.delete(link)

                    # Delete the non-survivor actor
                    session.delete(ns)
                    actors_merged += 1
            except Exception:
                logger.debug(
                    "Actor merge failed for non-survivor %s into %s",
                    ns.id[:8], survivor.id[:8],
                )

    if actors_merged:
        logger.info("Merged %d duplicate actors into survivors", actors_merged)
```

Then update the return statement to include merged count. Find the existing return and change:

```python
    return {"actors_created": actors_created, "actors_updated": actors_updated}
```

to:

```python
    return {"actors_created": actors_created, "actors_updated": actors_updated, "actors_merged": actors_merged}
```

- [ ] **Step 2: Verify syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "from services.actor_service import profile_actors; print('OK')"`
Expected: OK

- [ ] **Step 3: Commit**

```bash
git add vigilwolf-v2/backend/services/actor_service.py
git commit -m "feat: add actor merge pass to deduplicate fragment actors (D-2)"
```

---

### Task 3: Optimize actor profiling memory usage (S-2)

**Files:**
- Modify: `vigilwolf-v2/backend/services/actor_service.py:246-340` (pre-loading section)

- [ ] **Step 1: Add memory constants**

In `actor_service.py`, after line 39 (`MIN_INFRA_OVERLAP_COUNT = 3`), add:

```python
# S-2: Memory optimization limits
MAX_DOMAINS_PER_CAMPAIGN_PROFILE = 500
MAX_TOTAL_DOMAINS_WARNING = 25000
```

- [ ] **Step 2: Filter snapshot pre-loading to latest snapshot per domain only**

In `actor_service.py`, replace the snapshot pre-loading block (lines 319-326):

```python
    # Pre-load domain -> snapshot mappings (filtered to relevant domains only)
    domain_snapshot_map: dict[str, set[str]] = {}
    if relevant_domain_ids:
        filtered_snapshots = session.query(SnapshotModel).filter(
            SnapshotModel.domain_id.in_(relevant_domain_ids)
        ).all()
        for s in filtered_snapshots:
            domain_snapshot_map.setdefault(s.domain_id, set()).add(s.id)
```

with:

```python
    # Pre-load domain -> snapshot mappings (S-2: only latest snapshot per domain)
    domain_snapshot_map: dict[str, set[str]] = {}
    if relevant_domain_ids:
        # Only load the most recent snapshot per domain to reduce memory
        from sqlalchemy import func as sa_func
        latest_snapshot_ids = (
            session.query(sa_func.max(SnapshotModel.id))
            .filter(SnapshotModel.domain_id.in_(relevant_domain_ids))
            .group_by(SnapshotModel.domain_id)
            .all()
        )
        filtered_snapshots = session.query(SnapshotModel).filter(
            SnapshotModel.id.in_([sid for (sid,) in latest_snapshot_ids])
        ).all()
        for s in filtered_snapshots:
            domain_snapshot_map.setdefault(s.domain_id, set()).add(s.id)
```

- [ ] **Step 3: Add domain count warning**

In `actor_service.py`, after the `relevant_domain_ids` set is built (around line 317), add:

```python
    total_domain_count = sum(len(dids) for dids in cluster_domain_map.values() if dids)
    if total_domain_count > MAX_TOTAL_DOMAINS_WARNING:
        logger.warning(
            "profile_actors: %d total domains across campaigns exceeds %d; "
            "consider reducing CAMPAIGN_WINDOW_DAYS",
            total_domain_count, MAX_TOTAL_DOMAINS_WARNING,
        )
```

- [ ] **Step 4: Add yield_per to large query**

In `actor_service.py`, add `yield_per` to the SnapshotModel query for IOC mapping (around line 336):

```python
        filtered_occurrences = session.query(IocOccurrenceModel).filter(
            IocOccurrenceModel.snapshot_id.in_(relevant_snapshot_ids)
        ).yield_per(500).all()
```

- [ ] **Step 5: Verify syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "from services.actor_service import profile_actors; print('OK')"`
Expected: OK

- [ ] **Step 6: Commit**

```bash
git add vigilwolf-v2/backend/services/actor_service.py
git commit -m "perf: optimize actor profiling memory with latest-snapshot filter and yield_per (S-2)"
```