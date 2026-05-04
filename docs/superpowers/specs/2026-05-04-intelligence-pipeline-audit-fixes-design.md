# VigilWolf V2 Intelligence Pipeline Audit Fixes

**Date:** 2026-05-04
**Status:** Approved
**Approach:** Targeted surgical fixes — no refactoring, no new abstractions

---

## Scope

15 issues from the production audit, grouped into 5 independent subsystems
implemented in parallel. Each fix targets the exact failure point identified
in the audit.

---

## Subsystem 1: Schema Fixes (C-1, H-5, D-3)

### C-1: Add `asn` and `registrar` columns

**database.py changes:**
- `DomainIpModel`: add `asn = Column(String(20), nullable=True)`
- `DomainModel`: add `registrar = Column(String(200), nullable=True)`

**New migration `015_add_asn_registrar_columns.py`:**
- `down_revision = "014_remove_onupdate_domain_processing_plugin_weight"`
- Add both columns as nullable (no data backfill needed)
- Also remove `onupdate=utc_now` from `ClusteringWatermarkModel.updated_at` (D-5)

**Wire enrichment data:**
- In `orchestrate_analysis()`, after whois_enricher runs: if findings contain `registrar`, update `DomainModel.registrar` for the current domain
- In `orchestrate_analysis()`, after dns_enricher runs: if DNS resolution returns ASN data, update `DomainIpModel.asn` for resolved IPs

### H-5: Fix Alembic migration collisions

Re-chain migrations to form a single linear chain:

| File | revision | down_revision |
|------|----------|---------------|
| 004_intelligence_unique_constraints.py | 004_intelligence_unique_constraints | 003_performance_indexes |
| 004_pipeline_status.py | 004_pipeline_status | 004_intelligence_unique_constraints |
| 005_clustering_watermark.py | 005_clustering_watermark | 004_pipeline_status |
| 005_phishkit_unique_constraint.py | 005_phishkit_unique_constraint | 005_clustering_watermark |
| 006+ | (unchanged revision IDs) | 005_phishkit_unique_constraint |

Each subsequent migration's `down_revision` must chain from the previous.

### D-3: Phone and wallet normalization

**ioc_service.py `_normalize_ioc_value()` additions:**
- `phone` case: strip all non-digit characters. If 11 digits starting with `1`, prefix `+`. If 10 digits, prefix `+1`. Otherwise prefix `+`.
- `wallet` case: if value starts with `0x` (EVM address), lowercase. Otherwise preserve original (Bitcoin checksums are case-sensitive).

---

## Subsystem 2: Pipeline Orchestration (C-2, C-3, C-4, H-4)

### C-2: Convert per-snapshot triggers to periodic batch

**intelligence_worker.py changes:**
- Remove direct calls to `cluster_snapshot()`, `detect_campaigns_for_snapshot()`, `detect_phishkits_for_snapshot()` from `run_intelligence_pipeline()`
- Replace with stage status markers: `_record_stage_status(snapshot_id, stage, "queued")`
- Keep `_emit_intelligence_update()` at end of pipeline

**worker.py additions:**
- 3 new periodic schedulers with daemon threads:
  - `BATCH_CLUSTERING_INTERVAL_S = 300` (5 min)
  - `BATCH_CAMPAIGN_INTERVAL_S = 600` (10 min)
  - `BATCH_PHISHKIT_INTERVAL_S = 300` (5 min)
- 3 new Dramatiq actors: `batch_clustering_actor`, `batch_campaign_actor`, `batch_phishkit_actor`
- Each calls the corresponding service's main function with a fresh session
- Each records aggregated pipeline status upon completion
- Start all 3 in `lifespan()` alongside existing schedulers

**config.py additions:**
- `BATCH_CLUSTERING_ENABLED`, `BATCH_CAMPAIGN_ENABLED`, `BATCH_PHISHKIT_ENABLED` feature flags (default true)
- `BATCH_CLUSTERING_INTERVAL_S`, `BATCH_CAMPAIGN_INTERVAL_S`, `BATCH_PHISHKIT_INTERVAL_S` intervals

### C-3: Watermark race condition

**clustering_service.py `_set_watermark()` change:**
- Replace simple UPDATE with:
  ```sql
  UPDATE clustering_watermarks
  SET last_processed_at = CASE
    WHEN last_processed_at < :ts THEN :ts
    ELSE last_processed_at
  END
  WHERE id = :id
  ```
- This ensures watermarks only advance forward, using CASE for SQLite compatibility

**PostgreSQL advisory locks:**
- Before each clustering pass, execute `SELECT pg_advisory_lock(hashtext(:watermark_id))`
- After pass completes, `SELECT pg_advisory_unlock(hashtext(:watermark_id))`
- For SQLite: skip advisory lock (single-writer model)
- Implement via `session.execute(text("SELECT ..."))` with a PostgreSQL detection check

**Same fix in phishkit_service.py `_set_watermark()`.**

### C-4: Plugin retry idempotency

**worker.py `orchestrate_analysis()` change:**
- Before `session.add(AnalysisResultModel(...))` on line 884:
  ```python
  existing_result = (
      session.query(AnalysisResultModel)
      .filter_by(snapshot_id=ctx.snapshot_id, plugin_name=result.plugin_name)
      .first()
  )
  if existing_result is not None:
      # Already persisted from previous attempt — skip insert
  else:
      session.add(AnalysisResultModel(...))
  ```
- This prevents IntegrityError on retry and allows the status update to "done" to proceed correctly

### H-4: Scale reconciliation batch limits

**config.py additions:**
- `RECONCILE_IOC_BATCH = 200` (up from 50)
- `RECONCILE_PIPELINE_BATCH = 100` (up from 20)

**reconciliation_service.py changes:**
- Replace hardcoded `.limit(50)` with `config.RECONCILE_IOC_BATCH`
- Replace hardcoded `.limit(20)` with `config.RECONCILE_PIPELINE_BATCH`
- Add backlog warning: if query returns `>= limit` rows, log a warning that backlog may be growing

**New: `reconcile_cluster_counts()`**
- Add to `reconciliation_service.py`
- For each cluster where `domain_count != SELECT COUNT(*) FROM cluster_members WHERE cluster_id = :id`, update the count
- Called from `run_periodic_reconciliation()`
- Also addresses D-1 (domain_count drift)

---

## Subsystem 3: Clustering & Campaign (H-1, H-2, F-2)

### H-1: Short brand keyword allowlist

**campaign_service.py additions:**
- Add `_SHORT_BRAND_ALLOWLIST = {"dhl": "DHL", "ups": "UPS", "pnc": "PNC"}`
- Change `_detect_brand()` filter from:
  ```python
  if len(keyword) < _BRAND_MIN_LENGTH or keyword.lower() in _BRAND_DENYLIST:
  ```
  to:
  ```python
  if len(keyword) < _BRAND_MIN_LENGTH and keyword.lower() not in _SHORT_BRAND_ALLOWLIST:
      continue
  if keyword.lower() in _BRAND_DENYLIST:
      continue
  ```
- Short brand keywords in the allowlist bypass the min-length check but still go through the denylist

### H-2: Campaign merge when kit_signature is missing

**campaign_service.py additions:**
- Add helper `_count_shared_iocs(cluster_domain_ids, campaign_id, session)`:
  ```sql
  SELECT COUNT(DISTINCT ioc_occurrences.ioc_id)
  FROM ioc_occurrences
  JOIN snapshots ON snapshots.id = ioc_occurrences.snapshot_id
  JOIN cluster_members ON cluster_members.domain_id = snapshots.domain_id
  JOIN campaign_clusters ON campaign_clusters.cluster_id = cluster_members.cluster_id
  WHERE campaign_clusters.campaign_id = :campaign_id
  AND snapshots.domain_id IN :cluster_domain_ids
  ```
- In the `sig_missing` branch of `detect_campaigns()`:
  - If `sig_missing` and both target the same brand, call `_count_shared_iocs`
  - If shared IOCs >= 3, allow merge (link cluster to existing campaign)
  - If shared IOCs < 3, create separate campaign (current behavior)

### F-2: Brand detection against SLD only

**campaign_service.py `_detect_brand()` change:**
- Extract SLD from each hostname: split on `.`, take the second-to-last segment
  - `login.paypal.evil.com` → SLD = `evil`
  - `paypal-phish.com` → SLD = `paypal-phish`
  - `paypal.com` → SLD = `paypal`
- Match brand keywords against the SLD instead of the full hostname
- Implementation: `_extract_sld(hostname) -> str` helper that handles edge cases
- Use a hardcoded `_TWO_PART_TLDS` set (e.g., `co.uk`, `co.jp`, `com.au`, `co.nz`, `co.za`, `com.br`, `com.cn`) to detect when the TLD is 2 parts and the SLD is the third-to-last segment
- For 2-part TLDs: `login.paypal.co.uk` → SLD = `paypal` (not `co`)
- For standard TLDs: `login.paypal.com` → SLD = `paypal`

---

## Subsystem 4: C2 & Actor (H-3, D-2, S-2)

### H-3: C2 score bidirectional updates with decay

**worker.py `run_periodic_c2_ranking()` change:**
- Replace `if candidate["c2_score"] > existing.c2_score:` with unconditional overwrite
- Add confidence decay in `c2_service.py rank_c2_candidates()`:
  - After computing `score` for each IOC, check if `IocModel.last_seen` is > 14 days old
  - If so, apply `score *= 0.7` decay multiplier
  - This causes stale C2 candidates to naturally decay without manual cleanup

### D-2: Actor merge pass

**actor_service.py `profile_actors()` addition:**
- After the pairwise comparison loop, add a merge pass:
  1. Build `campaign_to_actors: dict[str, set[str]]` — map each campaign_id to all actor_ids linked to it
  2. For each campaign with > 1 actor, collect all actors sharing that campaign
  3. For each merge group: pick actor with highest `confidence_score` as survivor
  4. Delete non-survivor actors, re-link their campaigns to survivor via ActorCampaignModel
  5. Update survivor's `fingerprint` and `label` to reflect merged campaigns
  6. Update survivor's `meta["campaign_ids"]` to include all merged campaigns
- Use `session.begin_nested()` for each merge group to isolate failures

### S-2: Actor profiling memory optimization

**actor_service.py changes:**
- Add `MAX_DOMAINS_PER_CAMPAIGN_PROFILE = 500`
- When pre-loading snapshot-IOC mappings, filter to only the most recent snapshot per domain:
  ```python
  subq = session.query(func.max(SnapshotModel.id)).group_by(SnapshotModel.domain_id).correlate(...)
  ```
  This reduces the snapshot-IOC join from ~5 snapshots/domain to 1
- Add `yield_per(500)` to large query results where applicable
- Log warning if total domain count across all campaigns exceeds 25K

---

## Subsystem 5: IOC Service (F-1, S-3)

### F-1: URL role classification — domain denylist before keyword matching

**ioc_service.py `_classify_url_role()` changes:**
- Move the legitimate domain denylist check to be the FIRST check in the function (before exfil keyword matching)
- Add `_EXFIL_DOMAIN_DENYLIST` containing domains where exfil keywords appear legitimately:
  - `postbank.com`, `deutsche-bank.de`, `poste.it`, `canadapost-postescanada.ca`
- After extracting `hostname`, check: if hostname matches `_EXFIL_DOMAIN_DENYLIST` (exact or subdomain), return `resource`
- Refine exfil keyword matching: `post` only matches in path context after a `/` (e.g., `/post`, `/api/post`), not in the domain name itself

### S-3: Incremental same_page relationship generation

**ioc_service.py `persist_iocs()` changes:**
- Replace O(n^2) generation + cap with priority-based incremental generation:
  1. Classify each IOC as "high-value" (role=exfil_endpoint, type=telegram, type=wallet) or "standard"
  2. Generate pairs in priority order:
     - high-value ↔ high-value (most important)
     - high-value ↔ standard
     - standard ↔ standard (least important, likely truncated)
  3. Stop when `MAX_SAME_PAGE_RELATIONSHIPS` reached
- Implementation: sort `snapshot_ioc_ids` by priority, then use nested loops with a running counter that breaks at the cap

---

## Files Modified

| File | Changes |
|------|---------|
| database.py | Add asn, registrar columns; remove ClusteringWatermarkModel onupdate |
| config.py | Add batch scheduler flags/intervals; reconciliation batch sizes |
| worker.py | Add batch schedulers/actors; fix C2 score update; fix plugin retry idempotency |
| intelligence_worker.py | Remove per-snapshot batch calls; add queued status markers |
| clustering_service.py | Fix watermark race; add advisory locks |
| campaign_service.py | Short brand allowlist; IOC-based campaign merge; SLD brand matching |
| actor_service.py | Actor merge pass; memory optimization |
| c2_service.py | Bidirectional C2 score; confidence decay |
| ioc_service.py | Phone/wallet normalization; URL role denylist; priority same_page generation |
| reconciliation_service.py | Configurable batch sizes; backlog warning; cluster count reconciliation |
| phishkit_service.py | Fix watermark race |
| migrations/versions/004_pipeline_status.py | Fix down_revision chain |
| migrations/versions/005_clustering_watermark.py | Fix down_revision chain |
| migrations/versions/005_phishkit_unique_constraint.py | Fix down_revision chain |
| migrations/versions/015_add_asn_registrar_columns.py | New migration |

---

## Testing Strategy

- Each fix has a corresponding unit test validating the specific failure scenario
- Integration test: run full pipeline with 10 synthetic snapshots, verify no data loss, no duplicate entities, correct scores
- Scale test: simulate 1000 snapshots, verify batch processing completes without DB exhaustion
- Migration test: run `alembic upgrade head` from clean schema, verify all constraints exist