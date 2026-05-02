# VigilWolf V2 — Full Stack Pipeline Design

**Date**: 2026-05-02
**Scope**: Phase 1 bug fixes, Phase 2 intelligence pipeline wiring, Phase 3 actor/C2 integration, cross-cutting security and testing

## Problem Statement

VigilWolf v2 has 5 runtime-breaking bugs in Phase 1, fully coded but untriggered Phase 2/3 intelligence services, and critical security/test gaps. The product vision requires a working detection→alert pipeline (Phase 1), connected campaign intelligence (Phase 2), and actor attribution (Phase 3). Currently, alerts don't dispatch, IOC tables stay empty, and clustering/campaigns/actors never run.

## Approach

**Approach A: Fix First, Then Wire** — Fix all Phase 1 runtime bugs first and validate, then wire Phase 2 intelligence pipeline via Dramatiq workers, then connect Phase 3 actor profiling. Each phase is validated before the next starts. Intelligence pipeline triggers async via Dramatiq workers.

---

## Phase 1: Critical Bug Fixes

### 1.1 Config Ordering Bug

**File**: `vigilwolf-v2/backend/config.py`
**Problem**: `API_KEY` production guard at line 83 references `ENVIRONMENT` before it's defined at line 93. The guard is a no-op at module load time.
**Fix**: Move `ENVIRONMENT` definition above the `API_KEY` section. Restructure config so all variable definitions come before validation logic.

### 1.2 Alert Dispatch Signature Mismatch

**File**: `vigilwolf-v2/backend/worker.py` (call site) vs `vigilwolf-v2/backend/services/alert_service.py` (method)
**Problem**: `worker.py` calls `alert_service.send_alert()` with keyword args (`snapshot_id=`, `domain=`, `risk_level=`, etc.) but `AlertService.send_alert()` expects `(self, ctx: SnapshotContext, score_outcome: dict, session)`.
**Fix**: Align the worker call to construct a `SnapshotContext` and `score_outcome` dict matching the service's actual signature.

### 1.3 IOC Pipeline Gap

**File**: `vigilwolf-v2/backend/worker.py`
**Problem**: `ioc_extractor` puts IOCs in `PluginResult.findings`, but `services/ioc_service.persist_iocs()` is never called. All IOC, C2, and relationship tables stay permanently empty.
**Fix**: After `orchestrate_analysis()` stores plugin results, check if `ioc_extractor` produced results. If so, call `ioc_service.persist_iocs(snapshot_id, session)` inline in the worker (before Dramatiq, because downstream services need this data).

### 1.4 Blocking Redis in Async Event Loop

**File**: `vigilwolf-v2/backend/services/event_bus.py`
**Problem**: `iter_events()` calls synchronous `pubsub.get_message(timeout=1.0)` inside an async generator, freezing the event loop for up to 1s per iteration.
**Fix**: Switch to `redis.asyncio`. Make `iter_events()` use `await pubsub.get_message(timeout=1.0)` with the async Redis client. Keep in-memory fallback unchanged.

### 1.5 SSE Connection Counter Race Condition

**File**: `vigilwolf-v2/backend/routes/v2/events.py`
**Problem**: `_active_connections` check-and-increment is not atomic under concurrent requests.
**Fix**: Replace global integer with `asyncio.Semaphore(50)`. Use `asyncio.Semaphore(MAX_SSE_CONNECTIONS)` for atomic acquire/release.

---

## Phase 2: Intelligence Pipeline Wiring

### 2.1 Post-Processing Architecture

After `aggregate_results()` completes, enqueue a Dramatiq `intelligence_pipeline` actor:

```
domain scored → enqueue intelligence_pipeline(snapshot_id)
    ↓
IOC persistence (persist_iocs) — inline in worker, before Dramatiq
    ↓
Clustering (structural hash + infrastructure)
    ↓
Campaign detection (from clusters)
    ↓
PhishKit detection (from structural hashes)
```

Each step is sequential because each depends on the previous step's DB writes.

### 2.2 IOC Persistence Integration

After `orchestrate_analysis()` stores plugin results, if `ioc_extractor` ran successfully, call `ioc_service.persist_iocs(snapshot_id, session)`. This runs inline in the worker, before the Dramatiq enqueue, because downstream services (clustering, campaigns) need IOC data.

### 2.3 Inter-Plugin Data Passing

**Problem**: Enrichment plugins (WHOIS, DNS) produce findings that aren't available to detection plugins because `SnapshotContext` is frozen before the pipeline starts.

**Fix**: After the enrichment group runs, update `SnapshotContext` with enrichment findings before running the detection group:
- After `whois_enricher`: inject `registrar` and `creation_date` into `ctx.metadata`
- After `dns_enricher`: inject DNS records into `ctx.metadata`
- `scoring_service.apply_context_modifiers()` already reads `ctx.snapshot_record.get("registrar")` — populate it from WHOIS findings

### 2.4 Dramatiq Intelligence Worker

**New file**: `vigilwolf-v2/backend/intelligence_worker.py`

```python
@dramatiq.actor
def run_intelligence_pipeline(snapshot_id: str):
    """Runs after domain scoring completes."""
    # 1. Load snapshot + results
    # 2. Run clustering_service
    # 3. Run campaign_service
    # 4. Run phishkit_service
    # 5. Publish intelligence_update event
```

**Trigger**: `aggregate_results()` enqueues this actor via Dramatiq (if `USE_DRAMATIQ_PIPELINE=true`) or calls synchronously (if not).

### 2.5 Feature Flags

- `INTELLIGENCE_PIPELINE_ENABLED` (default: `false`) — master switch for Phase 2
- `CLUSTERING_ENABLED` (already exists)
- `CAMPAIGN_DETECTION_ENABLED` (new, default: `false`)
- `PHISHKIT_DETECTION_ENABLED` (new, default: `false`)

---

## Phase 3: Actor Tracking & C2 Detection

### 3.1 Actor Pipeline Worker

Add a Dramatiq `actor_pipeline` actor triggered after campaigns are created:

```python
@dramatiq.actor
def run_actor_pipeline(campaign_id: str):
    """Runs after campaign detection completes."""
    # 1. Load campaign + related clusters
    # 2. Run actor_service.profile_actors()
    # 3. Run c2_service.rank_c2_candidates()
    # 4. Publish actor_update event
```

**Trigger**: The intelligence pipeline enqueues this after campaign detection succeeds.

### 3.2 Actor Profiling Scalability

**Problem**: `actor_service.profile_actors()` uses `itertools.combinations(campaigns, 2)` — O(n²), won't scale past ~100 campaigns.

**Fix**: Replace brute-force pairwise comparison with staged approach:
1. Pre-filter: Group campaigns by shared signals (phishkit signature, infrastructure hash) using dict-based lookups (O(n)) instead of pairwise comparison (O(n²))
2. Only compare campaigns within the same signal group
3. Add configurable `MAX_CAMPAIGNS_PER_PROFILE` limit (default: 500) with logging when exceeded

### 3.3 Feature Flags

- `ACTOR_PROFILING_ENABLED` (default: `false`)
- `C2_DETECTION_ENABLED` (default: `false`)

---

## Cross-Cutting Concerns

### 4.1 Security Fixes

| Fix | Priority | File(s) |
|---|---|---|
| Fix X-Forwarded-For bypass — only trust header from configured proxy IPs | HIGH | `middleware/rate_limit.py` |
| Hash webhook secrets in DB (bcrypt), return plaintext only on create | HIGH | `database.py`, `routes/v2/webhooks.py` |
| Add input validation to Pydantic models (length, format) | MEDIUM | `routes/v2/webhooks.py`, `routes/v2/monitoring.py` |
| Escape `%` and `_` in LIKE queries | MEDIUM | `routes/v2/search.py`, `routes/v2/domains.py` |
| Pin dependency versions in requirements.txt | MEDIUM | `requirements.txt` |

### 4.2 Frontend Auth

The frontend has zero auth — no API key in requests, no login page, no protected routes.

**Fix**:
- Store API key in localStorage after user enters it
- Add `X-API-Key` header to all `apiFetch()` calls
- Add auth gate component at the app level
- Keep `/health` and `/metrics` as only public endpoints

### 4.3 Test Coverage Plan

Add tests for:
- Auth middleware (missing key, wrong key, production enforcement)
- Rate limiter (Redis path, in-memory path, X-Forwarded-For bypass)
- Capture engine SSRF protections
- SSE connection limits
- Alert dispatch (integration test with actual signature)
- IOC persistence pipeline
- Intelligence pipeline trigger
- Frontend auth gate

### 4.4 Circuit Breaker Fix

**Problem**: `orchestrate_analysis()` calls `circuit_breaker.should_run()` with `queue_depth=0`, threshold is 10000 — never activates.
**Fix**: Wire `pipeline_metrics.queue_depth` into the circuit breaker check. When using Dramatiq, read actual queue depth.

### 4.5 Double-Counting in Pipeline Metrics

**Problem**: `record_success()` and `record_domain_processed()` both increment `domains_processed`.
**Fix**: Remove the `domains_processed` increment from `record_success()` — it should only track processing times. The explicit `record_domain_processed()` call in the worker is the canonical counter.

---

## Implementation Order

1. **Phase 1 bug fixes** (1.1–1.5) — blocking runtime bugs, must be fixed first
2. **IOC persistence wiring** (2.2) — enables Phase 2
3. **Inter-plugin data passing** (2.3) — makes enrichment useful to detection
4. **Intelligence pipeline worker** (2.4) — Dramatiq integration
5. **Feature flags** (2.5) — guard Phase 2 features
6. **Security fixes** (4.1) — unblock production
7. **Actor pipeline** (3.1–3.3) — Phase 3
8. **Frontend auth** (4.2) — production prerequisite
9. **Test coverage** (4.3) — ongoing alongside each step
10. **Circuit breaker + metrics fixes** (4.4–4.5) — operational correctness