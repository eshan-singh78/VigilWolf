# VigilWolf v2: EASM + Phishing Intelligence Platform — Design Spec

**Date:** 2026-04-28
**Status:** Approved
**Scope:** Full system evolution from v1 (domain monitor) to v2 (EASM + phishing intelligence platform)

---

## 1. Product Vision

VigilWolf v2 is an attacker behavior tracking system, not just a phishing detector. It evolves from v1's scheduled domain checker into a distributed intelligence pipeline that: detects phishing, extracts IOCs, clusters infrastructure, tracks campaigns, and profiles threat actors.

**End goal:** Answer "which actor is behind this campaign, and what else have they done?"

---

## 2. Architecture

### 2.1 Stack

- **FastAPI** (monolith) — API + pipeline definitions
- **Dramatiq + Redis** — task queue for distributed processing
- **PostgreSQL** — primary data store
- **Redis** — Dramatiq broker (db 0), caching (db 1), rate limiting (db 2)
- **Qdrant** — vector similarity for HTML clustering (Phase 2+)
- **Next.js 16 + React 19 + shadcn/ui** — frontend

### 2.2 Data Flow

```
NRD Ingest
   ↓
enqueue(domain_id) → Domain Queue (Redis)
   ↓
capture_worker → HTML + Screenshot + Assets → filesystem
   ↓
context_builder → SnapshotContext (parsed HTML, forms, links, scripts, text)
   ↓
orchestrator_worker → fan-out parallel plugins
   ├── plugin:login_detector
   ├── plugin:keyword_detector
   ├── plugin:brand_match
   ├── plugin:external_js_detector
   ├── plugin:nrd_age_scorer
   ├── plugin:ioc_extractor
   ├── plugin:html_hasher
   ↓
aggregator_worker → weighted scoring + normalization
   ↓
store results (PostgreSQL: analysis_results, risk_scores)
   ↓
post-processing fan-out:
   ├── alert_worker (if risk = HIGH, after dry-run validation)
   ├── ioc_worker (enrich + dedup)
   ├── embedding_worker → Qdrant (async, non-blocking)
   ├── clustering_worker (async)
   ├── campaign_worker (Phase 3)
   ├── actor_worker (Phase 4)
```

### 2.3 Orchestrator + Fan-Out Model

Not chained actors. One orchestrator controls flow:

1. `capture_worker` completes → enqueues `context_builder`
2. `context_builder` builds `SnapshotContext` → enqueues `orchestrator_worker`
3. `orchestrator_worker` fans out one Dramatiq message per plugin
4. Each plugin updates `snapshot_plugin_status` on completion
5. Redis counter tracks expected completions; last plugin triggers `aggregator_worker`
6. Timeout handler (120s): triggers aggregator with partial results if plugins stall

### 2.4 Filesystem Storage

```
/data/
  domains/
    <domain>/
      <snapshot_id>/
        html.html
        screenshot.png
        assets/
```

Metadata in DB: `storage_path`, `size_bytes`, `retention_flag`.

---

## 3. Database Schema (PostgreSQL)

### 3.1 Core Tables

```sql
CREATE TABLE domains (
    id              UUID PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ,
    registrar       TEXT,
    asn             INTEGER,
    asn_org         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE domain_ips (
    id              SERIAL PRIMARY KEY,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    UNIQUE(domain_id, ip)
);

CREATE TABLE dns_records (
    id              SERIAL PRIMARY KEY,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    value           TEXT NOT NULL,
    ttl             INTEGER,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ
);

CREATE TABLE domain_processing_state (
    id              SERIAL PRIMARY KEY,
    domain_id       UUID REFERENCES domains(id) UNIQUE,
    status          TEXT NOT NULL CHECK (status IN ('pending','processing','done','failed')),
    last_processed_at TIMESTAMPTZ,
    retry_count     INTEGER DEFAULT 0,
    error_message   TEXT,
    priority        TEXT NOT NULL DEFAULT 'low' CHECK (priority IN ('high','low')),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE snapshots (
    id              UUID PRIMARY KEY,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    sha256          TEXT NOT NULL,
    trigger_type    TEXT NOT NULL CHECK (trigger_type IN ('initial','automatic','manual','nrd_ingest')),
    html_path       TEXT NOT NULL,
    screenshot_path TEXT,
    assets_dir      TEXT,
    asset_count     INTEGER DEFAULT 0,
    size_bytes      BIGINT DEFAULT 0,
    retention_flag  TEXT DEFAULT 'standard' CHECK (retention_flag IN ('standard','high_risk','permanent')),
    success         BOOLEAN DEFAULT TRUE,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain_id, sha256)
);

CREATE TABLE analysis_results (
    id              SERIAL PRIMARY KEY,
    snapshot_id     UUID REFERENCES snapshots(id) ON DELETE CASCADE,
    plugin_name     TEXT NOT NULL,
    plugin_version  TEXT NOT NULL,
    plugin_type     TEXT NOT NULL CHECK (plugin_type IN ('detection','extraction','enrichment','fingerprint')),
    result_json     JSONB NOT NULL,
    score_contribution INTEGER DEFAULT 0,
    confidence      REAL DEFAULT 1.0,
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(snapshot_id, plugin_name)
);

CREATE TABLE risk_scores (
    id              SERIAL PRIMARY KEY,
    snapshot_id     UUID REFERENCES snapshots(id) UNIQUE,
    total_score     INTEGER NOT NULL,
    normalized_score REAL NOT NULL,
    risk_level      TEXT NOT NULL CHECK (risk_level IN ('high','medium','low')),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    reasons         JSONB NOT NULL,
    dominant_signals TEXT[] NOT NULL DEFAULT '{}',
    plugin_breakdown JSONB NOT NULL DEFAULT '{}'::JSONB,
    overall_confidence REAL NOT NULL DEFAULT 1.0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE snapshot_plugin_status (
    id              SERIAL PRIMARY KEY,
    snapshot_id     UUID REFERENCES snapshots(id) ON DELETE CASCADE,
    plugin_name     TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending','running','done','failed','timed_out')),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    UNIQUE(snapshot_id, plugin_name)
);
```

### 3.2 IOC Tables

```sql
CREATE TABLE iocs (
    id              SERIAL PRIMARY KEY,
    type            TEXT NOT NULL CHECK (type IN ('domain','ip','url','email','telegram','wallet','phone')),
    value           TEXT NOT NULL UNIQUE
);

CREATE TABLE ioc_occurrences (
    id              SERIAL PRIMARY KEY,
    ioc_id          INTEGER REFERENCES iocs(id) ON DELETE CASCADE,
    snapshot_id     UUID REFERENCES snapshots(id) ON DELETE CASCADE,
    context         TEXT,
    confidence      REAL DEFAULT 1.0,
    role            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ioc_relationships (
    id              SERIAL PRIMARY KEY,
    source_ioc_id   INTEGER REFERENCES iocs(id) ON DELETE CASCADE,
    target_ioc_id   INTEGER REFERENCES iocs(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    confidence      REAL DEFAULT 1.0
);
```

### 3.3 Intelligence Tables

```sql
CREATE TABLE clusters (
    id              UUID PRIMARY KEY,
    cluster_type    TEXT NOT NULL CHECK (cluster_type IN ('html_similarity','infra','phishkit','campaign')),
    signature_hash  TEXT NOT NULL,
    signature_type  TEXT NOT NULL,
    description     TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    domain_count    INTEGER DEFAULT 0,
    metadata        JSONB DEFAULT '{}'::JSONB
);

CREATE TABLE cluster_members (
    id              SERIAL PRIMARY KEY,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    confidence      REAL DEFAULT 1.0,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(cluster_id, domain_id)
);

CREATE TABLE phishkits (
    id              UUID PRIMARY KEY,
    signature_hash  TEXT UNIQUE,
    panel_path      TEXT,
    exfil_endpoint  TEXT,
    metadata        JSONB DEFAULT '{}'::JSONB,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE snapshot_phishkits (
    snapshot_id     UUID REFERENCES snapshots(id) ON DELETE CASCADE,
    phishkit_id     UUID REFERENCES phishkits(id) ON DELETE CASCADE,
    similarity      REAL DEFAULT 1.0,
    PRIMARY KEY(snapshot_id, phishkit_id)
);

CREATE TABLE campaigns (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    target_brand    TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    domain_count    INTEGER DEFAULT 0,
    kit_signature   TEXT,
    status          TEXT DEFAULT 'active' CHECK (status IN ('active','dormant','closed')),
    metadata        JSONB DEFAULT '{}'::JSONB
);

CREATE TABLE campaign_clusters (
    campaign_id     UUID REFERENCES campaigns(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE,
    PRIMARY KEY(campaign_id, cluster_id)
);

CREATE TABLE actors (
    id              UUID PRIMARY KEY,
    label           TEXT NOT NULL UNIQUE,
    fingerprint     JSONB NOT NULL,
    confidence_score REAL DEFAULT 0.0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}'::JSONB
);

CREATE TABLE actor_campaigns (
    actor_id        UUID REFERENCES actors(id) ON DELETE CASCADE,
    campaign_id     UUID REFERENCES campaigns(id) ON DELETE CASCADE,
    PRIMARY KEY(actor_id, campaign_id)
);
```

### 3.4 Alerting Tables

```sql
CREATE TABLE webhooks (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    secret          TEXT,
    events          TEXT[] NOT NULL,
    filters         JSONB DEFAULT '{}'::JSONB,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE alerts (
    id              SERIAL PRIMARY KEY,
    event_type      TEXT NOT NULL,
    dedup_key       TEXT NOT NULL,
    domain_id       UUID REFERENCES domains(id),
    snapshot_id     UUID REFERENCES snapshots(id),
    risk_level      TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    score           INTEGER,
    campaign_id     UUID REFERENCES campaigns(id),
    webhook_id      UUID REFERENCES webhooks(id),
    payload         JSONB NOT NULL,
    payload_version TEXT NOT NULL DEFAULT '1.0',
    status          TEXT DEFAULT 'sent' CHECK (status IN ('sent','failed','retrying')),
    attempts        INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 3.5 Plugin + Config Tables

```sql
CREATE TABLE plugin_weights (
    id              SERIAL PRIMARY KEY,
    plugin_name     TEXT NOT NULL UNIQUE,
    weight          REAL NOT NULL DEFAULT 1.0,
    enabled         BOOLEAN DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE groups (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE monitoring_configs (
    id              UUID PRIMARY KEY,
    group_id        UUID REFERENCES groups(id) ON DELETE CASCADE,
    domain_id       UUID REFERENCES domains(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    dump_mode       TEXT NOT NULL CHECK (dump_mode IN ('html_only','html_and_assets')),
    frequency_seconds INTEGER NOT NULL,
    active          BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_checked_at TIMESTAMPTZ
);

CREATE TABLE analyst_feedback (
    id              SERIAL PRIMARY KEY,
    snapshot_id     UUID REFERENCES snapshots(id) ON DELETE CASCADE,
    label           TEXT NOT NULL CHECK (label IN ('false_positive','confirmed_phishing')),
    analyst_id      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id              SERIAL PRIMARY KEY,
    action          TEXT NOT NULL,
    actor_id        TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 3.6 Indexes

```sql
CREATE INDEX idx_domains_domain ON domains(domain);
CREATE INDEX idx_domains_first_seen ON domains(first_seen);
CREATE INDEX idx_domain_ips_domain ON domain_ips(domain_id);
CREATE INDEX idx_domain_ips_ip ON domain_ips USING gist(ip inet_ops);
CREATE INDEX idx_dns_records_domain ON dns_records(domain_id);
CREATE INDEX idx_dns_records_type_value ON dns_records(type, value);
CREATE INDEX idx_snapshots_domain ON snapshots(domain_id);
CREATE INDEX idx_snapshots_created ON snapshots(created_at);
CREATE INDEX idx_snapshots_sha256 ON snapshots(sha256);
CREATE INDEX idx_analysis_snapshot ON analysis_results(snapshot_id);
CREATE INDEX idx_analysis_plugin ON analysis_results(plugin_name);
CREATE INDEX idx_risk_scores_level ON risk_scores(risk_level);
CREATE INDEX idx_iocs_type_value ON iocs(type, value);
CREATE INDEX idx_ioc_occurrences_snapshot ON ioc_occurrences(snapshot_id);
CREATE INDEX idx_ioc_occurrences_ioc ON ioc_occurrences(ioc_id);
CREATE INDEX idx_cluster_type ON clusters(cluster_type);
CREATE INDEX idx_cluster_signature ON clusters(signature_hash, signature_type);
CREATE INDEX idx_cluster_members_domain ON cluster_members(domain_id);
CREATE INDEX idx_cluster_members_cluster ON cluster_members(cluster_id);
CREATE INDEX idx_campaign_first_seen ON campaigns(first_seen);
CREATE INDEX idx_campaign_status ON campaigns(status);
CREATE INDEX idx_alerts_dedup ON alerts(dedup_key);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created ON alerts(created_at);
CREATE INDEX idx_plugin_weights_name ON plugin_weights(plugin_name);
CREATE INDEX idx_processing_state_status ON domain_processing_state(status);
CREATE INDEX idx_processing_state_priority ON domain_processing_state(priority);
CREATE INDEX idx_analyst_feedback_snapshot ON analyst_feedback(snapshot_id);
```

### 3.7 Time-Series Partitioning (Future)

Snapshots and analysis_results will be partitioned by month once volume warrants it. Implemented via PostgreSQL table partitions or timescaleDB extension.

---

## 4. Analysis Pipeline + Plugin Architecture

### 4.1 Plugin Interface

```python
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class PluginType(Enum):
    DETECTION = "detection"
    EXTRACTION = "extraction"
    ENRICHMENT = "enrichment"
    FINGERPRINT = "fingerprint"

@dataclass
class SnapshotContext:
    snapshot_id: str
    domain: str
    html: str
    text: str
    forms: list
    links: list[str]
    scripts: list[dict]
    metadata: dict
    snapshot_record: dict    # flattened snapshot DB row (id, domain_id, sha256, trigger_type, etc.)

@dataclass
class PluginResult:
    plugin_name: str
    plugin_version: str
    plugin_type: PluginType
    score_contribution: int
    confidence: float
    tags: list[str]
    findings: dict
    error: Optional[str] = None

class AnalysisPlugin:
    name: str
    version: str
    plugin_type: PluginType

    def run(self, ctx: SnapshotContext) -> PluginResult:
        raise NotImplementedError
```

### 4.2 Plugin Registry

```python
PLUGIN_REGISTRY: dict[str, type[AnalysisPlugin]] = {}

def register_plugin(cls: type[AnalysisPlugin]):
    PLUGIN_REGISTRY[cls.name] = cls
    return cls
```

### 4.3 Execution Groups

```python
@dataclass
class ExecutionGroup:
    name: str
    plugins: list[tuple[str, int]]  # (plugin_name, priority)

EXECUTION_GROUPS = [
    ExecutionGroup(name="enrich",    plugins=[
        ("whois_enricher", 1),
        ("dns_enricher", 1),
    ]),
    ExecutionGroup(name="detect",    plugins=[
        ("login_detector", 1),
        ("brand_match", 1),
        ("keyword_detector", 2),
        ("external_js_detector", 2),
        ("nrd_age_scorer", 2),
    ]),
    ExecutionGroup(name="extract",   plugins=[
        ("ioc_extractor", 1),
    ]),
    ExecutionGroup(name="fingerprint", plugins=[
        ("html_hasher", 1),
    ]),
]
```

Within a group, plugins run in parallel. Groups run sequentially. Priority within groups determines alert ordering (high-priority plugins report first for faster alerts).

### 4.4 Phase 1 Plugins

| Plugin | Type | Detects | Max Score | Weight |
|---|---|---|---|---|
| login_detector | DETECTION | Password fields, hidden inputs, external POST | 40 | 1.0 |
| keyword_detector | DETECTION | Urgency/scam language | 15 | 0.6 |
| brand_match | DETECTION | Brand name in domain + content | 25 | 1.2 |
| external_js_detector | DETECTION | JS from different domain | 10 | 0.8 |
| nrd_age_scorer | DETECTION | Domain age from registration | 10 | 0.5 |
| ioc_extractor | EXTRACTION | Domains, IPs, URLs, emails, Telegram, wallets | 0 | — |
| html_hasher | FINGERPRINT | Structural DOM hash for dedup | 0 | — |

### 4.5 Plugin Versioning

- `plugin_version` stored in `analysis_results`
- On version change: reprocess worker invalidates old results and re-enqueues affected snapshots
- Cache key includes version: `plugin:{name}:{version}:{snapshot_hash}`

### 4.6 Caching

```python
def get_cached_or_compute(domain: str, plugin_name: str, version: str,
                          snapshot_hash: str, compute_fn: callable, ttl: int = 3600) -> PluginResult:
    cache_key = f"plugin:{plugin_name}:{version}:{snapshot_hash}"
    cached = redis_db_1.get(cache_key)
    if cached:
        return PluginResult.from_json(cached)
    result = compute_fn()
    redis_db_1.setex(cache_key, ttl, result.to_json())
    return result
```

Enrichment plugins (WHOIS, DNS) use 24h TTL. Detection plugins use short TTL or skip cache.

### 4.7 Circuit Breaker

```python
class CircuitBreaker:
    def __init__(self, threshold: int = 10000, cooldown: int = 300):
        self.threshold = threshold
        self.cooldown = cooldown

    def should_run(self, plugin_name: str, plugin_type: PluginType,
                   queue_depth: int, high_impact_plugins: set[str]) -> bool:
        if queue_depth <= self.threshold:
            return True
        if plugin_type == PluginType.DETECTION:
            return plugin_name in high_impact_plugins
        if plugin_type == PluginType.EXTRACTION:
            return True
        return False  # skip enrichment + fingerprint under load
```

Graceful degradation: under load, keep high-impact detection plugins (login_detector, brand_match) and all extraction plugins. Skip low-impact detection and all enrichment/fingerprint.

### 4.8 Fault Tolerance

Orchestrator creates `snapshot_plugin_status` rows for each plugin. Timeout handler (120s) marks stuck plugins as `timed_out` and triggers aggregator with partial results. Aggregator only waits for plugins in the current execution group.

---

## 5. Scoring Engine

### 5.1 Weighted Scoring with Normalization

```python
def calculate_score(results: list[PluginResult], weights: dict[str, float]) -> dict:
    max_possible = sum(
        result.score_contribution * weights.get(result.plugin_name, 1.0)
        for result in results
        if result.plugin_type == PluginType.DETECTION
    )

    total = 0
    for result in results:
        if result.plugin_type != PluginType.DETECTION:
            continue
        weight = weights.get(result.plugin_name, 1.0)
        confidence_adjusted = result.confidence ** 1.5  # non-linear scaling
        contribution = result.score_contribution * weight * confidence_adjusted
        total += contribution

    normalized = (total / max_possible * 100) if max_possible > 0 else 0
    score = min(100, round(normalized))
    risk_level = 'high' if score >= 70 else 'medium' if score >= 40 else 'low'
    return {'score': score, 'risk_level': risk_level}
```

### 5.2 Non-Linear Confidence Scaling

`adjusted = score * weight * (confidence ** 1.5)`

Weak signals drop sharply. Strong signals stay strong. Reduces false positives.

### 5.3 Hard Signal Override

```python
HARD_SIGNAL_TAGS = {'credential_exfil', 'known_phishkit'}

def check_hard_signals(results: list[PluginResult], score: int, risk_level: str) -> tuple[int, str]:
    all_tags = set()
    for result in results:
        all_tags.update(result.tags)
    if HARD_SIGNAL_TAGS & all_tags:
        return max(score, 85), 'high', 'critical'
    return score, risk_level, determine_severity(risk_level)
```

### 5.4 Severity Mapping

```python
def determine_severity(risk_level: str, hard_signal: bool = False) -> str:
    if hard_signal:
        return 'critical'
    if risk_level == 'high':
        return 'high'
    if risk_level == 'medium':
        return 'medium'
    return 'low'
```

### 5.5 Context-Aware Threshold Modifiers

```python
def apply_context_modifiers(score: int, domain: 'Domain', snapshot: 'Snapshot') -> int:
    domain_age_days = (datetime.now() - domain.first_seen).days
    if domain_age_days < 3:
        score += 10
    if domain.get('registrar') and domain['registrar'] in config.HIGH_RISK_REGISTRARS:
        score += 5
    return min(100, score)
```

### 5.6 Aggregated Intelligence Storage

```json
{
  "score": 83,
  "normalized_score": 82.8,
  "risk": "high",
  "severity": "critical",
  "dominant_signals": ["login_form", "brand_match"],
  "overall_confidence": 0.88,
  "plugin_breakdown": {
    "login_detector": 38,
    "brand_match": 27,
    "keyword_detector": 12
  },
  "reasons": [
    {"plugin": "login_detector", "reason": "login_form_detected", "confidence": 0.95},
    {"plugin": "brand_match", "reason": "paypal_brand_detected", "confidence": 0.90}
  ]
}
```

---

## 6. Alert Engine

### 6.1 Webhook Payload

```json
{
  "id": "evt_abc123",
  "version": "1.0",
  "event": "phishing_detected",
  "dedup_key": "phishing_detected:snap_xyz789",
  "timestamp": "2026-04-28T14:30:00Z",
  "data": {
    "domain": "paypa1-secure-login.com",
    "score": 87,
    "risk_level": "high",
    "severity": "critical",
    "dominant_signals": ["login_form", "brand_match"],
    "plugin_breakdown": {
      "login_detector": 38,
      "brand_match": 27
    },
    "reasons": [
      {"plugin": "login_detector", "reason": "login_form_detected", "confidence": 0.95},
      {"plugin": "brand_match", "reason": "paypal_brand_detected", "confidence": 0.90}
    ],
    "iocs": [
      {"type": "url", "value": "https://paypa1-secure-login.com/verify"},
      {"type": "ip", "value": "185.234.72.11"}
    ],
    "snapshot_id": "snap_xyz789",
    "campaign": null,
    "screenshot_url": "/api/v2/snapshots/snap_xyz789/screenshot?token=signed"
  }
}
```

### 6.2 Signature

`X-VigilWolf-Signature: sha256=<HMAC-SHA256(secret, raw_body_without_signature_header)>`

Consumers verify signature + reject payloads older than 5 minutes (replay protection).

### 6.3 Alert Flow

```
aggregator_worker
   ↓
event_generator → determine event type + severity
   ↓
alert_dispatcher
   ├── dedup check (10 min window on domain + event_type)
   ├── filter matching (webhook.filters: min_score, domains, exclude_tags)
   ↓
fan-out per webhook:
   ├── webhook_delivery_worker(webhook_1, payload)
   ├── webhook_delivery_worker(webhook_2, payload)
   ↓
retry with jitter: delay = base * (2 ** attempt) + random(0, 1000)ms
max 3 attempts → DLQ
```

### 6.4 Alert Deduplication

Same `domain_id + event_type` within 10 minutes → suppress. Store dedup_key in alerts table.

### 6.5 Webhook Filters

```json
{
  "min_score": 70,
  "domains": ["paypal", "google"],
  "exclude_tags": ["low_confidence"],
  "severity": ["critical", "high"]
}
```

### 6.6 Screenshot URLs

Signed URLs with expiry (e.g., 1 hour). Generated server-side, not direct paths.

### 6.7 Rollout Strategy

Phase 1: Scoring only, no alerts
Phase 2: Alerts in dry-run mode (log only, no delivery)
Phase 3: Real alerts enabled

---

## 7. Intelligence Engines

### 7.1 IOC Extraction (Phase 2)

Context-aware extraction with role classification:

```json
{
  "type": "url",
  "value": "https://api.telegram.org/bot123/sendMessage",
  "context": "script",
  "confidence": 0.95,
  "role": "exfil_endpoint"
}
```

Roles: `exfil_endpoint`, `cdn`, `tracking`, `redirect`, `resource`. Role determines whether IOC is malicious or benign.

IOC graph via `ioc_relationships` table: `same_page`, `redirect`, `script_load`, `shared_hosting`.

### 7.2 HTML Similarity Clustering (Phase 2)

Three-layer hybrid strategy:

| Layer | Method | Use Case |
|---|---|---|
| Exact | `structural_hash` match | Identical DOM structure |
| Near | MinHash / SimHash | Slightly modified pages |
| Semantic | Embeddings (Qdrant) | Conceptually similar pages |

`final_similarity = weighted(score_structural, score_minhash, score_vector)`

### 7.3 Infrastructure Clustering (Phase 2)

Explicit infra signatures:

```json
{
  "asn": 12345,
  "registrar": "Namecheap",
  "ns": ["ns1.host.com"],
  "ip_range": "185.234.72.0/24"
}
```

Group by: IP, ASN, NS records, MX records. Each infra cluster links domains sharing hosting infrastructure.

### 7.4 PhishKit Detection (Phase 3)

Fuzzy matching with similarity scoring:

- JS hash overlap > 95% → same kit
- JS hash overlap 80-95% → variant
- DOM similarity + endpoint similarity contribute to match confidence

Kit variants are separate entries but linked via metadata.

### 7.5 Campaign Detection (Phase 3)

Campaign = cluster + time window + shared traits.

Temporal modeling with sliding windows:
- Burst detection: 10+ domains in 2 days → campaign spike
- Slow campaign: 1-2 domains per week over months
- Campaign growth rate tracked over time

Auto-generated names: `{BRAND}_PHISH_{MMDD}`. Human operators can rename.

### 7.6 Actor Profiling (Phase 4)

Multi-signal confidence scoring:

```
confidence =
  (shared_kit * 0.3) +
  (shared_infra * 0.3) +
  (shared_iocs * 0.2) +
  (temporal_overlap * 0.2)
```

Labels: `>0.8` = LIKELY SAME ACTOR, `0.5-0.8` = POSSIBLE, `<0.5` = WEAK.

Actor fingerprint stores: preferred_registrar, preferred_asn, phishkits, exfil_channels, target_brands, timing_pattern.

### 7.7 C2 Inference (Phase 4)

Ranked C2 scoring:

```json
{
  "ioc": "https://api.telegram.org/bot...",
  "c2_score": 0.92,
  "signals": [
    "used_in_5_domains",
    "receives_post_data",
    "linked_to_phishkit"
  ]
}
```

Detection: POST target analysis, redirect chain following, external JS analysis, known C2 indicator matching.

### 7.8 Cross-Phase Intelligence Loop

```
IOC → cluster (IOCs link domains to clusters)
cluster → campaign (clusters group into campaigns)
campaign → actor (campaigns attributed to actors)
actor → IOC (actor fingerprints include IOCs for future detection)
```

### 7.9 Analyst Feedback

```sql
INSERT INTO analyst_feedback (snapshot_id, label, analyst_id)
VALUES ('snap_xyz789', 'confirmed_phishing', 'analyst_1');
```

Labels: `false_positive`, `confirmed_phishing`. Phase 2+: feed back into scoring calibration (adjust plugin weights based on false positive rate).

---

## 8. Frontend Architecture

### 8.1 Page Structure

```
/                          Dashboard (threat overview)
/nrd                       NRD ingestion + search
/monitor                   Domain monitoring
/domain/[domainId]         Domain detail (risk + IOCs + snapshots)
/threats                   Threat feed (primary analyst view)
/threats/[id]              Threat detail (score breakdown, graph view)
/alerts                    Alert history + webhook config
/settings                  System config, plugins, thresholds
/clusters                  Cluster browser (Phase 2)
/clusters/[id]             Cluster detail
/campaigns                 Campaign list (Phase 3)
/campaigns/[id]            Campaign detail + timeline
/actors                    Actor profiles (Phase 4)
/actors/[id]               Actor detail + confidence breakdown
```

### 8.2 Navigation

Sidebar navigation replacing top navbar. Sidebar items expand per phase.

### 8.3 Key UI Features

**Global search bar** (header): search anything — domain, IP, email, telegram, campaign. Returns ranked, typed results:

```json
{
  "results": [
    {"type": "domain", "value": "paypa1-secure.com", "score": 0.92},
    {"type": "ioc", "value": "185.234.72.11", "score": 0.85}
  ]
}
```

**Threat feed pivot actions**: inline [View] [Pivot → Campaign] [Pivot → Cluster] [Pivot → IOC] buttons per row.

**Threat detail graph view**: relationship panel showing domain → IOCs → cluster → campaign → related domains.

**Campaign timeline**: temporal visualization of domain registrations, kit variants, infra changes.

**Actor confidence visualization**: breakdown bar showing kit (0.3), infra (0.25), IOC (0.15), temporal (0.12).

**Alert severity + dedup view**: severity badges (CRITICAL/HIGH/MEDIUM), grouped alerts suppressing duplicates.

**Settings guardrails**: weight change impact preview showing projected detection rate changes.

### 8.4 State Management

- **Server state**: TanStack Query with `staleTime: 30000`, `refetchInterval: 60000`
- **UI state**: Zustand (filters, modals, sidebar)
- **Real-time**: SSE or WebSocket for new threats + alerts (replaces polling)

### 8.5 Table Performance

Virtualized tables (react-virtualized or TanStack Table virtual mode) for threat feed at 50K+ entries. Server-side cursor-based pagination.

### 8.6 Investigation Workflow (Phase 2+)

User can select domains, add to investigation, add related domains via pivots, export report.

---

## 9. API Design

### 9.1 Endpoints

**Domains + Threats:**
```
GET    /api/v2/domains                     List domains (cursor-based, field selection)
GET    /api/v2/domains/{id}                 Domain detail
GET    /api/v2/domains/{id}/threat         Threat view of domain
GET    /api/v2/domains/{id}/snapshots      Snapshot history
GET    /api/v2/domains/{id}/iocs           IOCs for domain
GET    /api/v2/domains/{id}/clusters       Clusters containing domain
POST   /api/v2/domains/bulk                Bulk domain operations
GET    /api/v2/threats                     Threat feed (filtered, sorted, cursor-paginated)
GET    /api/v2/threats/stats               Dashboard stats
```

**Search + Pivot:**
```
GET    /api/v2/search?q=...&types=domain,ioc  Global search (ranked, typed results)
GET    /api/v2/pivot/domain/{id}?depth=1&limit=50  Pivot from domain
GET    /api/v2/pivot/ioc/{type}/{value}?depth=1&limit=50  Pivot from IOC
```

**Snapshots:**
```
GET    /api/v2/snapshots/{id}              Snapshot detail
GET    /api/v2/snapshots/{id}/screenshot   Screenshot (signed URL)
POST   /api/v2/snapshots/{id}/feedback    Analyst feedback
```

**NRD + Brand:**
```
GET    /api/v2/nrd/latest                  Latest NRD (cursor-paginated)
POST   /api/v2/nrd/ingest                  Trigger ingest
GET    /api/v2/nrd/stats                   NRD stats
POST   /api/v2/brand/search               Brand search
GET    /api/v2/brand/hits                  Brand hits with risk scores
```

**Monitoring:**
```
POST   /api/v2/monitoring/groups           Create group
GET    /api/v2/monitoring/groups            List groups
GET    /api/v2/monitoring/groups/{id}       Group detail
GET    /api/v2/monitoring/groups/{id}/domains  Domains in group
POST   /api/v2/monitoring/domains/{id}/force-dump  Force dump
POST   /api/v2/monitoring/reset            Reset environment
```

**Webhooks + Alerts:**
```
POST   /api/v2/webhooks                    Create webhook
GET    /api/v2/webhooks                     List webhooks
GET    /api/v2/webhooks/{id}               Webhook detail
PUT    /api/v2/webhooks/{id}               Update webhook
DELETE /api/v2/webhooks/{id}               Delete webhook
POST   /api/v2/webhooks/{id}/test         Test webhook
GET    /api/v2/alerts                       Alert history (cursor-paginated)
GET    /api/v2/alerts/{id}                  Alert detail
POST   /api/v2/alerts/{id}/retry          Retry failed alert
```

**Plugins + Scoring:**
```
GET    /api/v2/plugins                      List plugins
PUT    /api/v2/plugins/{name}/weight        Update weight
PUT    /api/v2/plugins/{name}/enabled       Enable/disable
GET    /api/v2/plugins/{name}/impact        Preview weight impact
GET    /api/v2/risk-thresholds              Get thresholds
PUT    /api/v2/risk-thresholds              Update thresholds
```

**IOCs (Phase 2):**
```
GET    /api/v2/iocs                         List IOCs (cursor-paginated, filterable)
GET    /api/v2/iocs/{id}                    IOC detail + occurrences
GET    /api/v2/iocs/{id}/domains            Domains containing IOC
POST   /api/v2/iocs/bulk                    Bulk IOC operations
POST   /api/v2/exports                      Create async export job
GET    /api/v2/exports/{id}                 Export job status + download
```

**Clusters (Phase 2):**
```
GET    /api/v2/clusters                     List clusters
GET    /api/v2/clusters/{id}               Cluster detail
GET    /api/v2/clusters/{id}/domains        Domains in cluster
```

**Campaigns (Phase 3):**
```
GET    /api/v2/campaigns                    List campaigns
GET    /api/v2/campaigns/{id}               Campaign detail
PUT    /api/v2/campaigns/{id}               Update campaign
GET    /api/v2/campaigns/{id}/timeline      Campaign timeline
GET    /api/v2/campaigns/{id}/domains       Domains in campaign
```

**Actors (Phase 4):**
```
GET    /api/v2/actors                       List actors
GET    /api/v2/actors/{id}                  Actor detail
PUT    /api/v2/actors/{id}                  Update actor label
GET    /api/v2/actors/{id}/campaigns        Actor campaigns
```

**System:**
```
GET    /api/v2/health                       Health check
GET    /api/v2/config                       System config
GET    /api/v2/metrics                      Prometheus metrics
GET    /api/v2/queue/status                 Queue depths + worker status
GET    /api/v2/audit-logs                   Audit trail
```

### 9.2 Response Envelope

```json
{
  "data": { ... },
  "meta": {
    "next_cursor": "abc123",
    "has_more": true,
    "total": 12847,
    "request_id": "abc123"
  }
}
```

### 9.3 Cursor-Based Pagination

All list endpoints support `?cursor=abc&limit=50`. Response includes `next_cursor` and `has_more`.

### 9.4 Field Selection

`?fields=domain,score,risk_level` — reduces payload size for list endpoints.

### 9.5 API Versioning

URL prefix: `/api/v2/`. Header support: `Accept: application/vnd.vigilwolf.v2+json`.

### 9.6 RBAC

Early role structure: `admin` (all access), `analyst` (read + feedback + webhook management), `viewer` (read-only). Roles stored in `config.py` as `API_ROLES` mapping API keys to roles. Enforced at API middleware layer via a `require_role` dependency. SaaS multi-tenancy adds tenant isolation later (each API key scoped to a tenant_id).

### 9.7 Rate Limits

| Tier | Limit | Scope |
|---|---|---|
| Search/pivot | 60/min | per IP |
| List endpoints | 120/min | per IP |
| Write endpoints | 30/min | per IP |
| Webhook delivery | 10/sec | per webhook |

---

## 10. Migration Strategy

### 10.1 Strangler Fig Pattern

Each step leaves v1 working while v2 components are added alongside. V1 endpoints remain until v2 equivalents are verified.

### 10.2 Step 1: PostgreSQL Migration (Dual-Write + Validation)

1. Add PostgreSQL to docker-compose.yml
2. Create Alembic migrations for all v2 tables
3. Enable dual-write: all writes go to both SQLite (v1) and PostgreSQL (v2)
4. Run validation script: count checks, checksum sampling of 100 random domains
5. When validation passes, switch reads to PostgreSQL
6. Keep SQLite in read-only mode for 7 days as rollback

### 10.3 Step 2: Dramatiq Pipeline (Isolated)

1. Add Dramatiq + worker Docker service
2. Feature flag: `USE_DRAMATIQ_PIPELINE=true`
3. Initially: Dramatiq handles NRD ingestion only. APScheduler still handles monitored domains.
4. When stable: migrate monitored domain checks to Dramatiq
5. Retire APScheduler

### 10.4 Step 3: Plugin System (Scoring Only, No Alerts)

1. Build plugin framework: base classes, registry, execution groups
2. Per-plugin feature flags: `ENABLE_LOGIN_DETECTOR=true`
3. Plugins run and write to `analysis_results` + `risk_scores` — no alert delivery yet
4. Validate scoring accuracy against known phishing/benign samples

### 10.5 Step 4: Backfill Old Data

After pipeline is stable, backfill existing snapshots:

```python
for snapshot in old_snapshots:
    enqueue → context_builder → orchestrator → aggregator
```

This builds historical intelligence for campaign detection.

### 10.6 Step 5: Enable Alerts (Dry-Run → Live)

1. Alerts in dry-run mode: log only, no delivery
2. Verify alert content, dedup, severity mapping
3. Enable real alert delivery
4. Monitor for alert fatigue (dedup window, filter effectiveness)

### 10.7 Step 6: Frontend Rewrite (Shadow → Full)

1. New pages accessible via `/v2/threats`, `/v2/alerts`, etc. (shadow mode)
2. Internal testing while v1 UI remains default
3. Feature flags switch sidebar links to new pages
4. Old pages progressively replaced

### 10.8 Step 7: Enable Clustering (Qdrant)

1. `CLUSTERING_ENABLED=false` by default
2. Enable embedding worker + clustering worker
3. Validate cluster quality before surfacing in UI
4. If Qdrant fails, system continues without clustering

### 10.9 Step 8: Decommission v1

Remove SQLite, APScheduler, v1 endpoints, v1 frontend pages.

### 10.10 Observability During Migration

Migration metrics tracked in Prometheus:
- domains_processed/sec
- plugin execution time (p50, p95, p99)
- queue depth per worker
- error rate per step
- dual-write consistency check failures

### 10.11 Rollback Plan

| Step | Rollback |
|---|---|
| Step 1 (PostgreSQL) | Fall back to SQLite (7-day read-only window) |
| Step 2 (Dramatiq) | Feature flag switches back to APScheduler |
| Step 3 (Plugins) | Per-plugin feature flags |
| Step 4 (Backfill) | N/A — additive |
| Step 5 (Alerts) | Disable alert delivery, keep dry-run |
| Step 6 (Frontend) | Feature flags per page, shadow mode |
| Step 7 (Qdrant) | `CLUSTERING_ENABLED=false` |

On rollback, v2 writes are frozen. Any v2 data written during the migration window is either accepted (if forward-compatible) or reverse-synced to v1 schema (if critical).

---

## 11. Directory Structure (Post-Migration)

```
vigilwolf-core/
  backend/
    main.py
    config.py
    database.py
    worker.py
    rate_limiter.py
    requirements.txt
    plugins/
      base.py
      registry.py
      login_detector.py
      keyword_detector.py
      brand_match.py
      external_js_detector.py
      nrd_age_scorer.py
      ioc_extractor.py
      html_hasher.py
      html_similarity_embedder.py
      phishkit_detector.py
    routes/
      v1/
        monitoring.py
        brand.py
        nrd.py
        whois.py
      v2/
        domains.py
        threats.py
        webhooks.py
        alerts.py
        search.py
        plugins.py
        clusters.py
        campaigns.py
        actors.py
        iocs.py
        exports.py
    services/
      capture_engine.py
      monitoring_service.py
      storage_manager.py
      alert_service.py
      scoring_service.py
      search_service.py
      qdrant_client.py
    migrations/
      001_initial_schema.py
    frontend/
    app/
      layout.tsx
      page.tsx
      nrd/page.tsx
      monitor/page.tsx
      domain/[domainId]/page.tsx
      threats/page.tsx
      threats/[id]/page.tsx
      alerts/page.tsx
      settings/page.tsx
      clusters/page.tsx
      clusters/[id]/page.tsx
      campaigns/page.tsx
      campaigns/[id]/page.tsx
      actors/page.tsx
      actors/[id]/page.tsx
      api/proxy/[...path]/route.ts
    components/
      ui/
      layout/
        sidebar.tsx
        header.tsx
      threats/
        threat-table.tsx
        threat-score-badge.tsx
        score-breakdown.tsx
        ioc-list.tsx
        relationship-graph.tsx
      alerts/
        webhook-card.tsx
        webhook-form.tsx
        alert-history.tsx
      monitoring/
        monitoring-dashboard.tsx
        domain-detail.tsx
      shared/
        score-bar.tsx
        risk-badge.tsx
        global-search.tsx
        severity-badge.tsx
    lib/
      api.ts
      query-client.ts
      store.ts
  docker-compose.yml
```

---

## 12. Phase Build Order

| Phase | Scope | Timeline |
|---|---|---|
| Phase 1 | PostgreSQL migration, Dramatiq pipeline, plugin scoring, risk scoring, webhooks (dry-run → live), enhanced frontend | Weeks 1-3 |
| Phase 2 | IOC extraction, HTML similarity (Qdrant), infra clustering, DNS enrichment | Weeks 4-6 |
| Phase 3 | PhishKit detection (fuzzy), campaign engine, campaign timeline UI | Weeks 7-9 |
| Phase 4 | Actor profiling, C2 inference, actor confidence visualization | Weeks 10-12 |