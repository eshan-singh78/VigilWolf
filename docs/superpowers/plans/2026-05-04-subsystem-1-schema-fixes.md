# Subsystem 1: Schema Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add missing `asn` and `registrar` DB columns, fix Alembic migration collisions, add phone/wallet IOC normalization.

**Architecture:** Surgical schema additions + migration re-chaining + normalization logic. No refactoring.

**Tech Stack:** SQLAlchemy, Alembic, Python stdlib

---

### Task 1: Add `asn` column to DomainIpModel and `registrar` column to DomainModel

**Files:**
- Modify: `vigilwolf-v2/backend/database.py:202-218` (DomainIpModel)
- Modify: `vigilwolf-v2/backend/database.py:77-100` (DomainModel)
- Modify: `vigilwolf-v2/backend/database.py:502` (ClusteringWatermarkModel onupdate)
- Test: `vigilwolf-v2/backend/test_v2_schema.py`

- [ ] **Step 1: Add `asn` column to DomainIpModel**

In `database.py`, after line 210 (`last_seen = Column(DateTime, default=utc_now, nullable=False)`), add:

```python
        asn = Column(String(20), nullable=True)
```

- [ ] **Step 2: Add `registrar` column to DomainModel**

In `database.py`, after line 88 (`active = Column(Boolean, default=True, nullable=False)`), add:

```python
    registrar = Column(String(200), nullable=True)
```

- [ ] **Step 3: Remove `onupdate` from ClusteringWatermarkModel**

In `database.py` line 502, change:
```python
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
```
to:
```python
    updated_at = Column(DateTime, default=utc_now, nullable=False)
```

- [ ] **Step 4: Verify schema changes work**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "from database import DomainIpModel, DomainModel, ClusteringWatermarkModel; print('OK')"`
Expected: OK

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-v2/backend/database.py
git commit -m "feat: add asn/registrar columns, remove ClusteringWatermarkModel onupdate"
```

---

### Task 2: Create migration 015_add_asn_registrar_columns

**Files:**
- Create: `vigilwolf-v2/backend/migrations/versions/015_add_asn_registrar_columns.py`

- [ ] **Step 1: Create migration file**

Create `015_add_asn_registrar_columns.py`:

```python
"""add asn and registrar columns, remove clustering watermark onupdate

Revision ID: 015_add_asn_registrar_columns
Revises: 014_remove_onupdate_domain_processing_plugin_weight
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "015_add_asn_registrar_columns"
down_revision = "014_remove_onupdate_domain_processing_plugin_weight"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("domain_ips", sa.Column("asn", sa.String(20), nullable=True))
    op.add_column("domains", sa.Column("registrar", sa.String(200), nullable=True))


def downgrade() -> None:
    op.drop_column("domains", "registrar")
    op.drop_column("domain_ips", "asn")
```

- [ ] **Step 2: Verify migration syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "import importlib.util; spec = importlib.util.spec_from_file_location('m', 'migrations/versions/015_add_asn_registrar_columns.py'); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); print('revision:', mod.revision, 'down:', mod.down_revision)"`
Expected: revision: 015_add_asn_registrar_columns down: 014_remove_onupdate_domain_processing_plugin_weight

- [ ] **Step 3: Commit**

```bash
git add vigilwolf-v2/backend/migrations/versions/015_add_asn_registrar_columns.py
git commit -m "feat: add migration 015 for asn/registrar columns"
```

---

### Task 3: Fix Alembic migration collisions (H-5)

**Files:**
- Modify: `vigilwolf-v2/backend/migrations/versions/004_pipeline_status.py:14`
- Modify: `vigilwolf-v2/backend/migrations/versions/005_clustering_watermark.py:14`
- Modify: `vigilwolf-v2/backend/migrations/versions/005_phishkit_unique_constraint.py:12`

- [ ] **Step 1: Fix 004_pipeline_status down_revision**

In `004_pipeline_status.py` line 14, change:
```python
down_revision = "003_performance_indexes"
```
to:
```python
down_revision = "004_intelligence_unique_constraints"
```

- [ ] **Step 2: Fix 005_clustering_watermark down_revision**

In `005_clustering_watermark.py` line 14, change:
```python
down_revision = "004_pipeline_status"
```
to:
```python
down_revision = "004_pipeline_status"
```
(Already correct — no change needed)

- [ ] **Step 3: Fix 005_phishkit_unique_constraint down_revision**

In `005_phishkit_unique_constraint.py` line 12, change:
```python
down_revision = "004_intelligence_unique_constraints"
```
to:
```python
down_revision = "005_clustering_watermark"
```

- [ ] **Step 4: Verify chain is linear**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "
import importlib.util, os
migrations_dir = 'migrations/versions'
chain = {}
for f in os.listdir(migrations_dir):
    if f.endswith('.py') and not f.startswith('_'):
        spec = importlib.util.spec_from_file_location('m', os.path.join(migrations_dir, f))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, 'revision') and hasattr(mod, 'down_revision'):
            chain[mod.revision] = mod.down_revision
            print(f'{mod.revision} -> {mod.down_revision}')
"`
Expected: Linear chain with no two migrations sharing the same down_revision

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-v2/backend/migrations/versions/004_pipeline_status.py vigilwolf-v2/backend/migrations/versions/005_phishkit_unique_constraint.py
git commit -m "fix: re-chain Alembic migrations to resolve 004/005 collisions (H-5)"
```

---

### Task 4: Add phone and wallet normalization (D-3)

**Files:**
- Modify: `vigilwolf-v2/backend/services/ioc_service.py:27-60`
- Test: `vigilwolf-v2/backend/test_ioc_extractor.py`

- [ ] **Step 1: Write failing tests for phone and wallet normalization**

In `test_ioc_extractor.py`, add:

```python
from services.ioc_service import _normalize_ioc_value


def test_phone_normalization_with_country_code():
    assert _normalize_ioc_value("phone", "+1-555-123-4567") == "+15551234567"


def test_phone_normalization_without_country_code():
    assert _normalize_ioc_value("phone", "5551234567") == "+15551234567"


def test_phone_normalization_international():
    assert _normalize_ioc_value("phone", "+44 20 7946 0958") == "+442079460958"


def test_wallet_normalization_evm_lowercase():
    assert _normalize_ioc_value("wallet", "0xDeadBeef00000000000000000000000000000000") == "0xdeadbeef00000000000000000000000000000000"


def test_wallet_normalization_bitcoin_preserved():
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert _normalize_ioc_value("wallet", btc) == btc
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -m pytest test_ioc_extractor.py::test_phone_normalization_with_country_code -v`
Expected: FAIL (phone case returns input unchanged)

- [ ] **Step 3: Add phone normalization to `_normalize_ioc_value`**

In `ioc_service.py`, after the `telegram` case (line 59), add:

```python
    if ioc_type == "phone":
        digits = re.sub(r"\D", "", value)
        if not digits:
            return value
        if len(digits) == 11 and digits.startswith("1"):
            return f"+{digits}"
        if len(digits) == 10:
            return f"+1{digits}"
        return f"+{digits}"
    if ioc_type == "wallet":
        if value.startswith("0x") or value.startswith("0X"):
            return value.lower()
        return value
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -m pytest test_ioc_extractor.py -k "test_phone or test_wallet" -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add vigilwolf-v2/backend/services/ioc_service.py vigilwolf-v2/backend/test_ioc_extractor.py
git commit -m "feat: add phone and wallet IOC normalization (D-3)"
```

---

### Task 5: Wire whois_enricher registrar to DomainModel

**Files:**
- Modify: `vigilwolf-v2/backend/worker.py:868-876` (enrichment injection block)

- [ ] **Step 1: Update whois_enricher enrichment to persist registrar**

In `worker.py`, after the existing whois_enricher enrichment block (lines 868-874), add registrar persistence:

```python
                    if result.plugin_name == "whois_enricher" and result.findings:
                        if "registrar" in result.findings:
                            ctx.metadata["registrar"] = result.findings["registrar"]
                            # Persist registrar to DomainModel
                            try:
                                with get_session() as reg_session:
                                    domain_obj = reg_session.query(DomainModel).filter_by(id=ctx.snapshot_record.get("domain_id")).first()
                                    if domain_obj is not None and not domain_obj.registrar:
                                        domain_obj.registrar = result.findings["registrar"]
                                        reg_session.commit()
                            except Exception:
                                logger.debug("Failed to persist registrar for domain_id=%s", ctx.snapshot_record.get("domain_id", "")[:8])
```

Note: This replaces the existing whois_enricher block. The `ctx.metadata` and `ctx.snapshot_record` updates remain; only the DB persistence is added.

- [ ] **Step 2: Verify syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "import worker; print('OK')"`
Expected: OK

- [ ] **Step 3: Commit**

```bash
git add vigilwolf-v2/backend/worker.py
git commit -m "feat: persist whois registrar to DomainModel (C-1 wiring)"
```

---

### Task 6: Wire dns_enricher ASN to DomainIpModel

**Files:**
- Modify: `vigilwolf-v2/backend/worker.py:875-876` (dns_enricher enrichment block)

- [ ] **Step 1: Update dns_enricher enrichment to persist ASN**

In `worker.py`, after the existing dns_enricher enrichment block (lines 875-876), add ASN persistence:

```python
                    elif result.plugin_name == "dns_enricher" and result.findings:
                        ctx.metadata["dns_records"] = result.findings
                        # Persist ASN data to DomainIpModel if available
                        try:
                            with get_session() as dns_session:
                                from database import DomainIpModel
                                domain_id = ctx.snapshot_record.get("domain_id")
                                asn_value = result.findings.get("asn")
                                if asn_value and domain_id:
                                    ip_rows = (
                                        dns_session.query(DomainIpModel)
                                        .filter(DomainIpModel.domain_id == domain_id)
                                        .all()
                                    )
                                    for ip_row in ip_rows:
                                        if not ip_row.asn:
                                            ip_row.asn = str(asn_value)
                                    dns_session.commit()
                        except Exception:
                            logger.debug("Failed to persist ASN for domain_id=%s", ctx.snapshot_record.get("domain_id", "")[:8])
```

- [ ] **Step 2: Verify syntax**

Run: `cd /Users/eshansingh/Documents/GitHub/VigilWolf/vigilwolf-v2/backend && python -c "import worker; print('OK')"`
Expected: OK

- [ ] **Step 3: Commit**

```bash
git add vigilwolf-v2/backend/worker.py
git commit -m "feat: persist DNS ASN data to DomainIpModel (C-1 wiring)"
```