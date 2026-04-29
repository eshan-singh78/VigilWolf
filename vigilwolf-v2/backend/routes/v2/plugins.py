"""VigilWolf v2 — Plugin management and risk threshold API endpoints."""

from __future__ import annotations


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

import config
from database import PluginWeightModel, get_db
from plugins.registry import PLUGIN_REGISTRY

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class PluginInfo(BaseModel):
    name: str
    version: str
    plugin_type: str
    weight: float
    enabled: bool


class PluginListResponse(BaseModel):
    plugins: list[PluginInfo]


class WeightUpdate(BaseModel):
    weight: float


class EnabledUpdate(BaseModel):
    enabled: bool


class RiskThresholdsResponse(BaseModel):
    risk_threshold_high: int
    risk_threshold_medium: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/plugins", )
def list_plugins(session: Session = Depends(get_db)) -> PluginListResponse:
    """List registered plugins with their types, versions, and weights."""
    # Load weights from DB
    weight_rows = session.execute(select(PluginWeightModel)).scalars().all()
    weight_map = {row.plugin_name: row for row in weight_rows}

    plugins: list[PluginInfo] = []
    for name, cls in sorted(PLUGIN_REGISTRY.items()):
        # Check if there's a DB weight row
        db_weight = weight_map.get(name)
        weight = db_weight.weight if db_weight else 1.0
        enabled = db_weight.enabled if db_weight else True

        plugins.append(PluginInfo(
            name=name,
            version=cls.version,
            plugin_type=cls.plugin_type.value,
            weight=weight,
            enabled=enabled,
        ))

    return PluginListResponse(plugins=plugins)


@router.put("/plugins/{plugin_name}/weight", )
def update_plugin_weight(
    plugin_name: str,
    body: WeightUpdate,
    session: Session = Depends(get_db),
) -> PluginInfo:
    """Update plugin weight."""
    if plugin_name not in PLUGIN_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    weight_row = session.execute(
        select(PluginWeightModel).where(PluginWeightModel.plugin_name == plugin_name)
    ).scalars().first()

    if weight_row:
        weight_row.weight = body.weight
    else:
        weight_row = PluginWeightModel(
            plugin_name=plugin_name,
            weight=body.weight,
            enabled=True,
        )
        session.add(weight_row)

    session.commit()
    session.refresh(weight_row)

    cls = PLUGIN_REGISTRY[plugin_name]
    return PluginInfo(
        name=plugin_name,
        version=cls.version,
        plugin_type=cls.plugin_type.value,
        weight=weight_row.weight,
        enabled=weight_row.enabled,
    )


@router.put("/plugins/{plugin_name}/enabled", )
def update_plugin_enabled(
    plugin_name: str,
    body: EnabledUpdate,
    session: Session = Depends(get_db),
) -> PluginInfo:
    """Enable or disable a plugin."""
    if plugin_name not in PLUGIN_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found")

    weight_row = session.execute(
        select(PluginWeightModel).where(PluginWeightModel.plugin_name == plugin_name)
    ).scalars().first()

    if weight_row:
        weight_row.enabled = body.enabled
    else:
        weight_row = PluginWeightModel(
            plugin_name=plugin_name,
            weight=1.0,
            enabled=body.enabled,
        )
        session.add(weight_row)

    session.commit()
    session.refresh(weight_row)

    cls = PLUGIN_REGISTRY[plugin_name]
    return PluginInfo(
        name=plugin_name,
        version=cls.version,
        plugin_type=cls.plugin_type.value,
        weight=weight_row.weight,
        enabled=weight_row.enabled,
    )


@router.get("/risk-thresholds", )
def get_risk_thresholds() -> RiskThresholdsResponse:
    """Get current risk thresholds from config."""
    return RiskThresholdsResponse(
        risk_threshold_high=config.RISK_THRESHOLD_HIGH,
        risk_threshold_medium=config.RISK_THRESHOLD_MEDIUM,
    )