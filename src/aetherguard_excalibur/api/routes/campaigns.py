"""Campaign CRUD and execution routes."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, WebSocket
from pydantic import BaseModel, Field

from aetherguard_excalibur.config import CampaignConfig
from aetherguard_excalibur.models import CampaignResult, CampaignStatus, ProgressEvent

router = APIRouter()


class CampaignCreateRequest(BaseModel):
    """Request body for creating a campaign."""

    name: str = Field(description="Campaign name")
    description: str = Field(default="")
    target: dict[str, Any] = Field(description="Target configuration")
    vector_store: dict[str, Any] | None = Field(default=None)
    attacks: list[dict[str, Any]] = Field(description="Attack configurations")
    parallel: int = Field(default=3)
    reporting: dict[str, Any] = Field(default_factory=lambda: {"formats": ["json", "html"]})


class CampaignResponse(BaseModel):
    """Campaign response."""

    id: str
    name: str
    status: str
    total_attacks: int


@router.post("", response_model=CampaignResponse)
async def create_campaign(request: Request, body: CampaignCreateRequest, background_tasks: BackgroundTasks):
    """Create and start a new attack campaign."""
    engine = request.app.state.engine

    campaign_config = CampaignConfig(
        name=body.name,
        description=body.description,
        target=body.target,
        vector_store=body.vector_store,
        attacks=body.attacks,
        parallel=body.parallel,
        reporting=body.reporting,
    )

    campaign = await engine.create_campaign(campaign_config)

    # Run campaign in background
    background_tasks.add_task(_run_campaign_background, engine, campaign, request.app.state.report_generator, campaign_config)

    return CampaignResponse(
        id=campaign.id,
        name=campaign.name,
        status=campaign.status.value,
        total_attacks=len([a for a in body.attacks if a.get("enabled", True)]),
    )


async def _run_campaign_background(engine, campaign, report_generator, campaign_config):
    """Background task to execute campaign and generate reports."""
    from pathlib import Path

    result = await engine.execute_campaign(campaign)

    # Generate reports
    if result:
        await report_generator.generate(result, Path(campaign_config.reporting.get("output_dir", "results")))


@router.get("/{campaign_id}")
async def get_campaign(request: Request, campaign_id: str):
    """Get campaign status and results."""
    engine = request.app.state.engine
    campaign = await engine.get_campaign_status(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    response = {
        "id": campaign.id,
        "name": campaign.name,
        "status": campaign.status.value,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
    }

    if campaign.result:
        response["result"] = campaign.result.model_dump(mode="json")

    return response


@router.post("/{campaign_id}/abort")
async def abort_campaign(request: Request, campaign_id: str):
    """Abort a running campaign."""
    engine = request.app.state.engine
    await engine.abort_campaign(campaign_id)
    return {"status": "aborted", "campaign_id": campaign_id}
