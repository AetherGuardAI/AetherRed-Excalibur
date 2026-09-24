"""Attack listing and ad-hoc execution routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from aetherguard_excalibur.models import AttackMetadata

router = APIRouter()


class AttackRunRequest(BaseModel):
    """Request body for running a single ad-hoc attack."""

    type: str = Field(description="Attack type name")
    target: dict[str, Any] = Field(description="Target configuration")
    params: dict[str, Any] = Field(default_factory=dict, description="Attack parameters")


@router.get("")
async def list_attacks(request: Request, category: str | None = None) -> list[dict[str, Any]]:
    """List all available attack types with metadata."""
    registry = request.app.state.registry
    attacks = registry.list_attacks(category)

    return [
        {
            "name": a.name,
            "display_name": a.display_name,
            "category": a.category.value,
            "atlas_id": a.atlas_id,
            "description": a.description,
            "interface": a.interface,
            "params_schema": a.params_schema,
        }
        for a in attacks
    ]


@router.get("/categories")
async def list_categories(request: Request) -> list[str]:
    """List available attack categories."""
    registry = request.app.state.registry
    return registry.categories


@router.post("/run")
async def run_attack(request: Request, body: AttackRunRequest):
    """Run a single ad-hoc attack and return results."""
    from aetherguard_excalibur.adapters.factory import AdapterFactory
    from aetherguard_excalibur.config import TargetConfig

    registry = request.app.state.registry

    try:
        attack = registry.get_attack(body.type)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Create target adapter
    target_config = TargetConfig(**body.target)
    factory = AdapterFactory()
    adapter = factory.create_target(target_config)

    try:
        params = attack.validate_params(body.params)
        await attack.setup(adapter, params)
        result = await attack.execute()
        await attack.teardown()

        return result.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack execution failed: {str(e)}")
    finally:
        await adapter.close()
