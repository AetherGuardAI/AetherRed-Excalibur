"""FastAPI application for AetherGuard-Excalibur API server."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aetherguard_excalibur.adapters.factory import AdapterFactory
from aetherguard_excalibur.api.routes import attacks, campaigns, reports
from aetherguard_excalibur.config import load_config
from aetherguard_excalibur.engine import CampaignEngine
from aetherguard_excalibur.registry import AttackRegistry
from aetherguard_excalibur.reporting import ReportGenerator


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialize shared resources."""
    config = load_config()
    registry = AttackRegistry()
    registry.discover_attacks()

    app.state.config = config
    app.state.registry = registry
    app.state.engine = CampaignEngine(config, registry, AdapterFactory())
    app.state.report_generator = ReportGenerator(config.reporting)

    yield


app = FastAPI(
    title="AetherGuard-Excalibur",
    description="AI Red-Teaming & Attack Simulation Platform API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(campaigns.router, prefix="/api/campaigns", tags=["Campaigns"])
app.include_router(attacks.router, prefix="/api/attacks", tags=["Attacks"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "excalibur", "version": "1.0.0"}
