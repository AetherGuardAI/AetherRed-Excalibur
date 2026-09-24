"""Core data models for AetherGuard-Excalibur."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CampaignStatus(str, Enum):
    """Campaign lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class AttackStatus(str, Enum):
    """Individual attack execution states."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class AttackCategory(str, Enum):
    """Attack type categories."""

    ADVERSARIAL_ML = "adversarial_ml"
    NLP_LANGUAGE = "nlp_language"
    AGENT_TRUST = "agent_trust"
    RAG_EMBEDDING = "rag_embedding"
    INFRASTRUCTURE = "infrastructure"
    MODEL_INTEGRITY = "model_integrity"
    EVASION = "evasion"
    CONTENT_SAFETY = "content_safety"


class AtlasMapping(BaseModel):
    """MITRE ATLAS technique mapping for an attack."""

    technique_id: str = Field(description="ATLAS technique ID (e.g., AML.T0043)")
    technique_name: str = Field(description="Human-readable technique name")
    tactic: str = Field(description="ATLAS tactic (e.g., Evasion, Initial Access)")
    sub_technique: str | None = Field(default=None, description="Sub-technique ID if applicable")
    confidence: float = Field(default=1.0, description="Mapping confidence 0-1")


class AttackSample(BaseModel):
    """A single successful attack example for reporting."""

    input_text: str = Field(description="Original input")
    adversarial_text: str | None = Field(default=None, description="Modified adversarial input")
    original_output: str | None = Field(default=None, description="Model's original response")
    adversarial_output: str | None = Field(default=None, description="Model's response to attack")
    perturbation_magnitude: float | None = Field(default=None, description="Magnitude of change")
    notes: str | None = Field(default=None, description="Additional context")


class AttackResult(BaseModel):
    """Result of a single attack execution."""

    attack_name: str = Field(description="Attack type name")
    attack_type: str = Field(description="Attack class identifier")
    category: AttackCategory = Field(description="Attack category")
    atlas_id: str = Field(description="MITRE ATLAS technique ID")
    status: AttackStatus = Field(description="Execution status")
    success_rate: float = Field(default=0.0, description="Attack success rate 0-1")
    confidence: float = Field(default=0.0, description="Confidence in results 0-1")
    metrics: dict[str, Any] = Field(default_factory=dict, description="Attack-specific metrics")
    payloads_used: int = Field(default=0, description="Total payloads/samples attempted")
    payloads_successful: int = Field(default=0, description="Payloads that succeeded")
    samples: list[AttackSample] = Field(default_factory=list, description="Example successful attacks")
    duration_seconds: float = Field(default=0.0, description="Execution time")
    error: str | None = Field(default=None, description="Error message if failed")
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)


class ResilienceScore(BaseModel):
    """AetherGuard proprietary resilience scoring."""

    overall: float = Field(description="Overall score 0-100")
    grade: str = Field(description="Letter grade: A, B, C, D, F")
    categories: dict[str, float] = Field(
        default_factory=dict, description="Per-category scores 0-100"
    )
    breakdown: dict[str, Any] = Field(
        default_factory=dict, description="Detailed scoring breakdown"
    )

    @staticmethod
    def compute_grade(score: float) -> str:
        """Compute letter grade from numeric score."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


class ARTMetrics(BaseModel):
    """ART (Adversarial Robustness Toolbox) compatible metrics."""

    precision: float = Field(default=0.0, description="Detection precision")
    recall: float = Field(default=0.0, description="Detection recall")
    f1_score: float = Field(default=0.0, description="F1 score")
    per_category: dict[str, dict[str, float]] = Field(
        default_factory=dict, description="Per-category precision/recall/F1"
    )


class CampaignResult(BaseModel):
    """Aggregated results for an entire campaign."""

    campaign_id: str = Field(description="Campaign unique ID")
    campaign_name: str = Field(description="Campaign display name")
    status: CampaignStatus = Field(description="Final campaign status")
    total_attacks: int = Field(default=0, description="Total attacks configured")
    completed: int = Field(default=0, description="Attacks completed")
    failed: int = Field(default=0, description="Attacks that errored")
    skipped: int = Field(default=0, description="Attacks skipped")
    overall_success_rate: float = Field(default=0.0, description="Mean attack success rate")
    resilience_score: ResilienceScore | None = Field(default=None)
    art_metrics: ARTMetrics | None = Field(default=None)
    atlas_mappings: list[AtlasMapping] = Field(default_factory=list)
    attack_results: list[AttackResult] = Field(default_factory=list)
    duration_seconds: float = Field(default=0.0, description="Total campaign duration")
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    target_info: dict[str, str] = Field(default_factory=dict, description="Target system metadata")


class Campaign(BaseModel):
    """Campaign entity with full state."""

    id: str = Field(description="Unique campaign ID")
    name: str = Field(description="Campaign display name")
    description: str = Field(default="")
    status: CampaignStatus = Field(default=CampaignStatus.PENDING)
    config: dict[str, Any] = Field(default_factory=dict, description="Campaign config snapshot")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    result: CampaignResult | None = Field(default=None)


class AttackMetadata(BaseModel):
    """Metadata about a registered attack type."""

    name: str = Field(description="Attack name identifier")
    display_name: str = Field(description="Human-readable name")
    category: AttackCategory = Field(description="Attack category")
    atlas_id: str = Field(description="MITRE ATLAS technique ID")
    description: str = Field(description="Attack description")
    interface: str = Field(description="Interface type: blackbox, whitebox, protocol")
    params_schema: dict[str, Any] = Field(default_factory=dict, description="Parameter JSON schema")


class ProgressEvent(BaseModel):
    """Progress event emitted during campaign execution."""

    campaign_id: str
    event_type: str = Field(description="Type: attack_started, attack_completed, campaign_completed")
    attack_name: str | None = Field(default=None)
    progress: float = Field(default=0.0, description="Overall progress 0-1")
    message: str = Field(default="")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
