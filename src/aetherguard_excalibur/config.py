"""Configuration management for AetherGuard-Excalibur."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    """Configuration for a target system under test."""

    type: str = Field(description="Target type: openai, anthropic, azure, bedrock, local")
    model: str = Field(default="gpt-4o-mini", description="Model identifier")
    base_url: str | None = Field(default=None, description="Custom base URL")
    api_key_env: str | None = Field(default=None, description="Env var name for API key")
    region: str | None = Field(default=None, description="AWS region for Bedrock")
    temperature: float = Field(default=0.0, description="Default temperature")
    max_tokens: int = Field(default=1024, description="Default max tokens")
    timeout: int = Field(default=60, description="Request timeout in seconds")


class VectorStoreConfig(BaseModel):
    """Configuration for a vector store target."""

    type: str = Field(description="Vector store type: pinecone, weaviate, chroma, pgvector")
    host: str | None = Field(default=None, description="Host URL or connection string")
    api_key_env: str | None = Field(default=None, description="Env var name for API key")
    index_name: str | None = Field(default=None, description="Index/collection name")
    namespace: str | None = Field(default=None, description="Namespace for isolation")


class ModelConfig(BaseModel):
    """Configuration for direct model access (white-box)."""

    framework: str = Field(default="pytorch", description="Framework: pytorch, onnx, transformers")
    model_path: str = Field(description="Path to model weights or HF model ID")
    device: str = Field(default="cpu", description="Device: cpu, cuda, cuda:0")
    dtype: str = Field(default="float32", description="Model dtype: float32, float16, bfloat16")


class RateLimitConfig(BaseModel):
    """Rate limiting configuration to prevent target DoS."""

    requests_per_minute: int = Field(default=60, description="Max requests per minute per target")
    requests_per_second: int = Field(default=5, description="Max requests per second per target")
    burst_size: int = Field(default=10, description="Burst allowance")
    backoff_factor: float = Field(default=2.0, description="Exponential backoff multiplier")
    max_retries: int = Field(default=3, description="Max retries on rate limit")


class ExecutionConfig(BaseModel):
    """Campaign execution configuration."""

    max_parallel: int = Field(default=5, description="Max parallel attacks")
    attack_timeout: int = Field(default=300, description="Per-attack timeout in seconds")
    campaign_timeout: int = Field(default=3600, description="Campaign timeout in seconds")
    save_results: bool = Field(default=True, description="Persist results to disk")
    results_dir: str = Field(default="results", description="Directory for saved results")


class ReportConfig(BaseModel):
    """Reporting configuration."""

    formats: list[str] = Field(default=["json"], description="Output formats: json, html, pdf, sarif")
    resilience_score: bool = Field(default=True, description="Compute resilience score")
    atlas_mapping: bool = Field(default=True, description="Include ATLAS technique mapping")
    art_metrics: bool = Field(default=True, description="Include ART-compatible metrics")
    output_dir: str = Field(default="reports", description="Report output directory")


class AttackConfig(BaseModel):
    """Per-attack configuration within a campaign."""

    type: str = Field(description="Attack type name (e.g., textfooler, pgd, maic)")
    enabled: bool = Field(default=True, description="Whether this attack is enabled")
    params: dict[str, Any] = Field(default_factory=dict, description="Attack-specific parameters")
    timeout: int | None = Field(default=None, description="Override per-attack timeout")
    samples: int = Field(default=100, description="Number of samples to test")


class JudgeLLMConfig(BaseModel):
    """Configuration for the judge LLM evaluator."""

    enabled: bool = Field(default=False, description="Enable LLM judge for result evaluation")
    provider: str = Field(default="openai", description="Judge provider: openai, anthropic")
    model: str = Field(default="gpt-4o", description="Judge model ID")
    api_key_env: str = Field(default="EXCALIBUR_JUDGE_API_KEY", description="Env var for judge API key")
    temperature: float = Field(default=0.0, description="Temperature (0 = deterministic)")
    max_tokens: int = Field(default=500, description="Max tokens for judge response")


class CampaignConfig(BaseModel):
    """Campaign-level configuration loaded from YAML."""

    name: str = Field(description="Campaign name")
    description: str = Field(default="", description="Campaign description")
    target: TargetConfig = Field(description="Target system configuration")
    vector_store: VectorStoreConfig | None = Field(default=None, description="Vector store target")
    model: ModelConfig | None = Field(default=None, description="Direct model access config")
    attacks: list[AttackConfig] = Field(description="List of attacks to execute")
    parallel: int = Field(default=3, description="Max parallel attacks in this campaign")
    reporting: ReportConfig = Field(default_factory=ReportConfig)
    judge: JudgeLLMConfig = Field(default_factory=JudgeLLMConfig, description="Judge LLM config")


class ExcaliburConfig(BaseModel):
    """Root system configuration."""

    targets: dict[str, TargetConfig] = Field(default_factory=dict, description="Named targets")
    vector_stores: dict[str, VectorStoreConfig] = Field(default_factory=dict)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    reporting: ReportConfig = Field(default_factory=ReportConfig)
    judge: JudgeLLMConfig = Field(default_factory=JudgeLLMConfig, description="Judge LLM config")


def load_config(config_path: Path | None = None) -> ExcaliburConfig:
    """Load system configuration from YAML file or defaults.

    Resolution order:
    1. Built-in defaults
    2. ~/.excalibur/config.yaml (if exists)
    3. Provided config_path (if given)
    4. Environment variables (EXCALIBUR_* prefix)
    """
    config_data: dict[str, Any] = {}

    # Check user-level config
    user_config = Path.home() / ".excalibur" / "config.yaml"
    if user_config.exists():
        with open(user_config) as f:
            user_data = yaml.safe_load(f) or {}
            config_data.update(user_data)

    # Override with provided config
    if config_path and config_path.exists():
        with open(config_path) as f:
            file_data = yaml.safe_load(f) or {}
            config_data.update(file_data)

    return ExcaliburConfig(**config_data)


def load_campaign(campaign_path: Path) -> CampaignConfig:
    """Load and validate a campaign configuration from YAML."""
    if not campaign_path.exists():
        raise FileNotFoundError(f"Campaign config not found: {campaign_path}")

    with open(campaign_path) as f:
        data = yaml.safe_load(f)

    if not data:
        raise ValueError(f"Empty campaign config: {campaign_path}")

    # Resolve API key from environment
    if "target" in data and "api_key_env" in data["target"]:
        env_var = data["target"]["api_key_env"]
        if env_var and not os.environ.get(env_var):
            raise EnvironmentError(
                f"Required environment variable '{env_var}' not set. "
                f"Set it with: export {env_var}=<your-api-key>"
            )

    return CampaignConfig(**data)


def merge_configs(
    system: ExcaliburConfig,
    campaign: CampaignConfig,
    cli_overrides: dict[str, Any] | None = None,
) -> CampaignConfig:
    """Merge configuration hierarchy: system defaults < campaign < CLI overrides."""
    # Apply system-level rate limits and execution config as context
    # Campaign config takes precedence for its own fields
    if cli_overrides:
        campaign_data = campaign.model_dump()
        for key, value in cli_overrides.items():
            if value is not None:
                keys = key.split(".")
                d = campaign_data
                for k in keys[:-1]:
                    d = d.setdefault(k, {})
                d[keys[-1]] = value
        return CampaignConfig(**campaign_data)

    return campaign
