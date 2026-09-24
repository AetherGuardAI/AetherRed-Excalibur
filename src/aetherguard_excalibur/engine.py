"""Campaign orchestration engine — manages attack execution lifecycle."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from aetherguard_excalibur.adapters.factory import AdapterFactory
from aetherguard_excalibur.attacks.base import BaseAttack
from aetherguard_excalibur.config import CampaignConfig, ExcaliburConfig, RateLimitConfig
from aetherguard_excalibur.models import (
    AttackResult,
    AttackStatus,
    Campaign,
    CampaignResult,
    CampaignStatus,
    ProgressEvent,
)
from aetherguard_excalibur.registry import AttackRegistry

logger = logging.getLogger(__name__)


class CampaignEngine:
    """Core orchestration engine for running attack campaigns.

    Manages the full lifecycle: campaign creation, attack sequencing,
    parallel execution, progress tracking, and result aggregation.
    """

    def __init__(
        self,
        config: ExcaliburConfig,
        registry: AttackRegistry,
        adapter_factory: AdapterFactory | None = None,
    ) -> None:
        self._config = config
        self._registry = registry
        self._adapter_factory = adapter_factory or AdapterFactory()
        self._campaigns: dict[str, Campaign] = {}
        self._rate_limiters: dict[str, asyncio.Semaphore] = {}

    async def create_campaign(self, campaign_config: CampaignConfig) -> Campaign:
        """Create a new campaign from configuration.

        Args:
            campaign_config: Validated campaign configuration.

        Returns:
            Campaign entity with PENDING status.
        """
        campaign = Campaign(
            id=str(uuid.uuid4()),
            name=campaign_config.name,
            description=campaign_config.description,
            status=CampaignStatus.PENDING,
            config=campaign_config.model_dump(),
        )
        self._campaigns[campaign.id] = campaign
        logger.info(f"Created campaign: {campaign.name} ({campaign.id})")
        return campaign

    async def execute_campaign(
        self,
        campaign: Campaign,
        on_progress: Callable[[ProgressEvent], None] | None = None,
    ) -> CampaignResult:
        """Execute all attacks in a campaign with orchestration.

        Args:
            campaign: Campaign to execute.
            on_progress: Optional callback for progress events.

        Returns:
            Aggregated CampaignResult.
        """
        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = datetime.now(timezone.utc)
        start_time = time.time()

        campaign_config = CampaignConfig(**campaign.config)
        target_adapter = self._adapter_factory.create_target(campaign_config.target)

        # Initialize judge LLM if configured
        judge_instance = None
        if campaign_config.judge.enabled:
            from aetherguard_excalibur.judge import JudgeConfig, LLMJudge

            judge_config = JudgeConfig(
                enabled=True,
                provider=campaign_config.judge.provider,
                model=campaign_config.judge.model,
                api_key_env=campaign_config.judge.api_key_env,
            )
            judge_instance = LLMJudge(judge_config)
            logger.info(f"Judge LLM enabled: {campaign_config.judge.provider}/{campaign_config.judge.model}")

        # Filter enabled attacks
        enabled_attacks = [a for a in campaign_config.attacks if a.enabled]
        total_attacks = len(enabled_attacks)
        results: list[AttackResult] = []

        logger.info(
            f"Executing campaign '{campaign.name}' with {total_attacks} attacks "
            f"(parallel={campaign_config.parallel})"
        )

        # Execute attacks with bounded concurrency
        semaphore = asyncio.Semaphore(campaign_config.parallel)

        async def run_single_attack(attack_config: Any, index: int) -> AttackResult:
            async with semaphore:
                return await self._execute_attack(
                    attack_config=attack_config,
                    target_adapter=target_adapter,
                    campaign_config=campaign_config,
                    index=index,
                    total=total_attacks,
                    on_progress=on_progress,
                    campaign_id=campaign.id,
                    judge=judge_instance,
                )

        tasks = [
            run_single_attack(attack_cfg, i)
            for i, attack_cfg in enumerate(enabled_attacks)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=False)

        # Close target adapter and judge
        await target_adapter.close()
        if judge_instance:
            await judge_instance.close()

        # Aggregate results
        duration = time.time() - start_time
        campaign_result = self._aggregate_results(
            campaign_id=campaign.id,
            campaign_name=campaign.name,
            results=results,
            duration=duration,
            target_info={"type": campaign_config.target.type, "model": campaign_config.target.model},
        )

        # Update campaign state
        campaign.status = CampaignStatus.COMPLETED
        campaign.completed_at = datetime.now(timezone.utc)
        campaign.result = campaign_result

        # Emit completion event
        if on_progress:
            on_progress(
                ProgressEvent(
                    campaign_id=campaign.id,
                    event_type="campaign_completed",
                    progress=1.0,
                    message=f"Campaign completed: {campaign_result.resilience_score.overall if campaign_result.resilience_score else 'N/A'}/100",
                )
            )

        logger.info(
            f"Campaign '{campaign.name}' completed in {duration:.1f}s — "
            f"{campaign_result.completed}/{total_attacks} attacks, "
            f"success_rate={campaign_result.overall_success_rate:.2%}"
        )

        return campaign_result

    async def _execute_attack(
        self,
        attack_config: Any,
        target_adapter: Any,
        campaign_config: CampaignConfig,
        index: int,
        total: int,
        on_progress: Callable[[ProgressEvent], None] | None,
        campaign_id: str,
        judge: Any = None,
    ) -> AttackResult:
        """Execute a single attack with error handling and timing."""
        attack_name = attack_config.type
        start_time = time.time()

        # Emit start event
        if on_progress:
            on_progress(
                ProgressEvent(
                    campaign_id=campaign_id,
                    event_type="attack_started",
                    attack_name=attack_name,
                    progress=index / total,
                    message=f"Starting {attack_name} ({index + 1}/{total})",
                )
            )

        try:
            # Get attack instance from registry
            attack = self._registry.get_attack(attack_name)

            # Validate and apply params
            params = attack.validate_params(attack_config.params)

            # Setup
            await attack.setup(target_adapter, params)

            # Execute with timeout
            timeout = attack_config.timeout or self._config.execution.attack_timeout
            result = await asyncio.wait_for(attack.execute(), timeout=timeout)

            # Teardown
            await attack.teardown()

            result.duration_seconds = time.time() - start_time
            result.started_at = datetime.now(timezone.utc)
            result.completed_at = datetime.now(timezone.utc)

            logger.info(
                f"  [{index + 1}/{total}] {attack_name}: "
                f"success_rate={result.success_rate:.2%} ({result.duration_seconds:.1f}s)"
            )

            return result

        except asyncio.TimeoutError:
            logger.warning(f"  [{index + 1}/{total}] {attack_name}: TIMEOUT")
            return AttackResult(
                attack_name=attack_name,
                attack_type=attack_name,
                category=self._get_attack_category(attack_name),
                atlas_id=self._get_attack_atlas_id(attack_name),
                status=AttackStatus.TIMEOUT,
                duration_seconds=time.time() - start_time,
                error="Attack execution timed out",
            )
        except Exception as e:
            logger.error(f"  [{index + 1}/{total}] {attack_name}: ERROR — {e}")
            return AttackResult(
                attack_name=attack_name,
                attack_type=attack_name,
                category=self._get_attack_category(attack_name),
                atlas_id=self._get_attack_atlas_id(attack_name),
                status=AttackStatus.ERROR,
                duration_seconds=time.time() - start_time,
                error=str(e),
            )

    def _aggregate_results(
        self,
        campaign_id: str,
        campaign_name: str,
        results: list[AttackResult],
        duration: float,
        target_info: dict[str, str],
    ) -> CampaignResult:
        """Aggregate individual attack results into campaign summary."""
        completed = sum(1 for r in results if r.status in (AttackStatus.SUCCESS, AttackStatus.FAILURE))
        failed = sum(1 for r in results if r.status == AttackStatus.ERROR)
        skipped = sum(1 for r in results if r.status == AttackStatus.SKIPPED)

        # Mean success rate across completed attacks
        success_rates = [r.success_rate for r in results if r.status != AttackStatus.ERROR]
        overall_success_rate = sum(success_rates) / len(success_rates) if success_rates else 0.0

        # ATLAS mappings
        atlas_mappings = []
        for r in results:
            if r.atlas_id:
                from aetherguard_excalibur.models import AtlasMapping

                atlas_mappings.append(
                    AtlasMapping(
                        technique_id=r.atlas_id,
                        technique_name=r.attack_name,
                        tactic=r.category.value if r.category else "unknown",
                    )
                )

        return CampaignResult(
            campaign_id=campaign_id,
            campaign_name=campaign_name,
            status=CampaignStatus.COMPLETED,
            total_attacks=len(results),
            completed=completed,
            failed=failed,
            skipped=skipped,
            overall_success_rate=overall_success_rate,
            attack_results=results,
            atlas_mappings=atlas_mappings,
            duration_seconds=duration,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            target_info=target_info,
        )

    def _get_attack_category(self, name: str) -> Any:
        """Get attack category from registry (best-effort)."""
        from aetherguard_excalibur.models import AttackCategory

        try:
            attacks = self._registry.list_attacks()
            for a in attacks:
                if a.name == name:
                    return a.category
        except Exception:
            pass
        return AttackCategory.EVASION

    def _get_attack_atlas_id(self, name: str) -> str:
        """Get ATLAS ID from registry (best-effort)."""
        try:
            attacks = self._registry.list_attacks()
            for a in attacks:
                if a.name == name:
                    return a.atlas_id
        except Exception:
            pass
        return "AML.T0000"

    async def abort_campaign(self, campaign_id: str) -> None:
        """Abort a running campaign."""
        if campaign_id in self._campaigns:
            campaign = self._campaigns[campaign_id]
            campaign.status = CampaignStatus.ABORTED
            campaign.completed_at = datetime.now(timezone.utc)
            logger.info(f"Campaign '{campaign.name}' aborted")

    async def get_campaign_status(self, campaign_id: str) -> Campaign | None:
        """Get current campaign state."""
        return self._campaigns.get(campaign_id)
