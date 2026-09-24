"""SARIF (Static Analysis Results Interchange Format) exporter for CI/CD integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aetherguard_excalibur.models import AttackResult, AttackStatus, CampaignResult


class SARIFExporter:
    """Exports campaign results in SARIF v2.1.0 format.

    SARIF is the standard format for static/dynamic analysis tools,
    supported by GitHub Code Scanning, Azure DevOps, and other CI/CD platforms.
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    def export(self, campaign_result: CampaignResult) -> dict[str, Any]:
        """Convert campaign results to SARIF format.

        Args:
            campaign_result: Completed campaign result.

        Returns:
            SARIF document as dictionary.
        """
        rules = self._build_rules(campaign_result.attack_results)
        results = self._build_results(campaign_result.attack_results)

        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AetherGuard-Excalibur",
                            "version": "1.0.0",
                            "informationUri": "https://aetherguard.ai/excalibur",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": campaign_result.status.value == "completed",
                            "properties": {
                                "campaignId": campaign_result.campaign_id,
                                "campaignName": campaign_result.campaign_name,
                                "durationSeconds": campaign_result.duration_seconds,
                                "totalAttacks": campaign_result.total_attacks,
                                "resilienceScore": (
                                    campaign_result.resilience_score.overall
                                    if campaign_result.resilience_score
                                    else None
                                ),
                            },
                        }
                    ],
                }
            ],
        }

        return sarif

    def export_to_file(self, campaign_result: CampaignResult, output_path: Path) -> Path:
        """Export SARIF to file.

        Args:
            campaign_result: Campaign results.
            output_path: Output file path.

        Returns:
            Path to written file.
        """
        sarif = self.export(campaign_result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)
        return output_path

    def _build_rules(self, results: list[AttackResult]) -> list[dict[str, Any]]:
        """Build SARIF rules from attack types."""
        seen_rules: dict[str, dict[str, Any]] = {}
        for r in results:
            if r.attack_name not in seen_rules:
                seen_rules[r.attack_name] = {
                    "id": f"excalibur/{r.attack_name}",
                    "name": r.attack_name,
                    "shortDescription": {"text": f"{r.attack_name} attack simulation"},
                    "fullDescription": {"text": f"MITRE ATLAS: {r.atlas_id}"},
                    "helpUri": f"https://atlas.mitre.org/techniques/{r.atlas_id}",
                    "properties": {
                        "category": r.category.value if r.category else "unknown",
                        "atlasId": r.atlas_id,
                    },
                }
        return list(seen_rules.values())

    def _build_results(self, results: list[AttackResult]) -> list[dict[str, Any]]:
        """Build SARIF results from attack results."""
        sarif_results = []
        for r in results:
            if r.status == AttackStatus.ERROR:
                continue

            # Map success rate to SARIF severity
            if r.success_rate >= 0.7:
                level = "error"
            elif r.success_rate >= 0.3:
                level = "warning"
            elif r.success_rate > 0:
                level = "note"
            else:
                level = "none"

            sarif_result: dict[str, Any] = {
                "ruleId": f"excalibur/{r.attack_name}",
                "level": level,
                "message": {
                    "text": (
                        f"{r.attack_name}: {r.payloads_successful}/{r.payloads_used} "
                        f"payloads succeeded ({r.success_rate:.0%} success rate)"
                    )
                },
                "properties": {
                    "successRate": r.success_rate,
                    "confidence": r.confidence,
                    "durationSeconds": r.duration_seconds,
                    "atlasId": r.atlas_id,
                    "category": r.category.value if r.category else "unknown",
                    "metrics": r.metrics,
                },
            }
            sarif_results.append(sarif_result)

        return sarif_results
