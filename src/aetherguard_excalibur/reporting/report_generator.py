"""Report generation engine — HTML, PDF, JSON outputs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from aetherguard_excalibur.config import ReportConfig
from aetherguard_excalibur.models import CampaignResult
from aetherguard_excalibur.reporting.art_formatter import ARTFormatter
from aetherguard_excalibur.reporting.atlas_mapper import AtlasMapper
from aetherguard_excalibur.reporting.resilience_score import ResilienceScorer
from aetherguard_excalibur.reporting.sarif_exporter import SARIFExporter

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates campaign reports in multiple formats."""

    def __init__(self, config: ReportConfig | None = None) -> None:
        self._config = config or ReportConfig()
        self._resilience_scorer = ResilienceScorer()
        self._atlas_mapper = AtlasMapper()
        self._art_formatter = ARTFormatter()
        self._sarif_exporter = SARIFExporter()

    async def generate(
        self,
        campaign_result: CampaignResult,
        output_dir: Path | None = None,
    ) -> dict[str, Path]:
        """Generate all configured report formats.

        Args:
            campaign_result: Completed campaign results.
            output_dir: Override output directory.

        Returns:
            Dictionary of format -> output file path.
        """
        out_dir = output_dir or Path(self._config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Compute scores if not already present
        if self._config.resilience_score and not campaign_result.resilience_score:
            campaign_result.resilience_score = self._resilience_scorer.compute(
                campaign_result.attack_results
            )

        if self._config.art_metrics and not campaign_result.art_metrics:
            campaign_result.art_metrics = self._art_formatter.compute(
                campaign_result.attack_results
            )

        if self._config.atlas_mapping and not campaign_result.atlas_mappings:
            campaign_result.atlas_mappings = self._atlas_mapper.map_all(
                campaign_result.attack_results
            )

        # Generate each format
        generated: dict[str, Path] = {}
        for fmt in self._config.formats:
            try:
                if fmt == "json":
                    path = await self._generate_json(campaign_result, out_dir)
                elif fmt == "html":
                    path = await self._generate_html(campaign_result, out_dir)
                elif fmt == "pdf":
                    path = await self._generate_pdf(campaign_result, out_dir)
                elif fmt == "sarif":
                    path = self._sarif_exporter.export_to_file(
                        campaign_result, out_dir / "results.sarif"
                    )
                else:
                    logger.warning(f"Unknown report format: {fmt}")
                    continue
                generated[fmt] = path
                logger.info(f"Generated {fmt} report: {path}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {e}")

        return generated

    async def _generate_json(self, result: CampaignResult, out_dir: Path) -> Path:
        """Generate JSON report."""
        path = out_dir / "results.json"
        with open(path, "w") as f:
            json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
        return path

    async def _generate_html(self, result: CampaignResult, out_dir: Path) -> Path:
        """Generate HTML report with embedded charts."""
        path = out_dir / "report.html"

        # Build category data for chart
        category_data = {}
        if result.resilience_score:
            category_data = result.resilience_score.categories

        attack_rows = ""
        for r in result.attack_results:
            status_color = (
                "#e74c3c" if r.success_rate > 0.5
                else "#f39c12" if r.success_rate > 0.1
                else "#27ae60"
            )
            attack_rows += f"""
            <tr>
                <td>{r.attack_name}</td>
                <td>{r.category.value if r.category else 'N/A'}</td>
                <td>{r.atlas_id}</td>
                <td style="color: {status_color}; font-weight: bold;">{r.success_rate:.0%}</td>
                <td>{r.payloads_successful}/{r.payloads_used}</td>
                <td>{r.duration_seconds:.1f}s</td>
            </tr>"""

        score = result.resilience_score
        score_color = (
            "#27ae60" if score and score.overall >= 80
            else "#f39c12" if score and score.overall >= 60
            else "#e74c3c"
        ) if score else "#666"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Excalibur Report — {result.campaign_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
        .header {{ background: linear-gradient(135deg, #1a1f36, #2d1b69); padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; color: #fff; font-size: 24px; }}
        .header p {{ color: #8b949e; margin: 5px 0 0; }}
        .score-card {{ display: inline-block; background: #161b22; border: 2px solid {score_color}; border-radius: 12px; padding: 20px 30px; text-align: center; }}
        .score-value {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
        .score-grade {{ font-size: 24px; color: {score_color}; }}
        .stats {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px 20px; flex: 1; min-width: 150px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ color: #8b949e; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
        th {{ background: #21262d; padding: 12px; text-align: left; color: #8b949e; font-size: 12px; text-transform: uppercase; }}
        td {{ padding: 12px; border-top: 1px solid #21262d; }}
        .section {{ margin: 25px 0; }}
        .section h2 {{ color: #f0f6fc; font-size: 18px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AetherGuard Excalibur — Attack Campaign Report</h1>
        <p>{result.campaign_name} | {result.total_attacks} attacks | {result.duration_seconds:.1f}s</p>
    </div>

    <div style="text-align: center; margin: 20px 0;">
        <div class="score-card">
            <div class="score-value">{score.overall if score else 'N/A'}</div>
            <div class="score-grade">Grade: {score.grade if score else 'N/A'}</div>
            <div style="color: #8b949e; font-size: 12px; margin-top: 5px;">AetherGuard Resilience Score</div>
        </div>
    </div>

    <div class="stats">
        <div class="stat"><div class="stat-value">{result.total_attacks}</div><div class="stat-label">Total Attacks</div></div>
        <div class="stat"><div class="stat-value">{result.completed}</div><div class="stat-label">Completed</div></div>
        <div class="stat"><div class="stat-value">{result.overall_success_rate:.0%}</div><div class="stat-label">Attack Success Rate</div></div>
        <div class="stat"><div class="stat-value">{result.duration_seconds:.1f}s</div><div class="stat-label">Duration</div></div>
    </div>

    <div class="section">
        <h2>Attack Results</h2>
        <table>
            <thead><tr><th>Attack</th><th>Category</th><th>ATLAS ID</th><th>Success Rate</th><th>Payloads</th><th>Duration</th></tr></thead>
            <tbody>{attack_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <h2>Target Information</h2>
        <p>Type: {result.target_info.get('type', 'N/A')} | Model: {result.target_info.get('model', 'N/A')}</p>
    </div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
        return path

    async def _generate_pdf(self, result: CampaignResult, out_dir: Path) -> Path:
        """Generate PDF report (requires weasyprint)."""
        try:
            from weasyprint import HTML as WeasyHTML
        except ImportError:
            raise ImportError(
                "weasyprint is required for PDF reports. Install with: "
                "pip install 'aetherguard-excalibur[reporting]'"
            )

        # Generate HTML first, then convert to PDF
        html_path = await self._generate_html(result, out_dir)
        pdf_path = out_dir / "report.pdf"

        WeasyHTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path
