"""Report generation and retrieval routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

router = APIRouter()


@router.get("/{campaign_id}")
async def get_report(request: Request, campaign_id: str, format: str = "json"):
    """Download generated report for a campaign.

    Args:
        campaign_id: Campaign identifier.
        format: Report format (json, html, pdf, sarif).
    """
    # Look for report files in results directory
    format_map = {
        "json": "results.json",
        "html": "report.html",
        "pdf": "report.pdf",
        "sarif": "results.sarif",
    }

    filename = format_map.get(format)
    if not filename:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format}. Use: json, html, pdf, sarif")

    report_path = Path("results") / campaign_id / filename
    if not report_path.exists():
        # Try without campaign_id subdirectory
        report_path = Path("results") / filename

    if not report_path.exists():
        raise HTTPException(status_code=404, detail=f"Report not found: {report_path}")

    media_types = {
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
        "sarif": "application/json",
    }

    return FileResponse(
        path=str(report_path),
        media_type=media_types.get(format, "application/octet-stream"),
        filename=filename,
    )


@router.get("/{campaign_id}/formats")
async def list_available_formats(campaign_id: str):
    """List available report formats for a campaign."""
    results_dir = Path("results") / campaign_id
    if not results_dir.exists():
        results_dir = Path("results")

    available = []
    format_files = {
        "json": "results.json",
        "html": "report.html",
        "pdf": "report.pdf",
        "sarif": "results.sarif",
    }

    for fmt, filename in format_files.items():
        if (results_dir / filename).exists():
            available.append(fmt)

    return {"campaign_id": campaign_id, "available_formats": available}
