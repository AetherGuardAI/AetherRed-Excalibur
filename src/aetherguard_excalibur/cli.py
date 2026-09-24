"""CLI entry point for AetherGuard-Excalibur (excalibur command)."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from aetherguard_excalibur.config import ExcaliburConfig, load_campaign, load_config
from aetherguard_excalibur.engine import CampaignEngine
from aetherguard_excalibur.models import ProgressEvent
from aetherguard_excalibur.registry import AttackRegistry
from aetherguard_excalibur.reporting import ReportGenerator

console = Console()


def _setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _progress_callback(event: ProgressEvent) -> None:
    """Display progress events in terminal."""
    if event.event_type == "attack_started":
        console.print(f"  [cyan]▶[/cyan] {event.message}")
    elif event.event_type == "attack_completed":
        console.print(f"  [green]✓[/green] {event.message}")
    elif event.event_type == "campaign_completed":
        console.print(f"\n[bold green]✓ {event.message}[/bold green]")


@click.group()
@click.version_option(version="1.0.0", prog_name="excalibur")
def main() -> None:
    """AetherGuard-Excalibur — AI Red-Teaming & Attack Simulation Platform.

    Run adversarial attacks against LLMs, agents, and RAG systems to surface
    vulnerabilities before real attackers do.
    """
    pass


@main.command()
@click.argument("attack_type")
@click.option("--target", "-t", required=True, help="Target type (openai, anthropic, local, etc.)")
@click.option("--model", "-m", default=None, help="Model name/ID")
@click.option("--api-key-env", default=None, help="Env var containing API key")
@click.option("--samples", "-n", default=100, help="Number of samples to test")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file for results")
@click.option("--dry-run", is_flag=True, help="Validate config without executing")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--param", "-p", multiple=True, help="Attack params as key=value pairs")
@click.option("--judge", default=None, help="Judge LLM provider (openai, anthropic) for result evaluation")
@click.option("--judge-model", default="gpt-4o", help="Judge model ID (default: gpt-4o)")
@click.option("--judge-key-env", default="EXCALIBUR_JUDGE_API_KEY", help="Env var for judge API key")
def run(
    attack_type: str,
    target: str,
    model: str | None,
    api_key_env: str | None,
    samples: int,
    output: str | None,
    dry_run: bool,
    verbose: bool,
    param: tuple[str, ...],
    judge: str | None,
    judge_model: str,
    judge_key_env: str,
) -> None:
    """Run a single attack against a target.

    Examples:

        excalibur run textfooler -t openai -m gpt-4o-mini

        excalibur run pgd -t local --model ./model.pt -p epsilon=0.03 -p iterations=40

        excalibur run hallucination_induction -t anthropic -n 50
    """
    _setup_logging(verbose)

    # Parse attack params
    params = {"samples": samples}
    for p in param:
        key, _, value = p.partition("=")
        # Try to parse numeric values
        try:
            params[key] = float(value) if "." in value else int(value)
        except ValueError:
            # Comma-separated values become lists
            if "," in value:
                params[key] = [v.strip() for v in value.split(",")]
            elif value.lower() in ("true", "false"):
                params[key] = value.lower() == "true"
            else:
                params[key] = value

    if dry_run:
        console.print(f"[yellow]DRY RUN[/yellow] — would execute {attack_type} against {target}")
        console.print(f"  Params: {params}")
        return

    console.print(f"\n[bold]⚔️  Excalibur — Running {attack_type}[/bold]")
    console.print(f"  Target: {target} | Model: {model or 'default'} | Samples: {samples}")
    if judge:
        console.print(f"  Judge: {judge}/{judge_model} (eval enabled)")
    console.print()

    asyncio.run(_run_single_attack(attack_type, target, model, api_key_env, params, output, judge, judge_model, judge_key_env))


async def _run_single_attack(
    attack_type: str,
    target_type: str,
    model: str | None,
    api_key_env: str | None,
    params: dict,
    output: str | None,
    judge_provider: str | None = None,
    judge_model: str = "gpt-4o",
    judge_key_env: str = "EXCALIBUR_JUDGE_API_KEY",
) -> None:
    """Execute a single attack, optionally with LLM judge evaluation."""
    from aetherguard_excalibur.adapters.factory import AdapterFactory
    from aetherguard_excalibur.config import TargetConfig

    registry = AttackRegistry()
    registry.discover_attacks()

    attack = registry.get_attack(attack_type)

    target_config = TargetConfig(
        type=target_type,
        model=model or "gpt-4o-mini",
        api_key_env=api_key_env,
    )
    factory = AdapterFactory()
    adapter = factory.create_target(target_config)

    # Initialize judge if requested
    judge_instance = None
    if judge_provider:
        from aetherguard_excalibur.judge import JudgeConfig, LLMJudge

        judge_config = JudgeConfig(
            enabled=True,
            provider=judge_provider,
            model=judge_model,
            api_key_env=judge_key_env,
        )
        judge_instance = LLMJudge(judge_config)
        # Inject judge into attack if it supports it
        attack._judge = judge_instance

    try:
        validated_params = attack.validate_params(params)
        await attack.setup(adapter, validated_params)
        result = await attack.execute()
        await attack.teardown()

        # Display results
        color = "red" if result.success_rate > 0.5 else "yellow" if result.success_rate > 0.1 else "green"
        console.print(f"\n[bold {color}]Result: {result.success_rate:.0%} attack success rate[/bold {color}]")
        console.print(f"  Payloads: {result.payloads_successful}/{result.payloads_used} succeeded")
        console.print(f"  ATLAS: {result.atlas_id}")
        console.print(f"  Duration: {result.duration_seconds:.1f}s")
        if judge_instance:
            console.print(f"  Judge calls: {judge_instance.call_count}")

        if output:
            import json

            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
            console.print(f"\n  Results saved to: {output}")

    finally:
        await adapter.close()
        if judge_instance:
            await judge_instance.close()


@main.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--output-dir", "-o", type=click.Path(), default="results", help="Output directory")
@click.option("--parallel", default=None, type=int, help="Override max parallel attacks")
@click.option("--dry-run", is_flag=True, help="Validate config without executing")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--judge", default=None, help="Judge LLM provider (openai, anthropic)")
@click.option("--judge-model", default="gpt-4o", help="Judge model ID")
@click.option("--judge-key-env", default="EXCALIBUR_JUDGE_API_KEY", help="Env var for judge API key")
def campaign(
    config_file: str,
    output_dir: str,
    parallel: int | None,
    dry_run: bool,
    verbose: bool,
    judge: str | None,
    judge_model: str,
    judge_key_env: str,
) -> None:
    """Execute a full attack campaign from YAML config.

    Examples:

        excalibur campaign campaigns/quick_scan.yaml

        excalibur campaign campaigns/full_audit.yaml --parallel 5 -o results/

        excalibur campaign campaigns/quick_scan.yaml --judge openai --judge-model gpt-4o
    """
    _setup_logging(verbose)

    campaign_config = load_campaign(Path(config_file))

    # Apply judge config from CLI flags or campaign YAML
    if judge:
        from aetherguard_excalibur.config import JudgeLLMConfig
        campaign_config.judge = JudgeLLMConfig(
            enabled=True, provider=judge, model=judge_model, api_key_env=judge_key_env
        )

    if parallel:
        campaign_config.parallel = parallel

    if dry_run:
        console.print(f"[yellow]DRY RUN[/yellow] — campaign: {campaign_config.name}")
        console.print(f"  Target: {campaign_config.target.type}/{campaign_config.target.model}")
        console.print(f"  Attacks: {len(campaign_config.attacks)} configured")
        for a in campaign_config.attacks:
            status = "✓" if a.enabled else "✗"
            console.print(f"    [{status}] {a.type}")
        return

    console.print(f"\n[bold]⚔️  Excalibur — Campaign: {campaign_config.name}[/bold]")
    console.print(f"  Target: {campaign_config.target.type}/{campaign_config.target.model}")
    console.print(f"  Attacks: {len([a for a in campaign_config.attacks if a.enabled])} enabled")
    console.print(f"  Parallel: {campaign_config.parallel}\n")

    asyncio.run(_run_campaign(campaign_config, Path(output_dir)))


async def _run_campaign(campaign_config, output_dir: Path) -> None:
    """Execute campaign and generate reports."""
    system_config = load_config()
    registry = AttackRegistry()
    registry.discover_attacks()

    engine = CampaignEngine(system_config, registry)
    campaign_obj = await engine.create_campaign(campaign_config)

    result = await engine.execute_campaign(campaign_obj, on_progress=_progress_callback)

    # Generate reports
    report_gen = ReportGenerator(campaign_config.reporting)
    generated = await report_gen.generate(result, output_dir)

    console.print(f"\n[bold]📊 Reports generated:[/bold]")
    for fmt, path in generated.items():
        console.print(f"  {fmt}: {path}")

    # Summary
    score = result.resilience_score
    if score:
        color = "green" if score.overall >= 80 else "yellow" if score.overall >= 60 else "red"
        console.print(f"\n[bold {color}]Resilience Score: {score.overall}/100 (Grade: {score.grade})[/bold {color}]")


@main.command()
@click.argument("target")
@click.option("--intensity", "-i", type=click.Choice(["low", "medium", "high", "extreme"]), default="medium")
@click.option("--output", "-o", type=click.Path(), default="results/benchmark", help="Output directory")
@click.option("--compare", type=click.Path(exists=True), default=None, help="Previous results to compare against")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def benchmark(target: str, intensity: str, output: str, compare: str | None, verbose: bool) -> None:
    """Run evasion simulation benchmark suite.

    Examples:

        excalibur benchmark openai --intensity medium

        excalibur benchmark local --intensity high --compare results/previous/
    """
    _setup_logging(verbose)
    console.print(f"\n[bold]⚔️  Excalibur — Evasion Benchmark Suite[/bold]")
    console.print(f"  Target: {target} | Intensity: {intensity}")
    console.print("  [yellow]Benchmark suite will be available after Unit 7 implementation[/yellow]")


@main.command("list")
@click.option("--category", "-c", default=None, help="Filter by category")
@click.option("--verbose", "-v", is_flag=True, help="Show parameter schemas")
def list_attacks(category: str | None, verbose: bool) -> None:
    """List available attack types.

    Examples:

        excalibur list

        excalibur list --category nlp_language
    """
    registry = AttackRegistry()
    registry.discover_attacks()

    attacks = registry.list_attacks(category)

    if not attacks:
        console.print("[yellow]No attacks found.[/yellow]")
        if category:
            console.print(f"  Available categories: {', '.join(registry.categories)}")
        return

    table = Table(title="Available Attacks", show_lines=True)
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("ATLAS ID", style="blue")
    table.add_column("Interface", style="green")
    table.add_column("Description")

    for a in attacks:
        table.add_row(
            a.name,
            a.category.value,
            a.atlas_id,
            a.interface,
            a.description[:60] + "..." if len(a.description) > 60 else a.description,
        )

    console.print(table)
    console.print(f"\nTotal: {len(attacks)} attacks")


@main.command()
@click.argument("results_dir", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", multiple=True, default=["html"], help="Report formats")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output directory")
def report(results_dir: str, fmt: tuple[str, ...], output: str | None) -> None:
    """Generate reports from saved campaign results.

    Examples:

        excalibur report results/ --format html --format pdf

        excalibur report results/ -f sarif -o ci-reports/
    """
    console.print(f"\n[bold]📊 Generating reports from: {results_dir}[/bold]")
    console.print(f"  Formats: {', '.join(fmt)}")
    console.print("  [yellow]Report regeneration from saved results coming soon[/yellow]")


@main.command()
@click.argument("config_file", type=click.Path(exists=True))
def validate(config_file: str) -> None:
    """Validate campaign configuration without executing.

    Examples:

        excalibur validate campaigns/quick_scan.yaml
    """
    try:
        config = load_campaign(Path(config_file))
        console.print(f"[green]✓ Valid campaign config:[/green] {config.name}")
        console.print(f"  Target: {config.target.type}/{config.target.model}")
        console.print(f"  Attacks: {len(config.attacks)}")
        for a in config.attacks:
            console.print(f"    {'✓' if a.enabled else '✗'} {a.type}")
    except Exception as e:
        console.print(f"[red]✗ Invalid config:[/red] {e}")
        sys.exit(1)


@main.command()
@click.option("--host", default="0.0.0.0", help="API server host")
@click.option("--port", default=8100, type=int, help="API server port")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the Excalibur REST API server.

    Examples:

        excalibur serve --port 8100

        excalibur serve --reload  (development mode)
    """
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn required. Install with: pip install 'aetherguard-excalibur[api]'[/red]")
        sys.exit(1)

    console.print(f"\n[bold]🚀 Starting Excalibur API server[/bold]")
    console.print(f"  http://{host}:{port}")
    console.print(f"  Docs: http://{host}:{port}/docs\n")

    uvicorn.run(
        "aetherguard_excalibur.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    main()
