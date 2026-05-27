#!/usr/bin/env python3
"""
gitleaks-ai: AI-assisted secrets scanner with entropy analysis,
redaction-by-default output, CI-safe exit behavior, and remediation reporting.

Usage:
    python main.py scan .
    python main.py scan . --output json --findings findings.json
    python main.py scan . --ai-review --report remediation.md
    python main.py scan src/ --min-entropy 4.0 --output markdown
    python main.py remediate findings.json --output remediation.md
"""

import json
import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.scanner import scan_directory
from src.ai_reviewer import review_findings_batch, generate_remediation_report


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("gitleaks-ai.log")],
)

logger = logging.getLogger(__name__)
console = Console()


DEFAULT_EXCLUDES = [
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
]


def validate_target(target: str) -> bool:
    if not os.path.exists(target):
        console.print(f"[red]✗ Target not found: {target}[/red]")
        logger.error("Target path does not exist: %s", target)
        return False

    if not os.access(target, os.R_OK):
        console.print(f"[red]✗ Permission denied: {target}[/red]")
        logger.error("No read permission for target: %s", target)
        return False

    return True


def validate_ai_review() -> bool:
    if not os.getenv("OPENAI_API_KEY"):
        console.print(
            "[red]✗ --ai-review requires OPENAI_API_KEY environment variable[/red]\n"
            "[dim]Set it with: export OPENAI_API_KEY='sk-...'[/dim]"
        )
        logger.error("AI review requested but OPENAI_API_KEY not set")
        return False
    return True


def finding_to_dict(finding: Any, redact: bool = True) -> Dict[str, Any]:
    if hasattr(finding, "to_dict"):
        data = finding.to_dict()
    elif isinstance(finding, dict):
        data = dict(finding)
    else:
        data = dict(vars(finding))

    if redact:
        for key in ("secret", "value", "match", "token", "credential"):
            if key in data and data[key]:
                data[key] = "[REDACTED]"

    return data


def finding_attr(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def is_false_positive(finding: Any) -> bool:
    return bool(finding_attr(finding, "is_false_positive", False))


def build_output_payload(
    *,
    target: str,
    scan_start: datetime,
    findings: Iterable[Any],
    display_findings: Iterable[Any],
    confirmed_count: int,
    fp_count: int,
    ai_review_enabled: bool,
    min_entropy: float,
    max_file_size: int,
    redact: bool,
    excludes: List[str],
) -> Dict[str, Any]:
    findings_list = list(findings)
    display_list = list(display_findings)

    return {
        "metadata": {
            "target": target,
            "timestamp": scan_start.isoformat(),
            "scan_duration_seconds": round((datetime.now() - scan_start).total_seconds(), 2),
            "total_findings": len(findings_list),
            "displayed_findings": len(display_list),
            "confirmed_secrets": confirmed_count,
            "false_positives": fp_count,
            "ai_review_enabled": ai_review_enabled,
            "min_entropy": min_entropy,
            "max_file_size_kb": max_file_size,
            "redacted": redact,
            "excludes": excludes,
        },
        "findings": [finding_to_dict(f, redact=redact) for f in display_list],
    }


@click.group()
@click.version_option("1.0.3", prog_name="gitleaks-ai")
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
@click.pass_context
def cli(ctx, verbose):
    """gitleaks-ai — AI-assisted secrets scanner with entropy analysis."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")

    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command()
@click.argument("target", default=".")
@click.option("--ai-review", is_flag=True, default=False, help="Use AI review. Requires OPENAI_API_KEY.")
@click.option("--trusted-ai-gate", is_flag=True, default=False, help="Allow AI false-positive verdicts to affect CI exit code.")
@click.option("--min-entropy", default=3.5, show_default=True, type=float, help="Minimum Shannon entropy.")
@click.option("--output", default="table", type=click.Choice(["table", "json", "markdown"], case_sensitive=False))
@click.option("--findings", default=None, type=click.Path(), help="Save machine-readable findings JSON.")
@click.option("--report", default=None, type=click.Path(), help="Save Markdown remediation report.")
@click.option("--no-fp", is_flag=True, default=False, help="Hide AI-marked false positives from display. Requires --ai-review.")
@click.option("--redact/--no-redact", default=True, show_default=True, help="Redact secret values in output.")
@click.option("--max-file-size", default=512, show_default=True, type=int, help="Maximum file size to scan in KB.")
@click.option("--batch-size", default=10, show_default=True, type=int, help="AI API batch size.")
@click.option("--rate-limit-delay", default=1.0, show_default=True, type=float, help="Delay between AI batches.")
@click.option("--exclude", multiple=True, help="Path fragment to exclude. Can be repeated.")
@click.pass_context
def scan(
    ctx,
    target,
    ai_review,
    trusted_ai_gate,
    min_entropy,
    output,
    findings,
    report,
    no_fp,
    redact,
    max_file_size,
    batch_size,
    rate_limit_delay,
    exclude,
):
    """Scan a directory or file for hardcoded secrets and credentials."""
    try:
        if not validate_target(target):
            sys.exit(1)

        if ai_review and not validate_ai_review():
            sys.exit(1)

        if no_fp and not ai_review:
            console.print("[yellow]⚠ --no-fp requires --ai-review. Ignoring --no-fp.[/yellow]")
            logger.warning("--no-fp ignored because --ai-review is disabled")
            no_fp = False

        excludes = list(exclude) if exclude else DEFAULT_EXCLUDES

        scan_start = datetime.now()
        logger.info("Starting scan of %s with entropy threshold %s", target, min_entropy)

        console.print(
            Panel(
                f"[bold cyan]gitleaks-ai[/bold cyan] scanning [bold]{target}[/bold]\n"
                f"Entropy: {min_entropy} | AI review: {'enabled' if ai_review else 'disabled'} | "
                f"Redaction: {'enabled' if redact else 'disabled'}",
                expand=False,
            )
        )

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
            task = progress.add_task("Scanning files...", total=None)

            try:
                try:
                    found = scan_directory(
                        target,
                        min_entropy=min_entropy,
                        max_file_size_kb=max_file_size,
                        excludes=excludes,
                    )
                except TypeError:
                    found = scan_directory(
                        target,
                        min_entropy=min_entropy,
                        max_file_size_kb=max_file_size,
                    )
            except Exception as e:
                console.print(f"[red]✗ Scan error: {e}[/red]")
                logger.exception("Scan error")
                sys.exit(1)

            progress.update(task, description=f"Found {len(found)} potential secrets.")

        findings_list = list(found)
        logger.info("Scan complete: %d potential secrets found", len(findings_list))

        if not findings_list:
            console.print("[bold green]✓ No secrets detected.[/bold green]")
            sys.exit(0)

        fp_count = 0

        if ai_review:
            try:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
                    task = progress.add_task(f"AI reviewing {len(findings_list)} findings...", total=None)
                    findings_list = review_findings_batch(
                        findings_list,
                        batch_size=batch_size,
                        rate_limit_delay=rate_limit_delay,
                        timeout=300,
                    )
                    fp_count = sum(1 for f in findings_list if is_false_positive(f))
                    progress.update(task, description=f"AI review complete. {fp_count} false positives identified.")

                console.print(f"[dim]AI review: {fp_count}/{len(findings_list)} marked false positive.[/dim]")
                logger.info("AI review complete: %d false positives", fp_count)

            except TimeoutError as e:
                console.print("[yellow]⚠ AI review timeout. Continuing with raw findings.[/yellow]")
                logger.warning("AI review timeout: %s", e)
                ai_review = False
                fp_count = 0
            except Exception as e:
                console.print(f"[yellow]⚠ AI review failed: {e}. Continuing with raw findings.[/yellow]")
                logger.exception("AI review failed")
                ai_review = False
                fp_count = 0

        display_findings = [
            f for f in findings_list if not (no_fp and ai_review and is_false_positive(f))
        ]

        if ai_review and trusted_ai_gate:
            confirmed_count = sum(1 for f in findings_list if not is_false_positive(f))
        else:
            confirmed_count = len(findings_list)

        payload = build_output_payload(
            target=target,
            scan_start=scan_start,
            findings=findings_list,
            display_findings=display_findings,
            confirmed_count=confirmed_count,
            fp_count=fp_count,
            ai_review_enabled=ai_review,
            min_entropy=min_entropy,
            max_file_size=max_file_size,
            redact=redact,
            excludes=excludes,
        )

        if findings:
            try:
                findings_path = Path(findings)
                findings_path.parent.mkdir(parents=True, exist_ok=True)
                findings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                console.print(f"[bold green]✓ Findings saved to {findings_path}[/bold green]")
            except IOError as e:
                console.print(f"[red]✗ Failed to write findings JSON: {e}[/red]")
                logger.error("Failed to write findings JSON: %s", e)

        if output == "json":
            print(json.dumps(payload, indent=2))
            sys.exit(1 if confirmed_count > 0 else 0)

        if output == "markdown":
            lines = [
                "# gitleaks-ai Scan Report\n\n",
                f"**Target:** `{target}`  \n",
                f"**Scan Time:** {scan_start.strftime('%Y-%m-%d %H:%M:%S')}  \n",
                f"**Scan Duration:** {payload['metadata']['scan_duration_seconds']}s  \n",
                f"**Total findings:** {len(findings_list)}  \n",
                f"**Confirmed secrets:** {confirmed_count}  \n",
                f"**False positives:** {fp_count}  \n",
                f"**AI Review:** {'Enabled' if ai_review else 'Disabled'}  \n",
                f"**Redacted:** {'Yes' if redact else 'No'}\n\n",
                "| # | File | Line | Type | Entropy | Risk | AI Verdict |\n",
                "|---|------|------|------|---------|------|------------|\n",
            ]

            for i, f in enumerate(display_findings, 1):
                verdict = finding_attr(f, "ai_verdict", "—") or "—"
                lines.append(
                    f"| {i} | `{finding_attr(f, 'file', 'unknown')}` | "
                    f"{finding_attr(f, 'line', '?')} | "
                    f"{finding_attr(f, 'secret_type', 'unknown')} | "
                    f"{float(finding_attr(f, 'entropy', 0.0)):.2f} | "
                    f"{float(finding_attr(f, 'risk_score', 0.0)):.2f} | "
                    f"{verdict} |\n"
                )

            console.print(Markdown("".join(lines)))
            sys.exit(1 if confirmed_count > 0 else 0)

        table = Table(
            title=f"Secrets Scan — {len(display_findings)} displayed / {len(findings_list)} total",
            show_header=True,
            header_style="bold red",
            show_lines=False,
        )
        table.add_column("#", width=4, style="dim")
        table.add_column("File", style="cyan", no_wrap=False)
        table.add_column("Ln", width=5)
        table.add_column("Type", style="yellow")
        table.add_column("Entropy", width=8)
        table.add_column("Risk", width=6)
        table.add_column("AI", width=14)

        for i, f in enumerate(display_findings[:100], 1):
            verdict_style = "green" if is_false_positive(f) else "red"
            verdict = finding_attr(f, "ai_verdict", "—") or "—"
            table.add_row(
                str(i),
                str(finding_attr(f, "file", "unknown")),
                str(finding_attr(f, "line", "?")),
                str(finding_attr(f, "secret_type", "unknown")),
                f"{float(finding_attr(f, 'entropy', 0.0)):.2f}",
                f"{float(finding_attr(f, 'risk_score', 0.0)):.2f}",
                f"[{verdict_style}]{verdict}[/{verdict_style}]",
            )

        console.print(table)

        if len(display_findings) > 100:
            console.print(f"[dim]... and {len(display_findings) - 100} more. Use --output json for full output.[/dim]")

        if report:
            try:
                report_path = Path(report)
                report_path.parent.mkdir(parents=True, exist_ok=True)

                try:
                    remediation = generate_remediation_report(findings_list)
                except Exception:
                    remediation = generate_remediation_report(payload["findings"])

                report_path.write_text(
                    "# gitleaks-ai Remediation Report\n\n"
                    f"**Target:** `{target}`  \n"
                    f"**Scan Time:** {scan_start.strftime('%Y-%m-%d %H:%M:%S')}  \n"
                    f"**Confirmed secrets:** {confirmed_count}  \n"
                    f"**False positives:** {fp_count}  \n"
                    f"**Redacted:** {'Yes' if redact else 'No'}  \n"
                    f"**Scan Duration:** {payload['metadata']['scan_duration_seconds']}s\n\n"
                    "---\n\n"
                    f"{remediation}",
                    encoding="utf-8",
                )

                console.print(f"[bold green]✓ Remediation report saved to {report_path}[/bold green]")
            except IOError as e:
                console.print(f"[red]✗ Failed to write remediation report: {e}[/red]")
                logger.error("Failed to write remediation report: %s", e)

        if confirmed_count > 0:
            logger.warning("Scan completed with %d CI-relevant findings", confirmed_count)
            sys.exit(1)

        logger.info("Scan completed successfully with no CI-relevant findings")
        sys.exit(0)

    except KeyboardInterrupt:
        console.print("[yellow]⚠ Scan interrupted by user[/yellow]")
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]✗ Scan failed: {e}[/red]")
        logger.exception("Unexpected scan failure")
        sys.exit(1)


@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--output", default="remediation.md", type=click.Path(), help="Output Markdown remediation report.")
def remediate(findings_file, output):
    """Generate remediation report from scan findings JSON."""
    try:
        logger.info("Loading findings from %s", findings_file)

        with open(findings_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
        findings_list = data.get("findings", []) if isinstance(data, dict) else data

        if not findings_list:
            console.print("[yellow]⚠ No findings in file.[/yellow]")
            sys.exit(0)

        console.print(
            Panel(
                f"[bold cyan]gitleaks-ai[/bold cyan] generating remediation report\n"
                f"Findings: {len(findings_list)} | Target: {metadata.get('target', 'unknown')}",
                expand=False,
            )
        )

        remediation = generate_remediation_report(findings_list)

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            "# gitleaks-ai Remediation Report\n\n"
            f"**Target:** `{metadata.get('target', 'unknown')}`  \n"
            f"**Scan Time:** {metadata.get('timestamp', 'unknown')}  \n"
            f"**Confirmed Secrets:** {metadata.get('confirmed_secrets', len(findings_list))}  \n"
            f"**Scan Duration:** {metadata.get('scan_duration_seconds', 'unknown')}s  \n\n"
            "---\n\n"
            f"{remediation}",
            encoding="utf-8",
        )

        console.print(f"[bold green]✓ Remediation report saved to {output_path}[/bold green]")

    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON: {e}[/red]")
        sys.exit(1)
    except IOError as e:
        console.print(f"[red]✗ File I/O error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Remediation generation failed: {e}[/red]")
        logger.exception("Unexpected remediation failure")
        sys.exit(1)


if __name__ == "__main__":
    cli(obj={})
