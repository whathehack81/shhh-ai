#!/usr/bin/env python3
"""
gitleaks-ai: AI-enhanced secrets scanner with entropy analysis and
LLM-powered false-positive elimination.

Usage:
    python main.py scan .
    python main.py scan /path/to/repo --ai-review --report report.md
    python main.py scan src/ --min-entropy 4.0 --output json
    python main.py remediate findings.json --output remediation.md
"""

import json
import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from time import sleep

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.scanner import scan_directory
from src.ai_reviewer import review_findings_batch, generate_remediation_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler("gitleaks-ai.log")]
)
logger = logging.getLogger(__name__)

console = Console()


def validate_target(target: str) -> bool:
    """Validate that target path exists and is readable."""
    if not os.path.exists(target):
        console.print(f"[red]✗ Target not found: {target}[/red]")
        logger.error(f"Target path does not exist: {target}")
        return False

    if not os.access(target, os.R_OK):
        console.print(f"[red]✗ Permission denied: {target}[/red]")
        logger.error(f"No read permission for target: {target}")
        return False

    return True


def validate_ai_review() -> bool:
    """Validate OPENAI_API_KEY is set for AI review."""
    if not os.getenv("OPENAI_API_KEY"):
        console.print(
            "[red]✗ --ai-review requires OPENAI_API_KEY environment variable[/red]\n"
            "[dim]Set it with: export OPENAI_API_KEY='sk-...'[/dim]"
        )
        logger.error("AI review requested but OPENAI_API_KEY not set")
        return False
    return True


@click.group()
@click.version_option("1.0.2", prog_name="gitleaks-ai")
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
@click.pass_context
def cli(ctx, verbose):
    """gitleaks-ai — AI-enhanced secrets scanner with entropy analysis."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@cli.command()
@click.argument("target", default=".")
@click.option("--ai-review", is_flag=True, default=False,
              help="Use AI to eliminate false positives (requires OPENAI_API_KEY).")
@click.option("--min-entropy", default=3.5, show_default=True, type=float,
              help="Minimum Shannon entropy for generic pattern matches.")
@click.option("--output", default="table",
              type=click.Choice(["table", "json", "markdown"], case_sensitive=False),
              help="Output format.")
@click.option("--report", default=None,
              help="Save a Markdown remediation report to this file.")
@click.option("--no-fp", is_flag=True, default=False,
              help="Exclude false positives from output (requires --ai-review).")
@click.option("--max-file-size", default=512, show_default=True, type=int,
              help="Maximum file size to scan in KB.")
@click.option("--batch-size", default=10, show_default=True, type=int,
              help="Batch size for AI API calls (to avoid rate limits).")
@click.option("--rate-limit-delay", default=1, show_default=True, type=float,
              help="Delay in seconds between API batches.")
@click.pass_context
def scan(ctx, target, ai_review, min_entropy, output, report, no_fp, max_file_size, batch_size, rate_limit_delay):
    """Scan a directory or file for hardcoded secrets and credentials.

    \b
    Examples:
        python main.py scan .
        python main.py scan /path/to/repo --ai-review --report report.md
        python main.py scan src/ --output json | jq '.findings[] | select(.risk_score > 0.8)'
        python main.py scan . --ai-review --no-fp --output json
    """
    try:
        # Validate target
        if not validate_target(target):
            sys.exit(1)

        # Validate AI review requirements
        if ai_review and not validate_ai_review():
            sys.exit(1)

        # Enforce --no-fp requires --ai-review
        if no_fp and not ai_review:
            console.print("[yellow]⚠️  --no-fp requires --ai-review. Ignoring --no-fp.[/yellow]")
            logger.warning("--no-fp flag ignored: --ai-review not enabled")
            no_fp = False

        scan_start = datetime.now()
        logger.info(f"Starting scan of {target} with entropy threshold {min_entropy}")

        console.print(Panel(
            f"[bold cyan]gitleaks-ai[/bold cyan] scanning [bold]{target}[/bold]\n"
            f"Entropy threshold: {min_entropy} | AI review: {'enabled' if ai_review else 'disabled'}",
            expand=False
        ))

        # Scan directory
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            task = progress.add_task("Scanning files...", total=None)
            try:
                findings = scan_directory(target, min_entropy=min_entropy, max_file_size_kb=max_file_size)
            except Exception as e:
                console.print(f"[red]✗ Scan error: {e}[/red]")
                logger.error(f"Scan error: {e}")
                sys.exit(1)
            progress.update(task, description=f"Found {len(findings)} potential secrets.")

        logger.info(f"Scan complete: {len(findings)} potential secrets found")

        if not findings:
            console.print("[bold green]✓ No secrets detected.[/bold green]")
            logger.info("No secrets detected in target")
            return

        # AI review with rate limiting and error handling
        fp_count = 0
        if ai_review:
            try:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              console=console, transient=True) as progress:
                    task = progress.add_task(f"AI reviewing {len(findings)} findings...", total=None)
                    findings = review_findings_batch(
                        findings,
                        batch_size=batch_size,
                        rate_limit_delay=rate_limit_delay,
                        timeout=300  # 5 minute timeout
                    )
                    fp_count = sum(1 for f in findings if f.is_false_positive)
                    progress.update(task, description=f"AI review complete. {fp_count} false positives identified.")

                logger.info(f"AI review complete: {fp_count} false positives identified")
                console.print(f"[dim]AI review: {fp_count}/{len(findings)} marked as false positives.[/dim]")

            except TimeoutError as e:
                console.print("[yellow]⚠️  AI review timeout. Displaying findings without AI verdicts.[/yellow]")
                logger.warning(f"AI review timeout: {e}")
                ai_review = False
            except Exception as e:
                console.print(f"[yellow]⚠️  AI review failed: {e}. Displaying findings without AI verdicts.[/yellow]")
                logger.error(f"AI review error: {e}")
                ai_review = False

        # Filter findings
        display_findings = [f for f in findings if not (no_fp and f.is_false_positive)] if ai_review else findings
        confirmed_count = sum(1 for f in findings if not f.is_false_positive) if ai_review else len(findings)

        logger.info(f"Displaying {len(display_findings)} findings (confirmed: {confirmed_count})")

        # Output formats
        if output == "json":
            output_data = {
                "metadata": {
                    "target": target,
                    "timestamp": scan_start.isoformat(),
                    "scan_duration_seconds": round((datetime.now() - scan_start).total_seconds(), 2),
                    "total_findings": len(findings),
                    "displayed_findings": len(display_findings),
                    "confirmed_secrets": confirmed_count,
                    "false_positives": fp_count,
                    "ai_review_enabled": ai_review,
                    "min_entropy": min_entropy,
                    "max_file_size_kb": max_file_size
                },
                "findings": [f.to_dict() for f in display_findings]
            }
            output_json = json.dumps(output_data, indent=2)
            print(output_json)
            logger.info(f"JSON output generated: {len(display_findings)} findings")

            if report:
                try:
                    report_path = Path(report).with_suffix('.json')
                    with open(report_path, 'w') as f:
                        f.write(output_json)
                    console.print(f"[bold green]✓ JSON findings saved to {report_path}[/bold green]")
                    logger.info(f"Findings exported to {report_path}")
                except IOError as e:
                    console.print(f"[red]✗ Failed to write JSON report: {e}[/red]")
                    logger.error(f"Failed to write JSON report: {e}")
            
            # Exit with proper code
            sys.exit(1 if confirmed_count > 0 else 0)

        if output == "markdown":
            lines = [
                "# gitleaks-ai Scan Report\n\n",
                f"**Target:** `{target}`  \n",
                f"**Scan Time:** {scan_start.strftime('%Y-%m-%d %H:%M:%S')}  \n",
                f"**Scan Duration:** {round((datetime.now() - scan_start).total_seconds(), 2)}s  \n",
                f"**Total findings:** {len(findings)}  \n",
                f"**Confirmed secrets:** {confirmed_count}  \n",
                f"**False positives:** {fp_count}  \n",
                f"**AI Review:** {'Enabled' if ai_review else 'Disabled'}\n\n",
                "| # | File | Line | Type | Entropy | Risk | AI Verdict |\n",
                "|---|------|------|------|---------|------|------------|\n"
            ]
            for i, f in enumerate(display_findings, 1):
                verdict = f.ai_verdict or "—"
                lines.append(f"| {i} | `{f.file}` | {f.line} | {f.secret_type} | "
                             f"{f.entropy:.2f} | {f.risk_score:.2f} | {verdict} |\n")
            console.print(Markdown("".join(lines)))
            logger.info(f"Markdown output generated: {len(display_findings)} findings")
            
            # Exit with proper code
            sys.exit(1 if confirmed_count > 0 else 0)

        # Table output (default)
        table = Table(
            title=f"Secrets Scan — {len(display_findings)} findings ({confirmed_count} confirmed)",
            show_header=True, header_style="bold red", show_lines=False
        )
        table.add_column("#", width=4, style="dim")
        table.add_column("File", style="cyan", no_wrap=False)
        table.add_column("Ln", width=5)
        table.add_column("Type", style="yellow")
        table.add_column("Entropy", width=8)
        table.add_column("Risk", width=6)
        table.add_column("AI", width=12)

        for i, f in enumerate(display_findings[:100], 1):
            verdict_style = "green" if f.is_false_positive else "red"
            verdict_text = f"[{verdict_style}]{f.ai_verdict or '—'}[/{verdict_style}]"
            table.add_row(
                str(i), f.file, str(f.line), f.secret_type,
                f"{f.entropy:.2f}", f"{f.risk_score:.2f}", verdict_text
            )

        console.print(table)

        if len(display_findings) > 100:
            console.print(f"[dim]... and {len(display_findings) - 100} more. Use --output json for full results.[/dim]")

        # Remediation report
        if report:
            try:
                with Progress(SpinnerColumn(), TextColumn("Generating remediation report..."),
                              console=console, transient=True) as progress:
                    progress.add_task("", total=None)
                    remediation = generate_remediation_report(findings)

                with open(report, "w") as f:
                    f.write(f"# gitleaks-ai Remediation Report\n\n")
                    f.write(f"**Target:** `{target}`  \n")
                    f.write(f"**Scan Time:** {scan_start.strftime('%Y-%m-%d %H:%M:%S')}  \n")
                    f.write(f"**Confirmed secrets:** {confirmed_count}  \n")
                    f.write(f"**Scan Duration:** {round((datetime.now() - scan_start).total_seconds(), 2)}s\n\n")
                    f.write("---\n\n")
                    f.write(remediation)
                console.print(f"[bold green]✓ Remediation report saved to {report}[/bold green]")
                logger.info(f"Remediation report saved to {report}")
            except IOError as e:
                console.print(f"[red]✗ Failed to write remediation report: {e}[/red]")
                logger.error(f"Failed to write remediation report: {e}")

        # Exit code for CI/CD
        if confirmed_count > 0:
            logger.warning(f"Scan completed with {confirmed_count} confirmed secrets found")
            sys.exit(1)
        else:
            logger.info("Scan completed successfully with no confirmed secrets")
            sys.exit(0)

    except KeyboardInterrupt:
        console.print("[yellow]⚠️  Scan interrupted by user[/yellow]")
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]✗ Scan failed: {e}[/red]")
        logger.exception(f"Unexpected error during scan: {e}")
        sys.exit(1)


@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--output", default="remediation.md", type=click.Path(),
              help="Output file path for remediation report.")
def remediate(findings_file, output):
    """Generate remediation report from scan findings JSON file.

    \b
    Examples:
        python main.py remediate findings.json --output report.md
        python main.py remediate scan_results.json --output fixes/remediation.md
    """
    try:
        logger.info(f"Loading findings from {findings_file}")

        with open(findings_file, 'r') as f:
            data = json.load(f)

        # Extract metadata if present
        metadata = data.get("metadata", {})
        findings_list = data.get("findings", data if isinstance(data, list) else [])

        if not findings_list:
            console.print("[yellow]⚠️  No findings in file.[/yellow]")
            logger.warning("No findings found in JSON file")
            sys.exit(0)

        console.print(Panel(
            f"[bold cyan]gitleaks-ai[/bold cyan] generating remediation report\n"
            f"Findings: {len(findings_list)} | Target: {metadata.get('target', 'unknown')}",
            expand=False
        ))

        with Progress(SpinnerColumn(), TextColumn("Generating remediation report..."),
                      console=console, transient=True) as progress:
            progress.add_task("", total=None)
            remediation = generate_remediation_report(findings_list)

        with open(output, "w") as f:
            f.write(f"# gitleaks-ai Remediation Report\n\n")
            if metadata:
                f.write(f"**Target:** `{metadata.get('target', 'unknown')}`  \n")
                f.write(f"**Scan Time:** {metadata.get('timestamp', 'unknown')}  \n")
                f.write(f"**Confirmed Secrets:** {metadata.get('confirmed_secrets', len(findings_list))}  \n")
                f.write(f"**Scan Duration:** {metadata.get('scan_duration_seconds', 'unknown')}s  \n\n")
            f.write("---\n\n")
            f.write(remediation)

        console.print(f"[bold green]✓ Remediation report saved to {output}[/bold green]")
        logger.info(f"Remediation report generated: {output}")

    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON in findings file: {e}[/red]")
        logger.error(f"Failed to parse JSON: {e}")
        sys.exit(1)
    except IOError as e:
        console.print(f"[red]✗ File I/O error: {e}[/red]")
        logger.error(f"File I/O error: {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Remediation generation failed: {e}[/red]")
        logger.exception(f"Unexpected error during remediation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli(obj={})
