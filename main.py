#!/usr/bin/env python3
"""
gitleaks-ai: AI-enhanced secrets scanner with entropy analysis and
LLM-powered false-positive elimination.

Usage:
    python main.py scan .
    python main.py scan /path/to/repo --ai-review --report report.md
    python main.py scan src/ --min-entropy 4.0 --output json
"""

import json
import sys
import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.scanner import scan_directory
from src.ai_reviewer import review_findings_batch, generate_remediation_report

console = Console()


@click.group()
@click.version_option("1.0.0", prog_name="gitleaks-ai")
def cli():
    """gitleaks-ai — AI-enhanced secrets scanner with entropy analysis."""
    pass


@cli.command()
@click.argument("target", default=".")
@click.option("--ai-review", is_flag=True, default=False,
              help="Use AI to eliminate false positives (requires OPENAI_API_KEY).")
@click.option("--min-entropy", default=3.5, show_default=True,
              help="Minimum Shannon entropy for generic pattern matches.")
@click.option("--output", default="table",
              type=click.Choice(["table", "json", "markdown"], case_sensitive=False),
              help="Output format.")
@click.option("--report", default=None,
              help="Save a Markdown remediation report to this file.")
@click.option("--no-fp", is_flag=True, default=False,
              help="Exclude false positives from output (requires --ai-review).")
@click.option("--max-file-size", default=512, show_default=True,
              help="Maximum file size to scan in KB.")
def scan(target, ai_review, min_entropy, output, report, no_fp, max_file_size):
    """Scan a directory or file for hardcoded secrets and credentials.

    \b
    Examples:
        python main.py scan .
        python main.py scan /path/to/repo --ai-review --report report.md
        python main.py scan src/ --output json | jq '.[] | select(.risk_score > 0.8)'
    """
    console.print(Panel(
        f"[bold cyan]gitleaks-ai[/bold cyan] scanning [bold]{target}[/bold]\n"
        f"Entropy threshold: {min_entropy} | AI review: {'enabled' if ai_review else 'disabled'}",
        expand=False
    ))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        task = progress.add_task("Scanning files...", total=None)
        findings = scan_directory(target, min_entropy=min_entropy, max_file_size_kb=max_file_size)
        progress.update(task, description=f"Found {len(findings)} potential secrets.")

    if not findings:
        console.print("[bold green]✓ No secrets detected.[/bold green]")
        return

    if ai_review:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            task = progress.add_task(f"AI reviewing {len(findings)} findings...", total=None)
            findings = review_findings_batch(findings)
            fp_count = sum(1 for f in findings if f.is_false_positive)
            progress.update(task, description=f"AI review complete. {fp_count} false positives identified.")

        console.print(f"[dim]AI review: {fp_count}/{len(findings)} marked as false positives.[/dim]")

    display_findings = [f for f in findings if not (no_fp and f.is_false_positive)] if ai_review else findings
    confirmed_count = sum(1 for f in findings if not f.is_false_positive) if ai_review else len(findings)

    if output == "json":
        print(json.dumps([f.to_dict() for f in display_findings], indent=2))
        return

    if output == "markdown":
        lines = ["# gitleaks-ai Scan Report\n",
                 f"**Target:** `{target}`  \n**Total findings:** {len(findings)}  \n"
                 f"**Confirmed secrets:** {confirmed_count}\n\n",
                 "| # | File | Line | Type | Entropy | Risk | AI Verdict |\n",
                 "|---|------|------|------|---------|------|------------|\n"]
        for i, f in enumerate(display_findings, 1):
            verdict = f.ai_verdict or "—"
            lines.append(f"| {i} | `{f.file}` | {f.line} | {f.secret_type} | "
                         f"{f.entropy} | {f.risk_score} | {verdict} |\n")
        console.print(Markdown("".join(lines)))
        return

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
            str(f.entropy), str(f.risk_score), verdict_text
        )

    console.print(table)

    if len(display_findings) > 100:
        console.print(f"[dim]... and {len(display_findings) - 100} more. Use --output json for full results.[/dim]")

    if report:
        with Progress(SpinnerColumn(), TextColumn("Generating remediation report..."),
                      console=console, transient=True) as progress:
            progress.add_task("", total=None)
            remediation = generate_remediation_report(findings)

        with open(report, "w") as f:
            f.write(f"# gitleaks-ai Remediation Report\n\n")
            f.write(f"**Target:** `{target}`  \n**Confirmed secrets:** {confirmed_count}\n\n---\n\n")
            f.write(remediation)
        console.print(f"[bold green]✓ Remediation report saved to {report}[/bold green]")

    # Exit with non-zero if confirmed secrets found (useful for CI/CD)
    if confirmed_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    cli()
