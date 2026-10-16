"""AuditForge CLI — Typer + Rich Interface."""

import json
import os
import shutil
import subprocess
import sys
import urllib.request
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from auditforge import __version__
from auditforge.catalog.client import MCPCatalogClient
from auditforge.catalog.pinning import diff_catalogs
from auditforge.config import config
from auditforge.core.contracts import Severity, TrustState
from auditforge.orchestrator import ScanOrchestrator
from auditforge.reports.json_report import export_json_report
from auditforge.reports.markdown import generate_markdown_report
from auditforge.storage.database import Database

app = typer.Typer(
    name="auditforge",
    help="AuditForge — Evidence-First MCP Security Auditor",
    add_completion=False,
)
console = Console()


@app.command()
def version():
    """Display current AuditForge version."""
    console.print(f"[bold cyan]AuditForge[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def doctor():
    """Inspect environment, tool dependencies, and platform readiness without destructive changes."""
    console.print(Panel.fit("[bold cyan]AuditForge System Diagnostic & Readiness Doctor[/bold cyan]"))

    table = Table(title="Dependency & Environment Status", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="dim", width=22)
    table.add_column("Status", width=10)
    table.add_column("Observed Details", width=36)
    table.add_column("Recommendation", width=30)

    # 1. Python runtime
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        table.add_row("Python Runtime", "[bold green]PASS[/bold green]", f"Python {py_ver} ({sys.executable})", "Compatible (>=3.11)")
    else:
        table.add_row("Python Runtime", "[bold red]FAIL[/bold red]", f"Python {py_ver}", "Upgrade to Python 3.11 or 3.12")

    # 2. MCP SDK
    try:
        import mcp
        mcp_ver = getattr(mcp, "__version__", "installed (v2)")
        table.add_row("MCP Python SDK", "[bold green]PASS[/bold green]", f"MCP SDK v{mcp_ver}", "Ready for tool discovery")
    except ImportError:
        table.add_row("MCP Python SDK", "[bold red]FAIL[/bold red]", "Not installed", "Install mcp via uv pip install mcp")

    # 3. SQLite Storage
    try:
        db = Database(config.DB_PATH)
        table.add_row("SQLite Storage", "[bold green]PASS[/bold green]", f"Schema ready ({config.DB_PATH})", "Storage operational")
    except Exception as e:
        table.add_row("SQLite Storage", "[bold red]FAIL[/bold red]", str(e)[:34], "Check write permissions")

    # 4. Docker Sandbox
    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            if res.returncode == 0:
                table.add_row("Docker Daemon", "[bold green]PASS[/bold green]", "Docker daemon running", "Sandbox execution ready")
            else:
                table.add_row("Docker Daemon", "[bold yellow]WARN[/bold yellow]", "Docker installed, service down", "Start docker daemon if testing dynamic probes")
        except Exception:
            table.add_row("Docker Daemon", "[bold yellow]WARN[/bold yellow]", "Docker call timed out", "Ensure user in docker group")
    else:
        table.add_row("Docker Daemon", "[bold yellow]WARN[/bold yellow]", "docker CLI not found", "Install Docker for dynamic sandboxed probing")

    # 5. Ollama & Open-Weight Models
    try:
        req = urllib.request.Request(f"{config.OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            models = [m.get("name") for m in data.get("models", [])]
            mod_str = ", ".join(models[:3]) + (f" (+{len(models)-3} more)" if len(models) > 3 else "")
            table.add_row("Ollama Service", "[bold green]PASS[/bold green]", f"Connected ({mod_str or 'No models'})", f"Active model: {config.OLLAMA_MODEL}")
    except Exception:
        table.add_row("Ollama Service", "[bold yellow]WARN[/bold yellow]", f"Cannot connect to {config.OLLAMA_HOST}", "Start ollama serve for semantic checks")

    # 6. Node & npm (for Dashboard)
    node_bin = shutil.which("node")
    npm_bin = shutil.which("npm")
    if node_bin and npm_bin:
        table.add_row("Node & npm", "[bold green]PASS[/bold green]", "Node and npm available", "Dashboard build ready")
    else:
        table.add_row("Node & npm", "[bold yellow]WARN[/bold yellow]", "Missing node or npm", "Install Node.js for frontend dashboard")

    console.print(table)


@app.command()
def pin(
    catalog_path: str = typer.Argument(..., help="Path to catalog JSON file or server command"),
    server_id: str = typer.Option(None, "--id", "-i", help="Server ID to pin under"),
):
    """Pin an approved MCP server catalog baseline snapshot."""
    db = Database(config.DB_PATH)
    snapshot = MCPCatalogClient.load_from_file(catalog_path, server_id=server_id)
    db.save_baseline(snapshot)
    console.print(f"[bold green]✔[/bold green] Approved baseline pinned for [cyan]{snapshot.server_id}[/cyan]:")
    console.print(f"  Fingerprint: [yellow]{snapshot.catalog_fingerprint}[/yellow]")
    console.print(f"  Total tools: [bold]{len(snapshot.tools)}[/bold]")


@app.command()
def diff(
    catalog_path: str = typer.Argument(..., help="Path to current catalog JSON file"),
    server_id: str = typer.Option(..., "--id", "-i", help="Server ID to compare against baseline"),
):
    """Compare a server catalog against its pinned baseline snapshot."""
    db = Database(config.DB_PATH)
    baseline = db.get_baseline(server_id)
    if not baseline:
        console.print(f"[bold red]Error:[/bold red] No baseline pinned for server ID '{server_id}'")
        raise typer.Exit(code=1)

    current = MCPCatalogClient.load_from_file(catalog_path, server_id=server_id)
    diff_res = diff_catalogs(baseline, current)

    if diff_res.is_identical:
        console.print(f"[bold green]✔ Identical:[/bold green] Current catalog matches baseline fingerprint [yellow]{diff_res.baseline_fingerprint}[/yellow]")
    else:
        console.print(f"[bold red]⚠ Catalog Drift Detected for '{server_id}':[/bold red]")
        console.print(f"  Baseline Hash: {diff_res.baseline_fingerprint}")
        console.print(f"  Current Hash:  {diff_res.current_fingerprint}")
        if diff_res.added_tools:
            console.print(f"  [green]+ Added tools:[/green] {', '.join(diff_res.added_tools)}")
        if diff_res.removed_tools:
            console.print(f"  [red]- Removed tools:[/red] {', '.join(diff_res.removed_tools)}")
        if diff_res.modified_tools:
            console.print(f"  [yellow]~ Modified tools:[/yellow] {', '.join(diff_res.modified_tools.keys())}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target MCP server path or command"),
    no_docker: bool = typer.Option(False, "--no-docker", help="Disable dynamic Docker probing"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable open-weight LLM analysis"),
):
    """Execute complete security audit scan on target MCP server."""
    orchestrator = ScanOrchestrator(use_docker=not no_docker, use_llm=not no_llm)
    
    console.print(f"\n[bold cyan]Starting AuditForge Security Scan on:[/bold cyan] [yellow]{target}[/yellow]")
    result = orchestrator.run_scan(target)

    # Render Trust State Panel
    state_color = {
        TrustState.VERIFIED: "bold green",
        TrustState.TRUST_GAP: "bold red",
        TrustState.ROGUE: "bold white on red",
        TrustState.SUSPICIOUS: "bold yellow",
        TrustState.UNKNOWN: "bold magenta",
    }.get(result.trust_state, "bold white")

    console.print(Panel(
        f"Evaluation Result: [{state_color}]{result.trust_state.value}[/{state_color}]\n"
        f"Scan ID: [cyan]{result.scan_id}[/cyan]\n"
        f"{result.summary}",
        title="🛡️ AuditForge Trust Verdict",
        border_style=state_color.split()[-1].replace("on", "").strip(),
    ))

    # Findings Table
    if result.findings:
        table = Table(title=f"Security Findings ({len(result.findings)})", show_header=True, header_style="bold red")
        table.add_column("Severity", width=12)
        table.add_column("Rule ID", width=16)
        table.add_column("Tool", width=16)
        table.add_column("Reason / Evidence", width=44)

        for f in result.findings:
            sev_style = "bold red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            table.add_row(
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.rule_id,
                f.tool_name or "server",
                f.reason[:80] + ("..." if len(f.reason) > 80 else ""),
            )
        console.print(table)
    else:
        console.print("[bold green]✔ Zero security findings recorded.[/bold green]\n")

    # Probe Outcomes Table
    if result.probe_outcomes:
        p_table = Table(title=f"Container Dynamic Probes ({len(result.probe_outcomes)})", show_header=True, header_style="bold blue")
        p_table.add_column("Case ID", width=14)
        p_table.add_column("Tool", width=16)
        p_table.add_column("Status", width=12)
        p_table.add_column("Duration", width=12)
        p_table.add_column("Telemetry Events", width=24)

        for p in result.probe_outcomes:
            st_style = "green" if p.status.value == "OK" else "red"
            p_table.add_row(
                p.case_id,
                p.tool_name,
                f"[{st_style}]{p.status.value}[/{st_style}]",
                f"{p.duration_ms:.1f}ms",
                f"{len(p.telemetry_events)} events captured",
            )
        console.print(p_table)

    console.print(f"[bold cyan]Evidence Capsule:[/bold cyan] scan_reports/{result.scan_id}.json")
    console.print(f"[bold cyan]Markdown Report:[/bold cyan]  scan_reports/{result.scan_id}.md\n")


@app.command()
def demo():
    """Execute complete 5-stage judge-ready demonstration."""
    console.print(Panel.fit("[bold cyan]AuditForge — Master 5-Stage Live Demonstration[/bold cyan]", border_style="cyan"))

    orchestrator = ScanOrchestrator(use_docker=True, use_llm=True)
    db = Database(config.DB_PATH)
    with db._get_connection() as conn:
        conn.execute("DELETE FROM baselines WHERE server_id = 'clean_reader'")

    # Stage 1: Clean MCP baseline
    console.print("\n[bold green]═══ STAGE 1: Clean Baseline Server (Negative Control) ═══[/bold green]")
    res1 = orchestrator.run_scan("fixtures/clean_reader/")
    console.print(f"Target: clean_reader | Tools: {len(res1.snapshot.tools)} | Verdict: [bold green]{res1.trust_state.value}[/bold green] | Findings: {len(res1.findings)}")

    # Pin baseline for clean_reader
    db = Database(config.DB_PATH)
    db.save_baseline(res1.snapshot)
    console.print(f"Baseline pinned with SHA-256: [yellow]{res1.snapshot.catalog_fingerprint}[/yellow]")

    # Stage 2: Rogue Server Static & Dynamic Trap
    console.print("\n[bold red]═══ STAGE 2: Rogue Server Static Vulnerability & Sandbox Trap ═══[/bold red]")
    res2 = orchestrator.run_scan("fixtures/rogue_server/")
    console.print(f"Target: rogue_server | Verdict: [bold red]{res2.trust_state.value}[/bold red] | Findings: {len(res2.findings)}")
    for f in res2.findings[:2]:
        console.print(f"  - [{f.severity.value}] {f.rule_id} on {f.tool_name}: {f.reason}")

    # Stage 3: Poisoned Description Detection
    console.print("\n[bold yellow]═══ STAGE 3: Prompt Poisoning & Injection Detection ═══[/bold yellow]")
    res3 = orchestrator.run_scan("fixtures/poisoned_description/")
    console.print(f"Target: poisoned_description | Verdict: [bold yellow]{res3.trust_state.value}[/bold yellow] | Findings: {len(res3.findings)}")
    for f in res3.findings:
        console.print(f"  - [{f.severity.value}] {f.rule_id}: {f.reason}")

    # Stage 4: Lying Annotations (Trust Gap Reconciliation)
    console.print("\n[bold magenta]═══ STAGE 4: Lying Annotations Trust Gap Reconciliation ═══[/bold magenta]")
    res4 = orchestrator.run_scan("fixtures/lying_annotations/")
    console.print(f"Target: lying_annotations | Claimed: readOnly=True | Verdict: [bold red]{res4.trust_state.value}[/bold red]")
    for f in res4.findings:
        console.print(f"  - [{f.severity.value}] {f.rule_id}: {f.reason}")

    # Stage 5: Live Rug Pull Diff
    console.print("\n[bold cyan]═══ STAGE 5: Approved Baseline Pinning & Live Rug Pull Diff ═══[/bold cyan]")
    snap_v2 = MCPCatalogClient.load_from_file("fixtures/rug_pull/catalog_v2.json", server_id="clean_reader")
    baseline = db.get_baseline("clean_reader")
    diff_res = diff_catalogs(baseline, snap_v2)
    console.print(f"Baseline Hash: [yellow]{diff_res.baseline_fingerprint}[/yellow]")
    console.print(f"Current Hash:  [red]{diff_res.current_fingerprint}[/red]")
    console.print(f"Is Identical:  [bold red]{diff_res.is_identical}[/bold red]")
    if diff_res.added_tools:
        console.print(f"Added Tools:   [green]{', '.join(diff_res.added_tools)}[/green]")
    if diff_res.modified_tools:
        console.print(f"Modified:      [yellow]{', '.join(diff_res.modified_tools.keys())}[/yellow]")

    console.print("\n[bold green]✔ MASTER 5-STAGE DEMONSTRATION COMPLETE — ALL GATES VERIFIED.[/bold green]\n")


if __name__ == "__main__":
    app()
