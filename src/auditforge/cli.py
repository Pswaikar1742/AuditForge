"""AuditForge CLI — Typer + Rich Interface."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import click
import typer
import typer.core

# Workaround for Click >=8.2 with Typer make_metavar and flag_value mismatch
typer.core.rich = None

_orig_opt_init = typer.core.TyperOption.__init__
def _safe_opt_init(self, *args, **kwargs):
    if kwargs.get("flag_value") is None and "flag_value" in kwargs:
        unset = getattr(click.core, "UNSET", None)
        if unset is not None:
            kwargs["flag_value"] = unset
        else:
            del kwargs["flag_value"]
    _orig_opt_init(self, *args, **kwargs)
typer.core.TyperOption.__init__ = _safe_opt_init

def _make_metavar(self, ctx=None):
    if self.metavar is not None:
        return self.metavar
    if ctx is not None:
        try:
            v = self.type.get_metavar(param=self, ctx=ctx)
            if v:
                return v
        except Exception:
            pass
    return self.name.upper() if self.name else ""

typer.core.TyperArgument.make_metavar = _make_metavar
typer.core.TyperOption.make_metavar = _make_metavar

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from auditforge import __version__
from auditforge.config import config
from auditforge.storage.database import Database
from auditforge.core.contracts import Severity, TrustState
from auditforge.catalog.client import MCPCatalogClient
from auditforge.catalog.pinning import diff_catalogs
from auditforge.reports.markdown import generate_markdown_report
from auditforge.reports.json_report import export_json_report

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

    # 6. Node / npm (for Dashboard)
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
    reports: bool = typer.Option(True, "--reports", help="Generate and save Markdown & JSON reports"),
):
    """Execute security audit scan on target."""
    from auditforge.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator()
    try:
        console.print(Panel.fit(f"[bold cyan]AuditForge Security Auditor[/bold cyan]\nTarget: [yellow]{target}[/yellow]"))
        result = orchestrator.run_scan(target)

        table = Table(title=f"Scan Findings ({len(result.findings)} detected)")
        table.add_column("Severity", justify="center")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Tool", style="dim")
        table.add_column("Reason")

        sev_styles = {
            Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
            Severity.HIGH: "[bold yellow]HIGH[/bold yellow]",
            Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
            Severity.LOW: "[blue]LOW[/blue]",
            Severity.INFO: "[dim]INFO[/dim]",
        }

        for f in result.findings:
            table.add_row(
                sev_styles.get(f.severity, f.severity.value),
                f.rule_id,
                f.tool_name or "server",
                f.reason,
            )

        console.print(table)
        console.print(f"\n[bold]Trust State:[/bold] [bold magenta]{result.trust_state.value}[/bold magenta]")

        if reports:
            rep_dir = Path("reports")
            rep_dir.mkdir(parents=True, exist_ok=True)
            target_slug = Path(target).name or "server"
            md_path = rep_dir / f"audit_report_{target_slug}.md"
            json_path = rep_dir / f"audit_report_{target_slug}.json"
            generate_markdown_report(result, str(md_path))
            export_json_report(result, str(json_path))
            console.print(f"[dim]Reports generated at: {md_path} and {json_path}[/dim]")

    except Exception as e:
        console.print(f"[bold red]Scan Error:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
