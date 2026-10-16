"""Unit tests for AuditForge Typer CLI commands."""

from typer.testing import CliRunner
from auditforge.cli import app

runner = CliRunner()


def test_cli_help():
    """Verify CLI root help command executes successfully."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AuditForge — Evidence-First MCP Security Auditor" in result.output
    assert "doctor" in result.output
    assert "pin" in result.output
    assert "diff" in result.output


def test_cli_version():
    """Verify CLI version command outputs version."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AuditForge" in result.output
    assert "0.1.0" in result.output


def test_cli_doctor():
    """Verify doctor command runs diagnostic checks."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Dependency & Environment Status" in result.output
    assert "Python Runtime" in result.output
    assert "MCP Python SDK" in result.output


def test_cli_scan():
    """Verify scan command executes on clean_reader fixture."""
    result = runner.invoke(app, ["scan", "fixtures/clean_reader", "--no-reports"])
    assert result.exit_code == 0
    assert "Trust State:" in result.output
    assert "VERIFIED" in result.output
