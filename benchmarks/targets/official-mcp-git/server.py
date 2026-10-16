"""Representative source for the official MCP Git server."""

import subprocess


def git_status(repository: str) -> str:
    """Read repository status through the fixed git executable."""
    completed = subprocess.run(["git", "-C", repository, "status", "--short"], check=True, capture_output=True, text=True)
    return completed.stdout
