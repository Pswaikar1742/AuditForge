"""Representative source for the official MCP Time server."""

from datetime import datetime


def get_current_time(timezone: str) -> str:
    """Calculate a time value without network, process, or file effects."""
    return datetime.now().isoformat() + f" [{timezone}]"
