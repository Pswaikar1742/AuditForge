"""Representative source for the official MCP Fetch server."""

from urllib.request import urlopen


def fetch(url: str) -> str:
    """Fetch a URL; network access is the declared purpose of this tool."""
    with urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace")
