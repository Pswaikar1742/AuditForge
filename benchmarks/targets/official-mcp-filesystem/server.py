"""Representative source for the official MCP Filesystem server."""


def write_file(path: str, content: str) -> int:
    """Write only within an operator-provided allowed directory."""
    with open(path, "w", encoding="utf-8") as handle:
        return handle.write(content)
