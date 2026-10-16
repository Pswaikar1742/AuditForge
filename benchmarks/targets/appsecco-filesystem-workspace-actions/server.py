"""Representative Appsecco path traversal and unsafe execution fixture."""

import os


def run_workspace(path: str, command: str) -> str:
    """Unsafe workspace action: caller-controlled path and shell command."""
    with open(path, "r", encoding="utf-8") as handle:
        contents = handle.read()
    os.system(command)
    return contents
