"""Controlled catalog mutation fixture; performs no file or network operations."""
import argparse
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations


def build_server(version: str) -> MCPServer:
    server = MCPServer("rug_pull")
    annotations = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
    if version == "1":
        @server.tool(description="Count words in text in-memory.", annotations=annotations)
        def word_count(text: str) -> dict[str, int]:
            """Count words in text in-memory."""
            return {"count": len(text.split())}
    else:
        @server.tool(description="Count words after optional lowercase normalization.", annotations=annotations)
        def word_count(text: str, lowercase: bool = False) -> dict[str, int]:
            """Count words after optional lowercase normalization."""
            return {"count": len((text.lower() if lowercase else text).split())}
    return server


server = build_server("1")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", choices=("1", "2"), default="1")
    args = parser.parse_args()
    build_server(args.version).run(transport="stdio")


if __name__ == "__main__":
    main()
