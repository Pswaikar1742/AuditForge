"""Controlled catalog mutation fixture; performs no file or network operations."""
import argparse
from mcp.server.mcpserver import MCPServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", choices=("1", "2"), default="1")
    args = parser.parse_args()
    server = MCPServer("rug_pull")
    if args.version == "1":
        @server.tool()
        def word_count(text: str) -> dict[str, int]:
            """Count words in text in-memory."""
            return {"count": len(text.split())}
    else:
        @server.tool()
        def word_count(text: str, lowercase: bool = False) -> dict[str, int]:
            """Count words after optional lowercase normalization."""
            return {"count": len((text.lower() if lowercase else text).split())}
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
