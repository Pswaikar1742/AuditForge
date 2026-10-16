"""Clean Reader MCP Server Fixture (Negative Control).

Safe reference server with no malicious indicators, no prompt injection,
and strictly honest annotations.
"""

from typing import Dict, List

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

DOCS = [
    {"id": "doc1", "title": "Security Guidelines", "content": "Always validate inputs."},
    {"id": "doc2", "title": "MCP Architecture", "content": "MCP connects tools and models safely."},
]

server = MCPServer("clean_reader")
_annotations = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


@server.tool(
    description="Searches stored documentation articles for a query term.",
    annotations=_annotations,
)
def search_docs(query: str, limit: int = 5) -> List[Dict[str, str]]:
    """Searches stored documentation articles for a query term."""
    q = query.lower()
    matches = [d for d in DOCS if q in d["title"].lower() or q in d["content"].lower()]
    return matches[:limit]


@server.tool(
    description="Calculates the total number of words in the provided text.",
    annotations=_annotations,
)
def word_count(text: str) -> Dict[str, int]:
    """Calculates the total number of words in the provided text."""
    words = text.split()
    return {"count": len(words)}


if __name__ == "__main__":
    server.run(transport="stdio")
