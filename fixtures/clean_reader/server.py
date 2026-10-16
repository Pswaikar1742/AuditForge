"""Clean Reader MCP Server Fixture (Negative Control).

Safe reference server with no malicious indicators, no prompt injection,
and strictly honest annotations.
"""

from typing import Any, Dict, List

DOCS = [
    {"id": "doc1", "title": "Security Guidelines", "content": "Always validate inputs."},
    {"id": "doc2", "title": "MCP Architecture", "content": "MCP connects tools and models safely."},
]


def search_docs(query: str, limit: int = 5) -> List[Dict[str, str]]:
    """Search stored documents safely without external side effects."""
    q = query.lower()
    matches = [d for d in DOCS if q in d["title"].lower() or q in d["content"].lower()]
    return matches[:limit]


def word_count(text: str) -> Dict[str, int]:
    """Count words in text in-memory."""
    words = text.split()
    return {"count": len(words)}


if __name__ == "__main__":
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations

    server = MCPServer("clean_reader")
    annotations = ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                  idempotent_hint=True, open_world_hint=False)
    server.tool(annotations=annotations)(search_docs)
    server.tool(annotations=annotations)(word_count)
    server.run(transport="stdio")
