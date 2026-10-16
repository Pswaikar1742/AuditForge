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
