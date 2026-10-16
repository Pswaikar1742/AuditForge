"""Security Knowledge Corpus Registry and Hybrid Retrieval Engine.

Manages curated, versioned security references:
- MCP official specifications
- OWASP LLM top 10 guidance
- CWE vulnerability classifications
- AuditForge remediation playbooks

Provides deterministic lexical search (BM25 token relevance) and hybrid trust-tier
ranking, with zero external service dependencies.
"""

from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple


CORPUS_DIR = Path(__file__).parent / "corpus"
CORPUS_VERSION = "2026.1"

# Trust tier ranking weights
TRUST_WEIGHTS = {
    "OFFICIAL_SPEC": 1.30,
    "SECURITY_ADVISORY": 1.15,
    "AUDIT_PLAYBOOK": 1.05,
    "COMMUNITY": 0.90,
}


@dataclass
class KnowledgeChunk:
    """Verifiable chunk of security knowledge."""
    chunk_id: str
    document_id: str
    section_id: str
    title: str
    content: str
    content_hash: str
    trust_tier: str
    source_url: str
    publisher: str
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "section_id": self.section_id,
            "title": self.title,
            "content": self.content,
            "content_hash": self.content_hash,
            "trust_tier": self.trust_tier,
            "source_url": self.source_url,
            "publisher": self.publisher,
            "score": round(self.score, 4),
        }


@dataclass
class KnowledgeDocument:
    """A versioned security knowledge document."""
    id: str
    title: str
    publisher: str
    version: str
    trust_tier: str
    url: str
    license: str
    chunks: List[KnowledgeChunk] = field(default_factory=list)


def _tokenize(text: str) -> List[str]:
    """Tokenize text into lower-cased alphanumeric keywords."""
    return re.findall(r"\b[a-z0-9_\-\.]{2,}\b", text.lower())


class KnowledgeRegistry:
    """In-memory security knowledge corpus index supporting hybrid search."""

    def __init__(self, corpus_path: Optional[Path] = None):
        self.corpus_path = corpus_path or CORPUS_DIR
        self.documents: Dict[str, KnowledgeDocument] = {}
        self.chunks: Dict[str, KnowledgeChunk] = {}
        self.inverted_index: Dict[str, Set[str]] = {}
        self.doc_lengths: Dict[str, int] = {}
        self.avg_doc_length: float = 0.0
        self.total_chunks: int = 0
        self._load_and_index()

    def _load_and_index(self) -> None:
        """Ingest all JSON documents from corpus directory and build inverted index."""
        if not self.corpus_path.exists():
            return

        for fpath in sorted(self.corpus_path.glob("*.json")):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    doc_data = json.load(f)
                self.ingest_document(doc_data)
            except Exception:
                continue

        # Compute average chunk length for BM25
        if self.doc_lengths:
            self.avg_doc_length = sum(self.doc_lengths.values()) / len(self.doc_lengths)
        self.total_chunks = len(self.chunks)

    def ingest_document(self, data: Dict[str, Any]) -> KnowledgeDocument:
        """Ingest and index a single structured document."""
        doc_id = data.get("id", f"DOC-{hashlib.sha256(json.dumps(data).encode()).hexdigest()[:8]}")
        doc = KnowledgeDocument(
            id=doc_id,
            title=data.get("title", ""),
            publisher=data.get("publisher", "AuditForge"),
            version=data.get("version", "1.0"),
            trust_tier=data.get("trust_tier", "OFFICIAL_SPEC"),
            url=data.get("url", ""),
            license=data.get("license", ""),
        )

        sections = data.get("sections", [])
        for idx, sec in enumerate(sections):
            sec_id = sec.get("section_id", f"sec_{idx}")
            title = sec.get("title", "")
            content = sec.get("content", "")
            chunk_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

            # Deduplication: skip identical content within same document
            chunk_id = f"chk-{doc_id}-{sec_id}"
            chunk = KnowledgeChunk(
                chunk_id=chunk_id,
                document_id=doc_id,
                section_id=sec_id,
                title=title,
                content=content,
                content_hash=chunk_hash,
                trust_tier=doc.trust_tier,
                source_url=doc.url,
                publisher=doc.publisher,
            )
            doc.chunks.append(chunk)
            self.chunks[chunk_id] = chunk

            # Index chunk tokens
            tokens = _tokenize(f"{title} {content}")
            self.doc_lengths[chunk_id] = len(tokens)
            for tok in set(tokens):
                if tok not in self.inverted_index:
                    self.inverted_index[tok] = set()
                self.inverted_index[tok].add(chunk_id)

        self.documents[doc_id] = doc
        return doc

    def search(
        self,
        query: str,
        top_k: int = 5,
        trust_tier: Optional[str] = None,
        min_score: float = 0.1,
    ) -> List[KnowledgeChunk]:
        """Perform hybrid BM25 + trust-tier weighted retrieval on the knowledge corpus."""
        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scores: Dict[str, float] = {}
        N = max(1, len(self.chunks))
        k1 = 1.2
        b = 0.75
        avg_dl = max(1.0, self.avg_doc_length)

        for token in query_tokens:
            posting = self.inverted_index.get(token, set())
            n_q = len(posting)
            if n_q == 0:
                continue

            # Standard BM25 IDF
            idf = math.log((N - n_q + 0.5) / (n_q + 0.5) + 1.0)

            for chunk_id in posting:
                chunk = self.chunks[chunk_id]
                if trust_tier and chunk.trust_tier != trust_tier:
                    continue

                chunk_text_lower = f"{chunk.title} {chunk.content}".lower()
                tf = chunk_text_lower.count(token)
                dl = self.doc_lengths.get(chunk_id, avg_dl)

                denom = tf + k1 * (1 - b + b * (dl / avg_dl))
                term_score = idf * (tf * (k1 + 1)) / (denom if denom > 0 else 1.0)

                scores[chunk_id] = scores.get(chunk_id, 0.0) + term_score

        # Apply trust tier weights
        ranked: List[KnowledgeChunk] = []
        for chunk_id, raw_score in scores.items():
            chunk = self.chunks[chunk_id]
            weight = TRUST_WEIGHTS.get(chunk.trust_tier, 1.0)
            final_score = raw_score * weight
            if final_score >= min_score:
                # Return copy with computed score
                c_copy = KnowledgeChunk(
                    chunk_id=chunk.chunk_id,
                    document_id=chunk.document_id,
                    section_id=chunk.section_id,
                    title=chunk.title,
                    content=chunk.content,
                    content_hash=chunk.content_hash,
                    trust_tier=chunk.trust_tier,
                    source_url=chunk.source_url,
                    publisher=chunk.publisher,
                    score=final_score,
                )
                ranked.append(c_copy)

        ranked.sort(key=lambda c: c.score, reverse=True)
        return ranked[:top_k]

    def get_sources_catalog(self) -> List[Dict[str, Any]]:
        """Return list of all registered reference documents and metadata."""
        out = []
        for doc in self.documents.values():
            out.append({
                "id": doc.id,
                "title": doc.title,
                "publisher": doc.publisher,
                "version": doc.version,
                "trust_tier": doc.trust_tier,
                "url": doc.url,
                "license": doc.license,
                "chunks_count": len(doc.chunks),
            })
        return out


# Global singleton instance for app-wide retrieval
_REGISTRY_INSTANCE: Optional[KnowledgeRegistry] = None


def get_knowledge_registry() -> KnowledgeRegistry:
    """Return initialized global KnowledgeRegistry singleton."""
    global _REGISTRY_INSTANCE
    if _REGISTRY_INSTANCE is None:
        _REGISTRY_INSTANCE = KnowledgeRegistry()
    return _REGISTRY_INSTANCE
