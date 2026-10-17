"""
MCP Writeup RAG Server — Semantic search over bug bounty writeups.

Provides tools:
  - search_writeups: Search for similar vulnerabilities in writeup corpus
  - index_writeup:   Add a new writeup to the corpus
  - list_categories: List available writeup categories

Usage:
  python -m mcp_writeup_server.server
  # or via MCP: uv run python mcp-writeup-server/server.py
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.mcp.writeup")

# Corpus storage directory
CORPUS_DIR = Path(os.getenv("WRITEUP_CORPUS_DIR", "./data/writeup_corpus"))
INDEX_DIR = Path(os.getenv("WRITEUP_INDEX_DIR", "./data/writeup_index"))


class WriteupStore:
    """In-memory + on-disk writeup storage with optional ChromaDB vector search."""

    def __init__(self):
        self._writeups: List[Dict] = []
        self._chroma_collection = None
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        INDEX_DIR.mkdir(parents=True, exist_ok=True)

    def initialize(self):
        """Load writeups and optionally initialize ChromaDB."""
        self._load_from_disk()
        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(INDEX_DIR))
            self._chroma_collection = client.get_or_create_collection(
                name="writeups",
                metadata={"hnsw:space": "cosine"},
            )
            logger.info(f"ChromaDB initialized with {self._chroma_collection.count()} writeups")
        except ImportError:
            logger.info("ChromaDB not available — using keyword search fallback")

    def _load_from_disk(self):
        for f in CORPUS_DIR.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._writeups.extend(data)
                elif isinstance(data, dict):
                    self._writeups.append(data)
            except Exception as e:
                logger.warning(f"Failed to load {f}: {e}")
        logger.info(f"Loaded {len(self._writeups)} writeups from disk")

    def search(self, query: str, n_results: int = 5,
               category: Optional[str] = None) -> List[Dict]:
        """Search writeups by semantic similarity or keyword."""
        # Try ChromaDB vector search first
        if self._chroma_collection and self._chroma_collection.count() > 0:
            where = {"category": category} if category else None
            results = self._chroma_collection.query(
                query_texts=[query], n_results=n_results,
                where=where,
            )
            if results and results.get("documents"):
                return [
                    {"content": doc, "metadata": meta, "distance": dist}
                    for doc, meta, dist in zip(
                        results["documents"][0],
                        results["metadatas"][0],
                        results["distances"][0],
                    )
                ]

        # Fallback: keyword search
        query_lower = query.lower()
        scored = []
        for w in self._writeups:
            text = json.dumps(w).lower()
            score = sum(1 for word in query_lower.split() if word in text)
            if score > 0:
                if category and w.get("category", "").lower() != category.lower():
                    continue
                scored.append((score, w))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"content": w, "score": s} for s, w in scored[:n_results]]

    def add_writeup(self, writeup: Dict) -> str:
        """Add a writeup to the corpus."""
        self._writeups.append(writeup)
        # Save to disk
        slug = writeup.get("title", "untitled").lower().replace(" ", "_")[:50]
        path = CORPUS_DIR / f"{slug}.json"
        path.write_text(json.dumps(writeup, indent=2), encoding="utf-8")
        # Add to ChromaDB
        if self._chroma_collection:
            content = f"{writeup.get('title', '')} {writeup.get('description', '')} {writeup.get('content', '')}"
            self._chroma_collection.add(
                documents=[content],
                metadatas=[{
                    "title": writeup.get("title", ""),
                    "category": writeup.get("category", "misc"),
                    "severity": writeup.get("severity", ""),
                    "platform": writeup.get("platform", ""),
                }],
                ids=[slug],
            )
        return slug

    def list_categories(self) -> List[str]:
        cats = set()
        for w in self._writeups:
            if "category" in w:
                cats.add(w["category"])
        return sorted(cats) or ["ssrf", "xss", "idor", "sqli", "rce", "misc"]


# ═══════════════════════════════════════════
#  MCP Server Interface
# ═══════════════════════════════════════════

_store = WriteupStore()


def handle_tool_call(tool_name: str, params: Dict) -> Dict[str, Any]:
    """Handle MCP tool calls."""
    if tool_name == "search_writeups":
        results = _store.search(
            query=params.get("query", ""),
            n_results=params.get("n_results", 5),
            category=params.get("category"),
        )
        return {"success": True, "results": results, "count": len(results)}

    elif tool_name == "index_writeup":
        slug = _store.add_writeup(params.get("writeup", {}))
        return {"success": True, "id": slug}

    elif tool_name == "list_categories":
        return {"success": True, "categories": _store.list_categories()}

    return {"success": False, "error": f"Unknown tool: {tool_name}"}


TOOL_DEFINITIONS = [
    {
        "name": "search_writeups",
        "description": "Search bug bounty writeups for similar vulnerabilities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "n_results": {"type": "integer", "default": 5},
                "category": {"type": "string", "description": "Filter by category"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "index_writeup",
        "description": "Add a new bug bounty writeup to the corpus",
        "inputSchema": {
            "type": "object",
            "properties": {
                "writeup": {"type": "object", "description": "Writeup data"},
            },
            "required": ["writeup"],
        },
    },
    {
        "name": "list_categories",
        "description": "List available writeup categories",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _store.initialize()
    print(json.dumps({"tools": TOOL_DEFINITIONS}, indent=2))
    print(f"Writeup RAG Server ready — {len(_store._writeups)} writeups loaded")
