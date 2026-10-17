"""
╔══════════════════════════════════════════════════════════════╗
║  Semantic Memory — Vector Database + Embedding Pipeline    ║
║  ChromaDB/pgvector for semantic search & pattern matching  ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
import hashlib
from typing import Any, Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("hydra.memory.semantic")


class EmbeddingEngine:
    """Simple text → vector embedding pipeline."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._model_name = model_name
        self._model = None

    def _load_model(self):
        if self._model is not None:
            return
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name)
            logger.info(f"Embedding model loaded: {self._model_name}")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "Using hash-based fallback embeddings."
            )
            self._model = "fallback"

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Embed a list of texts into vectors."""
        self._load_model()
        if self._model == "fallback":
            return [self._hash_embed(t) for t in texts]
        return self._model.encode(texts).tolist()

    def embed_single(self, text: str) -> List[float]:
        return self.embed([text])[0]

    def _hash_embed(self, text: str, dim: int = 384) -> List[float]:
        """Fallback: deterministic hash-based pseudo-embedding."""
        h = hashlib.sha512(text.encode()).digest()
        import struct
        values = []
        for i in range(0, min(len(h), dim * 4), 4):
            chunk = h[i:i+4] if i+4 <= len(h) else h[i:].ljust(4, b'\x00')
            val = struct.unpack('f', chunk)[0]
            if not (-1e10 < val < 1e10):
                val = 0.0
            values.append(val / 1e6)
        while len(values) < dim:
            values.append(0.0)
        return values[:dim]


class SemanticMemory:
    """
    Semantic memory layer using vector database.
    
    Stores and retrieves:
      - Findings with semantic similarity search
      - Attack chains and patterns
      - Successful methodologies
      - False positive patterns
      - Historical exploit paths
    
    Supports ChromaDB (default), with in-memory fallback.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self._persist_dir = persist_dir
        self._client = None
        self._collections: Dict[str, Any] = {}
        self._embedder = EmbeddingEngine()
        self._fallback_mode = False
        # In-memory fallback
        self._mem_store: Dict[str, List[Dict[str, Any]]] = {}

    async def initialize(self):
        """Initialize ChromaDB or fallback."""
        try:
            import chromadb
            if self._persist_dir:
                Path(self._persist_dir).mkdir(parents=True, exist_ok=True)
                self._client = chromadb.PersistentClient(
                    path=self._persist_dir
                )
            else:
                self._client = chromadb.Client()

            # Create collections
            for name in ["findings", "attack_chains", "methodologies",
                         "false_positives", "reports"]:
                self._collections[name] = (
                    self._client.get_or_create_collection(
                        name=f"hydra_{name}",
                        metadata={"hnsw:space": "cosine"},
                    )
                )

            logger.info("✅ Semantic memory initialized (ChromaDB)")
        except ImportError:
            self._fallback_mode = True
            logger.warning(
                "ChromaDB not installed — using in-memory fallback"
            )
        except Exception as e:
            self._fallback_mode = True
            logger.warning(f"ChromaDB init failed: {e} — using fallback")

    async def store(
        self, collection: str, document: str,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
    ) -> str:
        """Store a document with its embedding."""
        doc_id = doc_id or hashlib.sha256(
            document.encode()
        ).hexdigest()[:16]
        metadata = metadata or {}
        metadata["stored_at"] = time.time()

        if not self._fallback_mode and collection in self._collections:
            try:
                self._collections[collection].add(
                    documents=[document],
                    metadatas=[metadata],
                    ids=[doc_id],
                )
            except Exception as e:
                logger.warning(f"ChromaDB store failed: {e}")
                self._store_fallback(collection, doc_id, document, metadata)
        else:
            self._store_fallback(collection, doc_id, document, metadata)

        return doc_id

    async def store_batch(
        self, collection: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None,
        batch_size: int = 512,
        upsert: bool = False,
    ) -> int:
        """Store many documents efficiently in a single (batched) add.

        Adding one document at a time forces ChromaDB to embed and persist
        per call, which is pathologically slow for large corpora. This adds
        in chunks so embedding is vectorised and persistence is amortised.

        With `upsert=True`, existing ids are overwritten instead of rejected
        as duplicates — used to re-index a corpus with refreshed metadata.
        """
        n = len(documents)
        if n == 0:
            return 0
        metadatas = metadatas or [{} for _ in range(n)]
        now = time.time()
        for m in metadatas:
            m.setdefault("stored_at", now)
        if ids is None:
            ids = [hashlib.sha256(d.encode()).hexdigest()[:16] for d in documents]

        if not self._fallback_mode and collection in self._collections:
            stored = 0
            coll = self._collections[collection]
            write = coll.upsert if upsert else coll.add
            for i in range(0, n, batch_size):
                sl = slice(i, i + batch_size)
                try:
                    write(
                        documents=documents[sl],
                        metadatas=metadatas[sl],
                        ids=ids[sl],
                    )
                    stored += len(documents[sl])
                except Exception as e:
                    logger.warning(f"ChromaDB batch store failed: {e}")
                    for d, m, i2 in zip(documents[sl], metadatas[sl], ids[sl]):
                        self._store_fallback(collection, i2, d, m)
                        stored += 1
            return stored

        for d, m, i2 in zip(documents, metadatas, ids):
            self._store_fallback(collection, i2, d, m)
        return n

    def _store_fallback(self, collection: str, doc_id: str,
                        document: str, metadata: Dict):
        if collection not in self._mem_store:
            self._mem_store[collection] = []
        self._mem_store[collection].append({
            "id": doc_id, "document": document,
            "metadata": metadata,
            "embedding": self._embedder.embed_single(document),
        })

    async def search(
        self, collection: str, query: str,
        top_k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Semantic search across stored documents."""
        if not self._fallback_mode and collection in self._collections:
            try:
                where = filter_metadata if filter_metadata else None
                results = self._collections[collection].query(
                    query_texts=[query], n_results=top_k,
                    where=where,
                )
                items = []
                docs = results.get("documents", [[]])[0]
                metas = results.get("metadatas", [[]])[0]
                dists = results.get("distances", [[]])[0]
                ids = results.get("ids", [[]])[0]
                for i in range(len(docs)):
                    items.append({
                        "id": ids[i], "document": docs[i],
                        "metadata": metas[i] if i < len(metas) else {},
                        "distance": dists[i] if i < len(dists) else 1.0,
                        "similarity": 1 - (dists[i] if i < len(dists) else 1.0),
                    })
                return items
            except Exception as e:
                logger.warning(f"ChromaDB search failed: {e}")

        return self._search_fallback(collection, query, top_k)

    def _search_fallback(self, collection: str, query: str,
                         top_k: int) -> List[Dict[str, Any]]:
        """Cosine similarity search in fallback mode."""
        docs = self._mem_store.get(collection, [])
        if not docs:
            return []
        query_emb = self._embedder.embed_single(query)
        scored = []
        for doc in docs:
            sim = self._cosine_sim(query_emb, doc.get("embedding", []))
            scored.append({
                "id": doc["id"], "document": doc["document"],
                "metadata": doc["metadata"],
                "similarity": sim, "distance": 1 - sim,
            })
        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:top_k]

    @staticmethod
    def _cosine_sim(a: List[float], b: List[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = sum(x * x for x in a) ** 0.5
        mag_b = sum(x * x for x in b) ** 0.5
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    async def find_similar_findings(
        self, finding_text: str, top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Find similar historical findings."""
        return await self.search("findings", finding_text, top_k)

    async def store_finding(self, finding: Dict[str, Any]) -> str:
        """Store a finding for future similarity search."""
        text = (
            f"{finding.get('name', '')} "
            f"{finding.get('description', '')} "
            f"{finding.get('type', '')} "
            f"{finding.get('severity', '')}"
        )
        return await self.store("findings", text, metadata={
            "severity": finding.get("severity", ""),
            "type": finding.get("type", ""),
            "name": finding.get("name", ""),
        })

    async def store_methodology(
        self, name: str, steps: List[str],
        success_rate: float = 0.0
    ) -> str:
        """Store a successful methodology."""
        text = f"{name}: {' → '.join(steps)}"
        return await self.store("methodologies", text, metadata={
            "name": name, "steps_count": len(steps),
            "success_rate": success_rate,
        })

    async def find_similar_patterns(
        self, pattern: str, top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Find similar patterns from history."""
        return await self.search("methodologies", pattern, top_k)

    async def get_stats(self) -> Dict[str, Any]:
        if self._fallback_mode:
            return {
                "mode": "in-memory",
                "collections": {
                    k: len(v) for k, v in self._mem_store.items()
                },
            }
        return {
            "mode": "chromadb",
            "collections": {
                name: coll.count()
                for name, coll in self._collections.items()
            },
        }
