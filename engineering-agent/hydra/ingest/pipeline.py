"""
Ingest Pipeline — fetch public write-ups, persist a corpus, and feed the
learning subsystem (vulnerability classifier + semantic memory).
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from hydra.config import get_config
from hydra.ingest.base import REGISTRY, Writeup

logger = logging.getLogger("hydra.ingest.pipeline")


class IngestPipeline:
    """Orchestrates fetching from registered sources and learning from results."""

    def __init__(self, corpus_dir: Optional[str] = None, tokens: Optional[Dict[str, str]] = None):
        cfg = get_config()
        self.corpus_dir = Path(corpus_dir or (Path(cfg.ml.model_dir).parent / "writeup_corpus"))
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.tokens = tokens or {}

    def available_sources(self) -> List[str]:
        return sorted(REGISTRY.keys())

    # ── Fetch ──────────────────────────────────
    async def fetch(self, sources: List[str], query: str = "",
                    limit_per_source: int = 20) -> List[Writeup]:
        """Fetch write-ups from the named sources. Unknown names are skipped."""
        collected: List[Writeup] = []
        for name in sources:
            adapter_cls = REGISTRY.get(name)
            if not adapter_cls:
                logger.warning(f"Unknown source '{name}' — skipping "
                               f"(available: {self.available_sources()})")
                continue
            adapter = adapter_cls(token=self.tokens.get(name, ""))
            try:
                items = await adapter.fetch(query=query, limit=limit_per_source)
                collected.extend(items)
            except Exception as e:
                logger.warning(f"[{name}] fetch error: {e}")
        logger.info(f"📥 Fetched {len(collected)} write-ups from {len(sources)} source(s)")
        return collected

    # ── Persist ────────────────────────────────
    def save_corpus(self, writeups: List[Writeup]) -> Dict[str, Any]:
        """Merge into the on-disk corpus, de-duplicating by doc_id."""
        corpus_path = self.corpus_dir / "corpus.json"
        existing: Dict[str, Dict] = {}
        if corpus_path.exists():
            try:
                for w in json.loads(corpus_path.read_text(encoding="utf-8")):
                    existing[w.get("doc_id", w.get("url", ""))] = w
            except Exception:
                pass
        added = 0
        for w in writeups:
            key = w.doc_id()
            rec = w.to_dict()
            rec["doc_id"] = key
            if key not in existing:
                added += 1
            existing[key] = rec
        corpus_path.write_text(json.dumps(list(existing.values()), indent=2, default=str),
                               encoding="utf-8")
        logger.info(f"💾 Corpus: +{added} new, {len(existing)} total → {corpus_path}")
        return {"added": added, "total": len(existing), "path": str(corpus_path)}

    # ── Enrich ─────────────────────────────────
    async def enrich_with_kev(self, writeups: List[Writeup]) -> Dict[str, Any]:
        """Flag write-ups whose CVEs are known-exploited (CISA KEV).

        Adds a `known-exploited` tag (and `kev:<CVE>` tags) and lifts severity
        to critical for actively-exploited CVEs, so the learning subsystem
        learns which vulnerabilities are actually weaponised in the wild.
        NVD per-CVE lookups are skipped here (KEV catalog only) to stay fast
        over large corpora.
        """
        try:
            from hydra.exploits import ExploitIntel, extract_cves
        except Exception as e:
            logger.debug(f"Exploit intel unavailable: {e}")
            return {"enriched": 0, "known_exploited": 0}

        # KEV-only enrichment: _load_kev() hits a single cached feed and never
        # reads cfg.nvd_lookup, so we must NOT mutate the shared config singleton
        # here (doing so would disable NVD lookups process-wide for enrich_cve).
        ei = ExploitIntel()
        kev = await ei._load_kev()
        if not kev:
            return {"enriched": 0, "known_exploited": 0}

        enriched = 0
        known = 0
        for w in writeups:
            cves = extract_cves(w.title, w.content, *w.tags)
            if not cves:
                continue
            hits = [c for c in cves if c in kev]
            if not hits:
                continue
            enriched += 1
            known += 1
            if "known-exploited" not in w.tags:
                w.tags.append("known-exploited")
            for c in hits:
                tag = f"kev:{c}"
                if tag not in w.tags:
                    w.tags.append(tag)
            w.severity = "critical"        # actively exploited → top priority
        logger.info(f"🎯 KEV enrichment: {known} write-ups flagged known-exploited")
        return {"enriched": enriched, "known_exploited": known}

    # ── Learn ──────────────────────────────────
    @staticmethod
    def _to_finding(w: Writeup) -> Dict[str, Any]:
        return {"name": w.title, "description": w.content[:2000],
                "type": w.category, "severity": w.severity}

    def train_vuln_classifier(self, writeups: List[Writeup]) -> Dict[str, Any]:
        """Train the embedding-based VulnerabilityClassifier on categorised write-ups."""
        from hydra.ml import VulnerabilityClassifier
        samples = [(self._to_finding(w), w.category)
                   for w in writeups if w.category and w.category != "misc"]
        if not samples:
            return {"trained": False, "reason": "no categorised write-ups"}
        return VulnerabilityClassifier().train(samples)

    async def store_semantic(self, writeups: List[Writeup],
                             upsert: bool = False) -> int:
        """Store write-ups in semantic memory for similarity search."""
        try:
            from hydra.memory.semantic import SemanticMemory
        except Exception as e:
            logger.debug(f"Semantic memory unavailable: {e}")
            return 0
        mem = SemanticMemory(persist_dir=get_config().semantic_memory.persist_dir)
        await mem.initialize()
        documents, metadatas, ids = [], [], []
        for w in writeups:
            documents.append(f"{w.title}\n{w.content[:2000]}")
            metadatas.append({
                "source": w.source, "category": w.category,
                "severity": w.severity, "url": w.url,
                "title": w.title,
                # ChromaDB metadata must be scalar → join tags to a string.
                "tags": ",".join(w.tags),
            })
            ids.append(w.doc_id())
        stored = await mem.store_batch("methodologies", documents, metadatas, ids,
                                       upsert=upsert)
        logger.info(f"🧠 Stored {stored} write-ups in semantic memory")
        return stored

    def load_corpus(self) -> List[Writeup]:
        """Load the on-disk corpus back into Writeup objects."""
        corpus_path = self.corpus_dir / "corpus.json"
        if not corpus_path.exists():
            return []
        out: List[Writeup] = []
        for rec in json.loads(corpus_path.read_text(encoding="utf-8")):
            rec.pop("doc_id", None)          # recomputed by Writeup
            try:
                out.append(Writeup(**rec))
            except TypeError:
                # Tolerate schema drift: keep only known fields.
                out.append(Writeup(
                    source=rec.get("source", ""), title=rec.get("title", ""),
                    url=rec.get("url", ""), content=rec.get("content", ""),
                    category=rec.get("category", "misc"),
                    severity=rec.get("severity", "medium"),
                    author=rec.get("author", ""), published=rec.get("published", ""),
                    tags=rec.get("tags", []) or [],
                ))
        return out

    async def reindex_semantic(self) -> Dict[str, Any]:
        """Rebuild semantic memory from the on-disk corpus (upsert).

        Fixes stale entries indexed before metadata fields (e.g. `title`)
        were added, without re-fetching anything from the network.
        """
        writeups = self.load_corpus()
        if not writeups:
            return {"reindexed": 0, "reason": "empty corpus"}
        stored = await self.store_semantic(writeups, upsert=True)
        logger.info(f"♻️  Re-indexed {stored} write-ups from corpus into semantic memory")
        return {"reindexed": stored, "corpus_total": len(writeups)}

    # ── One-shot orchestration ─────────────────
    async def run(self, sources: List[str], query: str = "",
                  limit_per_source: int = 20, do_train: bool = True,
                  do_store: bool = True) -> Dict[str, Any]:
        writeups = await self.fetch(sources, query, limit_per_source)
        result: Dict[str, Any] = {"fetched": len(writeups)}
        if not writeups:
            return result
        # Flag known-exploited (CISA KEV) before persisting/learning so the
        # corpus, semantic memory, and classifier all see the enriched data.
        result["kev"] = await self.enrich_with_kev(writeups)
        result["corpus"] = self.save_corpus(writeups)
        if do_store:
            # Upsert so re-ingesting overlapping reports refreshes them in one
            # batched call instead of erroring on duplicate ids and falling
            # back to slow per-item stores.
            result["semantic_stored"] = await self.store_semantic(writeups, upsert=True)
        if do_train:
            result["training"] = self.train_vuln_classifier(writeups)
        # Category distribution for visibility
        dist: Dict[str, int] = {}
        for w in writeups:
            dist[w.category] = dist.get(w.category, 0) + 1
        result["categories"] = dist
        return result
