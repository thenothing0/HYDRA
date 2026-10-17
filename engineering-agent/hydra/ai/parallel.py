"""
╔══════════════════════════════════════════════════════════════╗
║  Parallel Model Reasoning — Multi-LLM Consensus Analysis   ║
║  Send same task to multiple LLMs, compare & combine        ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.ai.parallel")


class ParallelModelEngine:
    """
    Send the same task to multiple LLMs simultaneously,
    compare outputs, detect hallucinations, and combine
    into a unified consensus result.
    """

    def __init__(self, ai_router=None):
        self.ai = ai_router

    async def parallel_query(
        self, prompt: str, task_type: str = "reasoning",
        providers: Optional[List[str]] = None,
        max_tokens: int = 2000,
    ) -> Dict[str, Any]:
        """
        Send prompt to multiple providers in parallel.
        
        Returns combined result with confidence comparison.
        """
        if not self.ai or not self.ai._providers:
            return {"error": "No AI providers available"}

        target_providers = providers or list(self.ai._providers.keys())

        # Fire all queries in parallel
        tasks = {}
        for name in target_providers:
            if name in self.ai._providers:
                tasks[name] = asyncio.create_task(
                    self._safe_query(name, prompt, task_type, max_tokens)
                )

        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await task
            except Exception as e:
                results[name] = {"error": str(e), "response": None}

        # Analyze consensus
        analysis = self._analyze_consensus(results)

        return {
            "individual_results": results,
            "consensus": analysis,
            "providers_queried": len(tasks),
            "providers_responded": sum(
                1 for r in results.values()
                if r.get("response") is not None
            ),
        }

    async def _safe_query(
        self, provider: str, prompt: str,
        task_type: str, max_tokens: int,
    ) -> Dict[str, Any]:
        """Query a single provider safely."""
        start = time.time()
        try:
            response = await self.ai.query(
                prompt, task_type=task_type,
                provider_name=provider, max_tokens=max_tokens,
            )
            elapsed = time.time() - start
            return {
                "response": response,
                "latency": round(elapsed, 2),
                "provider": provider,
            }
        except Exception as e:
            return {
                "response": None,
                "error": str(e),
                "latency": round(time.time() - start, 2),
                "provider": provider,
            }

    def _analyze_consensus(
        self, results: Dict[str, Dict]
    ) -> Dict[str, Any]:
        """Analyze consensus across multiple model outputs."""
        responses = [
            r["response"] for r in results.values()
            if r.get("response")
        ]

        if not responses:
            return {"agreement": 0.0, "unified_result": None}

        if len(responses) == 1:
            return {
                "agreement": 1.0,
                "unified_result": responses[0],
                "hallucination_risk": "unknown",
            }

        # Simple similarity check via keyword overlap
        keyword_sets = []
        for resp in responses:
            words = set(resp.lower().split())
            keyword_sets.append(words)

        # Pairwise Jaccard similarity
        similarities = []
        for i in range(len(keyword_sets)):
            for j in range(i + 1, len(keyword_sets)):
                a, b = keyword_sets[i], keyword_sets[j]
                if a | b:
                    sim = len(a & b) / len(a | b)
                    similarities.append(sim)

        avg_sim = (
            sum(similarities) / len(similarities)
            if similarities else 0.0
        )

        # Hallucination risk
        if avg_sim < 0.2:
            hallucination_risk = "high"
        elif avg_sim < 0.4:
            hallucination_risk = "medium"
        else:
            hallucination_risk = "low"

        # Pick the longest response as "most complete"
        best = max(responses, key=len)

        return {
            "agreement": round(avg_sim, 4),
            "unified_result": best,
            "hallucination_risk": hallucination_risk,
            "responses_compared": len(responses),
        }
