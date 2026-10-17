"""
╔══════════════════════════════════════════════════════════════╗
║  AI Router — Multi-LLM Intelligent Routing Layer            ║
║  Selects the best model per task automatically              ║
╚══════════════════════════════════════════════════════════════╝

Supported providers:
  - OpenAI GPT (gpt-4o, gpt-4o-mini)
  - Anthropic Claude (claude-sonnet)
  - Ollama local models (llama3, mistral, etc.)
  - Custom OpenAI-compatible APIs
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

from hydra.config import get_config, AIProviderConfig

logger = logging.getLogger("hydra.ai.router")


# Task type → preferred capabilities mapping
TASK_CAPABILITY_MAP = {
    "reasoning": ["reasoning", "code_analysis"],
    "exploit_hypothesis": ["reasoning", "exploit_analysis"],
    "cve_mapping": ["reasoning", "vuln_classification"],
    "report_generation": ["report_generation"],
    "scoring": ["fast_classification", "reasoning"],
    "classification": ["fast_classification"],
    "code_analysis": ["code_analysis"],
}


class AIRouter:
    """
    Routes AI requests to the best available provider.
    
    Selection strategy:
      1. Match task capabilities to provider capabilities
      2. Prefer lower-cost providers for simple tasks
      3. Fall back to local (Ollama) when cloud is unavailable
      4. Track latency and success rates for adaptive routing
    """
    
    def __init__(self):
        self.config = get_config()
        self._providers: Dict[str, AIProviderConfig] = {}
        self._clients: Dict[str, Any] = {}
        self._stats: Dict[str, Dict[str, float]] = {}
    
    async def initialize(self):
        """Initialize AI provider connections."""
        self._providers = self.config.get_enabled_providers()
        
        for name, provider in self._providers.items():
            self._stats[name] = {
                "requests": 0, "successes": 0, "failures": 0,
                "total_latency": 0.0, "total_tokens": 0,
            }
            logger.info(f"  ✅ AI provider: {name} ({provider.model})")
        
        if not self._providers:
            logger.warning("⚠️  No AI providers configured — AI features disabled")
        else:
            logger.info(f"🧠 AI Router initialized with {len(self._providers)} providers")
    
    def _select_provider(self, task_type: str) -> Optional[str]:
        """Select the best provider for a given task type."""
        if not self._providers:
            return None
        
        required_caps = TASK_CAPABILITY_MAP.get(task_type, ["reasoning"])
        
        candidates = []
        for name, provider in self._providers.items():
            # Score based on capability match
            cap_score = sum(1 for c in required_caps if c in provider.capabilities)
            if cap_score == 0:
                continue
            
            # Factor in cost (prefer cheaper for simple tasks)
            cost_score = 1.0 / (1.0 + provider.cost_per_1k_tokens)
            
            # Factor in historical performance
            stats = self._stats.get(name, {})
            total = stats.get("requests", 0)
            if total > 0:
                success_rate = stats["successes"] / total
                avg_latency = stats["total_latency"] / total
                perf_score = success_rate * (1.0 / (1.0 + avg_latency / 10.0))
            else:
                perf_score = 0.5  # neutral for untested providers
            
            final_score = cap_score * 0.4 + cost_score * 0.3 + perf_score * 0.3
            candidates.append((name, final_score))
        
        if not candidates:
            # Fallback to first available
            return next(iter(self._providers), None)
        
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]
    
    async def query(
        self,
        prompt: str,
        task_type: str = "reasoning",
        provider_name: Optional[str] = None,
        max_tokens: int = 2000,
        temperature: float = 0.3,
    ) -> Optional[str]:
        """
        Send a query to the best-suited AI provider.
        
        Args:
            prompt: The prompt to send
            task_type: Type of task for routing
            provider_name: Force a specific provider
            max_tokens: Maximum response tokens
            temperature: Sampling temperature
            
        Returns:
            Response text or None on failure
        """
        if not self._providers:
            return None
        
        name = provider_name or self._select_provider(task_type)
        if not name or name not in self._providers:
            return None
        
        provider = self._providers[name]
        start = time.time()
        
        try:
            result = await self._call_provider(
                name, provider, prompt, max_tokens, temperature
            )
            elapsed = time.time() - start
            
            self._stats[name]["requests"] += 1
            self._stats[name]["successes"] += 1
            self._stats[name]["total_latency"] += elapsed
            
            logger.debug(f"AI [{name}] responded in {elapsed:.1f}s")
            return result
            
        except Exception as e:
            elapsed = time.time() - start
            self._stats[name]["requests"] += 1
            self._stats[name]["failures"] += 1
            self._stats[name]["total_latency"] += elapsed
            logger.warning(f"AI [{name}] failed: {e}")
            
            # Try fallback providers
            for fallback_name in self._providers:
                if fallback_name != name:
                    try:
                        fb_provider = self._providers[fallback_name]
                        result = await self._call_provider(
                            fallback_name, fb_provider, prompt, max_tokens, temperature
                        )
                        self._stats[fallback_name]["requests"] += 1
                        self._stats[fallback_name]["successes"] += 1
                        return result
                    except Exception:
                        continue
            
            return None
    
    async def _call_provider(
        self,
        name: str,
        provider: AIProviderConfig,
        prompt: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        """Call a specific AI provider."""
        
        if name == "ollama":
            return await self._call_ollama(provider, prompt, max_tokens, temperature)
        elif name in ("openai", "custom"):
            return await self._call_openai_compatible(
                provider, prompt, max_tokens, temperature
            )
        elif name == "anthropic":
            return await self._call_anthropic(provider, prompt, max_tokens, temperature)
        else:
            # Try OpenAI-compatible API
            return await self._call_openai_compatible(
                provider, prompt, max_tokens, temperature
            )
    
    async def _call_ollama(
        self, provider: AIProviderConfig, prompt: str,
        max_tokens: int, temperature: float,
    ) -> str:
        """Call Ollama local model."""
        import aiohttp
        
        payload = {
            "model": provider.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{provider.base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=provider.timeout),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data.get("response", "")
    
    async def _call_openai_compatible(
        self, provider: AIProviderConfig, prompt: str,
        max_tokens: int, temperature: float,
    ) -> str:
        """Call OpenAI-compatible API (GPT, custom endpoints)."""
        import aiohttp
        
        headers = {"Content-Type": "application/json"}
        if provider.api_key:
            headers["Authorization"] = f"Bearer {provider.api_key}"
        
        payload = {
            "model": provider.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{provider.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=provider.timeout),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data["choices"][0]["message"]["content"]
    
    async def _call_anthropic(
        self, provider: AIProviderConfig, prompt: str,
        max_tokens: int, temperature: float,
    ) -> str:
        """Call Anthropic Claude API."""
        import aiohttp
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": provider.api_key,
            "anthropic-version": "2023-06-01",
        }
        
        payload = {
            "model": provider.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{provider.base_url}/messages",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=provider.timeout),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                content = data.get("content", [{}])
                return content[0].get("text", "") if content else ""
    
    def get_stats(self) -> Dict[str, Any]:
        """Return routing statistics."""
        return {
            name: {
                **stats,
                "avg_latency": (
                    round(stats["total_latency"] / stats["requests"], 2)
                    if stats["requests"] > 0 else 0
                ),
                "success_rate": (
                    round(stats["successes"] / stats["requests"], 3)
                    if stats["requests"] > 0 else 0
                ),
            }
            for name, stats in self._stats.items()
        }
