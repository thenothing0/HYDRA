"""
╔══════════════════════════════════════════════════════════════╗
║  Web3 Security Agent — Smart Contract Analysis              ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
from typing import Any, Dict

from hydra.swarm.base_agent import BaseAgent
from hydra.memory.bus import Task

logger = logging.getLogger("hydra.agent.web3")


class Web3SecurityAgent(BaseAgent):
    AGENT_TYPE = "web3_specialist"
    AGENT_NAME = "Web3 Security Agent"

    VULN_PATTERNS = {
        "reentrancy": {
            "patterns": ["call.value", "call{value:", ".call(", "msg.sender.call"],
            "severity": "critical",
            "description": "Reentrancy vulnerability — external call before state update",
        },
        "unchecked_return": {
            "patterns": [".send(", ".transfer(", ".call("],
            "severity": "high",
            "description": "Unchecked return value from low-level call",
        },
        "tx_origin": {
            "patterns": ["tx.origin"],
            "severity": "high",
            "description": "tx.origin used for authorization instead of msg.sender",
        },
        "selfdestruct": {
            "patterns": ["selfdestruct(", "suicide("],
            "severity": "critical",
            "description": "Selfdestruct can destroy contract permanently",
        },
        "delegatecall": {
            "patterns": ["delegatecall("],
            "severity": "high",
            "description": "Delegatecall to untrusted contract",
        },
        "integer_overflow": {
            "patterns": ["unchecked {", "unchecked{"],
            "severity": "high",
            "description": "Potential integer overflow in unchecked block",
        },
        "access_control": {
            "patterns": ["onlyOwner", "require(msg.sender", "modifier"],
            "severity": "critical",
            "description": "Missing or weak access control",
        },
        "flash_loan": {
            "patterns": ["flashLoan", "flash_loan", "IFlashLoanReceiver"],
            "severity": "high",
            "description": "Flash loan interaction — check for manipulation",
        },
        "oracle_manipulation": {
            "patterns": ["getPrice", "latestAnswer", "getRoundData", "oracle"],
            "severity": "critical",
            "description": "Price oracle dependency — check for manipulation",
        },
        "front_running": {
            "patterns": ["block.timestamp", "block.number", "blockhash"],
            "severity": "medium",
            "description": "Block-dependent logic vulnerable to front-running",
        },
    }

    async def execute(self, task: Task) -> Dict[str, Any]:
        target = task.payload.get("target", "")
        contract_source = task.payload.get("source", "")
        self.logger.info(f"🔗 Web3 analysis: {target}")

        results = {
            "agent": self.AGENT_TYPE, "target": target,
            "findings": [], "patterns_checked": list(self.VULN_PATTERNS.keys()),
        }

        if contract_source:
            for vuln_name, vuln_info in self.VULN_PATTERNS.items():
                for pattern in vuln_info["patterns"]:
                    if pattern.lower() in contract_source.lower():
                        results["findings"].append({
                            "name": vuln_name,
                            "severity": vuln_info["severity"],
                            "description": vuln_info["description"],
                            "matched_pattern": pattern,
                            "confidence": 0.6,
                        })
                        break

        return results
