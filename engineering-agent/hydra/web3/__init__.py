"""
╔══════════════════════════════════════════════════════════════╗
║  Web3 Engine — Smart Contract Security Analysis             ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger("hydra.web3")


class SolidityAnalyzer:
    """Static analysis engine for Solidity smart contracts."""

    VULNERABILITY_CHECKS = {
        "reentrancy": {
            "patterns": [
                r"\.call\{value:", r"\.call\.value\(", r"msg\.sender\.call",
            ],
            "severity": "critical",
            "description": "External call before state update — potential reentrancy",
            "remediation": "Use checks-effects-interactions pattern or ReentrancyGuard",
        },
        "tx_origin": {
            "patterns": [r"tx\.origin"],
            "severity": "high",
            "description": "tx.origin used for authorization — vulnerable to phishing",
            "remediation": "Use msg.sender instead of tx.origin for auth checks",
        },
        "selfdestruct": {
            "patterns": [r"selfdestruct\(", r"suicide\("],
            "severity": "critical",
            "description": "selfdestruct can permanently destroy contract",
            "remediation": "Remove selfdestruct or add strict access control",
        },
        "delegatecall": {
            "patterns": [r"\.delegatecall\("],
            "severity": "high",
            "description": "delegatecall to potentially untrusted contract",
            "remediation": "Validate target address; avoid delegatecall to user input",
        },
        "unchecked_math": {
            "patterns": [r"unchecked\s*\{"],
            "severity": "medium",
            "description": "Unchecked arithmetic may overflow/underflow",
            "remediation": "Verify overflow is intentional; add bounds checks",
        },
        "block_timestamp": {
            "patterns": [r"block\.timestamp", r"block\.number"],
            "severity": "medium",
            "description": "Block-dependent values can be manipulated by miners",
            "remediation": "Avoid using block.timestamp for critical logic",
        },
        "hardcoded_address": {
            "patterns": [r"0x[a-fA-F0-9]{40}"],
            "severity": "low",
            "description": "Hardcoded address — may break on different networks",
            "remediation": "Use constructor parameters or configuration pattern",
        },
        "missing_access_control": {
            "patterns": [r"function\s+\w+\s*\([^)]*\)\s*public(?!\s+view|\s+pure)"],
            "severity": "high",
            "description": "Public function without access modifier",
            "remediation": "Add onlyOwner or role-based access control",
        },
    }

    def analyze(self, source_code: str, filename: str = "") -> Dict[str, Any]:
        """Analyze Solidity source code for vulnerabilities."""
        findings: List[Dict] = []

        for vuln_name, vuln_info in self.VULNERABILITY_CHECKS.items():
            for pattern in vuln_info["patterns"]:
                matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
                for match in matches:
                    line_num = source_code[:match.start()].count("\n") + 1
                    findings.append({
                        "name": vuln_name,
                        "severity": vuln_info["severity"],
                        "description": vuln_info["description"],
                        "remediation": vuln_info["remediation"],
                        "file": filename,
                        "line": line_num,
                        "matched_text": match.group()[:100],
                        "confidence": 0.7,
                    })

        return {
            "file": filename,
            "total_findings": len(findings),
            "findings": findings,
            "lines_analyzed": source_code.count("\n") + 1,
        }


class DeFiPatternDetector:
    """Detects common DeFi vulnerability patterns."""

    PATTERNS = {
        "flash_loan_attack": {
            "indicators": ["flashLoan", "flash_loan", "IFlashLoanReceiver",
                          "FlashBorrower", "executeOperation"],
            "description": "Flash loan interaction — verify price oracle integrity",
        },
        "oracle_manipulation": {
            "indicators": ["getPrice", "latestAnswer", "getRoundData",
                          "oracle", "priceFeed", "getReserves", "slot0"],
            "description": "Price oracle dependency — check for TWAP or manipulation",
        },
        "sandwich_attack": {
            "indicators": ["swap", "swapExact", "addLiquidity", "removeLiquidity",
                          "getAmountsOut", "getAmountOut"],
            "description": "DEX interaction vulnerable to sandwich attacks",
        },
        "governance_attack": {
            "indicators": ["propose", "vote", "execute", "timelock",
                          "quorum", "GovernorBravo"],
            "description": "Governance mechanism — check for flash loan governance",
        },
        "approval_abuse": {
            "indicators": ["approve", "transferFrom", "allowance",
                          "increaseAllowance", "type(uint256).max"],
            "description": "Token approval pattern — check for unlimited approvals",
        },
    }

    def detect(self, source_code: str) -> List[Dict]:
        findings = []
        for pattern_name, info in self.PATTERNS.items():
            matched = [i for i in info["indicators"]
                      if i.lower() in source_code.lower()]
            if matched:
                findings.append({
                    "pattern": pattern_name,
                    "description": info["description"],
                    "matched_indicators": matched,
                    "confidence": min(0.3 + len(matched) * 0.15, 0.9),
                })
        return findings


class TokenScanner:
    """Scanner for ERC20/ERC721/ERC1155 token contracts."""

    COMPLIANCE_CHECKS = {
        "erc20": {
            "required": ["totalSupply", "balanceOf", "transfer",
                        "transferFrom", "approve", "allowance"],
            "events": ["Transfer", "Approval"],
        },
        "erc721": {
            "required": ["balanceOf", "ownerOf", "safeTransferFrom",
                        "transferFrom", "approve", "getApproved",
                        "setApprovalForAll", "isApprovedForAll"],
            "events": ["Transfer", "Approval", "ApprovalForAll"],
        },
    }

    def check_compliance(self, source_code: str,
                         standard: str = "erc20") -> Dict:
        checks = self.COMPLIANCE_CHECKS.get(standard, {})
        missing_functions = [f for f in checks.get("required", [])
                           if f not in source_code]
        missing_events = [e for e in checks.get("events", [])
                        if f"event {e}" not in source_code]
        return {
            "standard": standard,
            "compliant": not missing_functions and not missing_events,
            "missing_functions": missing_functions,
            "missing_events": missing_events,
        }
