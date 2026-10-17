"""Tests for the Web3 / Solidity static-analysis engine."""

import pytest
from hydra.web3 import SolidityAnalyzer, DeFiPatternDetector, TokenScanner


VULN_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address owner = 0x1234567890abcdef1234567890abcdef12345678;

    function withdraw(uint256 amount) public {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function kill() public {
        selfdestruct(payable(owner));
    }

    function price() public view returns (uint256) {
        return block.timestamp;
    }
}
"""

CLEAN_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Counter {
    uint256 private _count;

    function increment() external {
        _count += 1;
    }

    function current() external view returns (uint256) {
        return _count;
    }
}
"""


class TestSolidityAnalyzer:
    def test_detects_reentrancy(self):
        result = SolidityAnalyzer().analyze(VULN_CONTRACT, "Vault.sol")
        names = {f["name"] for f in result["findings"]}
        assert "reentrancy" in names

    def test_detects_tx_origin_and_selfdestruct(self):
        result = SolidityAnalyzer().analyze(VULN_CONTRACT, "Vault.sol")
        names = {f["name"] for f in result["findings"]}
        assert "tx_origin" in names
        assert "selfdestruct" in names

    def test_findings_carry_line_numbers(self):
        result = SolidityAnalyzer().analyze(VULN_CONTRACT, "Vault.sol")
        assert result["total_findings"] > 0
        for f in result["findings"]:
            assert f["line"] >= 1
            assert f["file"] == "Vault.sol"
            assert f["severity"] in ("critical", "high", "medium", "low", "info")

    def test_clean_contract_has_no_critical(self):
        result = SolidityAnalyzer().analyze(CLEAN_CONTRACT, "Counter.sol")
        severities = {f["severity"] for f in result["findings"]}
        assert "critical" not in severities

    def test_empty_source(self):
        result = SolidityAnalyzer().analyze("", "empty.sol")
        assert result["total_findings"] == 0


class TestDeFiPatternDetector:
    def test_detects_oracle_pattern(self):
        src = "function p() public { uint x = oracle.latestAnswer(); }"
        findings = DeFiPatternDetector().detect(src)
        patterns = {f["pattern"] for f in findings}
        assert "oracle_manipulation" in patterns

    def test_no_false_positive_on_plain_code(self):
        findings = DeFiPatternDetector().detect("contract A { uint x; }")
        assert findings == []


class TestTokenScanner:
    def test_incomplete_erc20_flagged(self):
        src = "contract T { function totalSupply() public {} function balanceOf() public {} }"
        result = TokenScanner().check_compliance(src, "erc20")
        assert result["compliant"] is False
        assert "transfer" in result["missing_functions"]

    def test_unknown_standard_returns_compliant(self):
        result = TokenScanner().check_compliance("contract X {}", "erc999")
        # No checks defined → nothing missing → compliant
        assert result["compliant"] is True
