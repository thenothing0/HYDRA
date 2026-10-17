---
title: Web3 Smart Contract Audit
description: Autonomous smart contract security analysis skill
---

# Web3 Smart Contract Audit Skill

## Purpose
Analyze Solidity/Vyper smart contracts for security vulnerabilities using HYDRA's Web3 engine.

## Capabilities
- **Reentrancy Detection**: Identifies external calls before state updates
- **Flash Loan Analysis**: Detects flash loan interaction patterns
- **Oracle Manipulation**: Finds price oracle dependencies
- **Access Control**: Checks for missing/weak access modifiers
- **DeFi Patterns**: Common DeFi vulnerability patterns (sandwich, governance, approval)
- **Token Compliance**: ERC20/ERC721 standard compliance checks

## Usage
```
/web3-audit contracts/Vault.sol
/web3-audit contracts/ --recursive
/token-scan 0xAbCd...
```

## Safety
- Only analyze contracts you have permission to audit
- Never deploy or interact with mainnet contracts during testing
- Report findings through proper channels
