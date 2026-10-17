# Archived HYDRA security-platform README

This is the historical repository README, preserved on 2026-10-17. Its phase,
capability and test counts describe an earlier security/knowledge platform;
they are not current engineering-agent release claims. Start with the current
[main README](README.md) for installation and the general-purpose agent.

---

> **General engineering runtime:** the independently tested HYDRA engineering agent, browser extensions and architecture cleanup are available in [`engineering-agent/`](engineering-agent/README.md). Run its commands from that directory; the existing security/knowledge platform remains separate.

<p align="center">
  <img src="https://img.shields.io/badge/HYDRA-Offensive_Knowledge_OS-00ff88?style=for-the-badge&labelColor=000000" alt="HYDRA"/>
  <img src="https://img.shields.io/badge/Phase-O_·_Temporal_Intelligence-blueviolet?style=for-the-badge&labelColor=000000" alt="Phase O"/>
  <img src="https://img.shields.io/badge/MCP_Tools-108-orange?style=for-the-badge&labelColor=000000" alt="MCP Tools"/>
  <img src="https://img.shields.io/badge/Capabilities-153_effective-ff6600?style=for-the-badge&labelColor=000000" alt="Capabilities"/>
  <img src="https://img.shields.io/badge/Adapters-439-00aaff?style=for-the-badge&labelColor=000000" alt="Adapters"/>
  <img src="https://img.shields.io/badge/Tests-499_green-brightgreen?style=for-the-badge&labelColor=000000" alt="Tests"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&labelColor=000000" alt="License"/>
</p>

<h1 align="center">👁️‍🗨️ HYDRA — Offensive Knowledge Operating System</h1>
<h3 align="center">A cognitive, capability-first, <em>advisory</em> red-team knowledge platform</h3>

<p align="center">
  <b>Deterministic · Offline-first · Rebuild-identical · Canonical-wiki-centered · Federation-safe</b><br/>
  <sub>THENOTHING v7.1 — Claude Code Mode · Knowledge OS Phases A → O</sub>
</p>

---

> **HYDRA** turns offensive-security research into a *machine-operable, self-improving knowledge system*.
> It **reasons before it executes**, **simulates before it interacts**, learns from every outcome, and
> now — with **Phase O** — understands **how its own knowledge evolves over time**. Every intelligence
> layer is **derived, deterministic, and advisory**: the canonical wiki, the promotion rules, and the
> confidence engine are never silently mutated.
>
> 📄 A full, comprehensive design document is available as **`HYDRA_Project_Documentation.pdf`**.

## 📑 Table of Contents

- [Project Overview](#-project-overview)
- [Architecture Highlights](#-architecture-highlights)
- [Current Phase — O: Temporal Knowledge Intelligence](#-current-phase--o-temporal-knowledge-intelligence)
- [Key Features](#-key-features)
- [The Seven Agents](#-the-seven-agents)
- [MCP Tools (108)](#-mcp-tools-108)
- [Architecture Invariants](#-architecture-invariants)
- [System Inventory](#-system-inventory)
- [Data Flow](#-data-flow)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Layout](#-project-layout)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌐 Project Overview

HYDRA is an **Offensive Knowledge Operating System** — a layered, pure-Python platform that an LLM
operator (via the **Model Context Protocol**) uses to perform high-quality bug-bounty and offensive
security **research within explicit authorization**.

The system is built bottom-up across **15 locked phases (A → O)**. Each phase adds a *derived,
advisory* intelligence layer on top of a single **canonical knowledge store** (the wiki). Nothing
below the wiki ever writes back to it except through explicit, propose-only paths.

| | |
|---|---|
| **Current Phase** | **O — Temporal Knowledge Intelligence** |
| **Capabilities** | 87 core · **153 effective** (with plugins) |
| **Adapters** | 175 core · **439 effective** |
| **Agents** | **7** specialized agents |
| **Plugins** | **6** reference packs |
| **MCP Tools** | **108** |
| **Tests** | **499 passing** (6 integration deselected) |
| **License** | MIT |

---

## 🏗 Architecture Highlights

HYDRA's nine-phase reasoning loop —
`Observe → Understand → Reason → Simulate → Plan → Execute → Validate → Learn → Replan` —
sits on top of a stack of **derived, deterministic** subsystems:

```
                ┌──────────────────────────────────────────┐
                │   CANONICAL WIKI  (single source of truth) │  ← promotion.py / confidence.py (frozen)
                └───────────────────┬──────────────────────┘
                                    │ rebuild (read-only, one-way)
        ┌──────────────┬────────────┼────────────┬──────────────┬──────────────┐
        ▼              ▼            ▼            ▼              ▼              ▼
   LEARNING        GOVERNANCE    RUNTIME    SIMULATION     FEDERATION     TEMPORAL (Phase O)
   (source,        (health,      (workflow  (forecast,     (metadata-     (trends, decay,
    verif, tool,    drift, QA)    state)     strategy)      only digests)  momentum, anomaly)
    plugin)
```

- **Capability-first** — everything is a *capability* (e.g. `subdomain_discovery`), realized by
  interchangeable *tools* via *adapters*.
- **Derived & rebuildable** — every learning/intelligence store is a pure function of an append-only
  event log; delete it and it rebuilds identically.
- **Advisory-only** — simulation, governance, federation, and temporal layers *recommend*; they never
  execute, confirm, promote, or exploit.
- **Offline-first & deterministic** — given a fixed injected clock, outputs are byte-identical.

---

## 🕒 Current Phase — O: Temporal Knowledge Intelligence

Phase O (package `hydra/temporal_intel/`) makes HYDRA understand **how its knowledge changes over
time**, built entirely from the existing derived event logs — no new canonical data.

| Capability | What it does |
|---|---|
| **Trends** | rising / stable / declining per capability, adapter, agent, plugin, source, verification |
| **Momentum** | growth/decline momentum + acceleration/deceleration |
| **Decay** | stale capabilities/adapters/plugins/verification methods, severity-ranked, with suggested actions |
| **Forecasts** | bounded, **non-stochastic** projections of utilization, verification coverage, source diversity, plugin adoption |
| **Anomalies** | spikes, drops, inactivity, concentration (advisory findings, no alerts) |
| **Health** | a 0–100 temporal-health score, surfaced read-only inside governance |

> ⚡ **Performance:** O(E), **9.35 s at 1,000,000 rows (2M derived events)** — under the 10 s target,
> with a load-once `TemporalContext` and memoized bucketing. Deterministic and rebuild-identical.

---

## ✨ Key Features

- 🧠 **Cognitive reasoning loop** — observe → … → replan, with simulation before execution.
- 📚 **Machine-operable wiki** — the single canonical knowledge store (targets, techniques, assets, reports, intel, patterns, chains, findings).
- 🔭 **Recon fusion** — multi-source Asset Intelligence with a Two-Signal confidence rule.
- 🧩 **Capability + Adapter framework** — 153 capabilities × interchangeable tools = 439 SAFE-profile adapters.
- 🤖 **Multi-agent orchestration** — 7 agents route `Target → Agent → Capability → Tool`.
- 🔁 **Self-improving learning** — source/verification/tool/plugin learning stores improve prioritization over time.
- 🔮 **Decision simulation** — forecast a plan's outcome *before* running it.
- 🩺 **Governance & drift** — continuous health/freshness/consistency scoring.
- 🛰 **Federation** — exchange anonymized, **metadata-only** intelligence digests between HYDRA instances.
- 🕒 **Temporal intelligence** — trends, decay, momentum, forecasts, anomalies (Phase O).
- 🔒 **Invariant-preserving** — promotion/confidence are immutable; discovery is propose-only; no autonomous exploitation.

---

## 🤖 The Seven Agents

Introduced in **Phase H** (declarative agents) and made executable-as-*state* in **Phase I**
(runtime), the agents form a deterministic routing layer: a target is routed to the right
**agent**, which owns a set of capability **categories**, each realized by a learning-selected
**tool/adapter**. Agents **never execute tools, confirm findings, or write the wiki** — they plan
and route; the runtime tracks state only.

| Agent | Priority | Owns categories | Responsibility | Expected outputs |
|---|---|---|---|---|
| 🛰 **recon_agent** | 10 | reconnaissance, infrastructure | Discover & map the external attack surface — subdomains, DNS, ASN/CIDR, ports, services, tech, TLS. | subdomain, dns_record, ip, asn, open_port, service, technology, host |
| 🕸 **attack_surface_agent** | 8 | web, api | Enumerate the web/API surface and probe for vulnerability *candidates* (advisory). | endpoint, parameter, url, xss, sqli, ssrf, graphql, vulnerability |
| ☁️ **cloud_agent** | 7 | cloud, secrets, source_code | Discover cloud assets, leaked secrets, and source-code / dependency exposures. | cloud_bucket, cloud_misconfig, secret, credential, repository, dependency_vuln |
| ✅ **verification_agent** | 6 | verification | Validate suspected findings using verification playbooks — **never auto-confirms**. | idor, ssrf, auth_bypass, open_redirect, csrf, xss, sqli, takeover |
| 📱 **mobile_agent** | 6 | mobile | Static-analyze mobile apps (APKs): secret/endpoint extraction, deeplink & cert-pinning checks. *(Added in Phase I — closes capability ownership to 87/87.)* | mobile_finding, secret, credential, endpoint, internal_host, deeplink, cert_pinning |
| 🔗 **correlation_agent** | 5 | *(cross-cutting)* | Correlate findings + report-intel into **patterns and chains** — propose-only; promotion rules unchanged. | pattern, chain |
| 📝 **reporting_agent** | 3 | *(cross-cutting)* | Synthesize **confirmed** knowledge into structured bug-bounty reports. | report |

**How they interact with the stack:**

```
Target ──▶ agent_route ──▶ Agent ──▶ Capability (category-owned) ──▶ Tool (learning-selected)
                                          │                              │
                                          ▼                              ▼
                                   Adapter (SAFE profile)        tool_health learning
                                          │
                                          ▼
                                  Runtime Engine (workflow STATE only — no execution)
```

Agent quality is observable via `agent_coverage` (orphans/overlaps/bottlenecks) and
`agent_effectiveness` (Phase-L multi-agent simulation). Ownership of the full effective catalog is
**153/153 with zero gaps or conflicts**.

---

## 🛠 MCP Tools (108)

All tooling is exposed to the LLM operator through the **`hydra-security`** MCP server
(`python mcp_server.py`). Highlights by layer:

| Layer (Phase) | Example tools |
|---|---|
| **Recon & Surface** | `subfinder_scan`, `httpx_probe`, `katana_crawl`, `gau_urls`, `dnsx_resolve`, `full_recon` |
| **Vuln / Fuzz** | `nuclei_scan`, `sqlmap_scan`, `dalfox_scan`, `ffuf_fuzz`, `dirsearch_scan` |
| **Knowledge OS (A–C)** | `recon_fuse`, `kb_recall`, `ingest_report`, `discover_patterns`, `discover_chains`, `confirm_candidate` |
| **Learning & Ranking (D–F)** | `source_scores`, `rank_opportunities`, `select_sources`, `recon_plan`, `verification_playbook` |
| **Capabilities & Agents (G–H)** | `capability_catalog`, `rank_tools`, `agent_plan`, `agent_route`, `agent_coverage` |
| **Runtime & Governance (I–J)** | `workflow_create`, `runtime_summary`, `governance_summary`, `drift_report`, `knowledge_health` |
| **Adapters & Simulation (K–L)** | `adapter_catalog`, `adapter_select`, `simulate_workflow`, `predict_outcome`, `decision_health` |
| **Marketplace (M)** | `plugin_catalog`, `capability_graph`, `agent_ownership`, `ecosystem_summary` |
| **Federation (N)** | `federation_peers`, `export_digest`, `import_digest`, `capability_trends`, `federation_consensus` |
| **Temporal (O)** | `temporal_summary`, `temporal_trends`, `temporal_forecast`, `temporal_decay`, `temporal_anomalies`, `temporal_health` |

> A committed contract baseline (`tests/mcp/tool_contract_baseline.json`) and a CLAUDE.md doc-sync
> test guard against tool-registry drift — code and docs cannot diverge silently.

---

## 🔒 Architecture Invariants

These are **enforced and continuously verified**:

- 📖 **Wiki is the single canonical source** — no second canonical source, **no dual-write**.
- 🧊 **`promotion.py` and `confidence.py` are immutable** (last touched in Phase A).
- 🔍 **Discovery is propose-only** — no autonomous confirmation or promotion.
- ♻️ **Learning is derived, disposable, event-sourced, rebuild-identical.**
- 🌐 **Offline-first & deterministic.**
- 🧭 **Advisory-only intelligence** — no autonomous exploitation, no offensive execution, no hidden confidence changes.
- 🧩 **SAFE adapter profiles only** (offline / passive / validation / simulation).
- 🛰 **Federation exchanges metadata only** — never findings, evidence, targets, sources, or secrets.
- 🔌 **Plugins are declarative** — no plugin execution.
- ➕ **MCP is additive & backward-compatible.**

---

## 📦 System Inventory

| Class | Items |
|---|---|
| **Core capabilities** | 87 |
| **Effective capabilities** | 153 (core + 6 plugin packs) |
| **Adapters** | 175 core · 439 effective |
| **Agents** | 7 |
| **Plugins** | cloud, mobile, container, iot, supply_chain, osint |
| **Learning stores** | `source_learning`, `source_metrics`, `verification_learning`, `tool_health`, `plugin_health` |
| **Intelligence stores** | `decision_learning`, `temporal` *(Phase O)* |
| **Runtime store** | `workflows` |
| **Governance store** | `knowledge_governance` |
| **Federation store** | `federation` |
| **Canonical index** | `knowledge_index` (rebuildable from the wiki) |

All `data/*.db` stores are **derived, disposable, gitignored**, and rebuildable from their event logs.

---

## 🔀 Data Flow

```
recon-fusion ─┐                                   ┌─ ingest_report / confirm_candidate
              ▼                                   ▼   (explicit, propose-only writers)
        ┌──────────────────────── CANONICAL WIKI ───────────────────────┐
        │            promotion.py · confidence.py  (frozen)             │
        └───────────────────────────────┬──────────────────────────────┘
                                         │ rebuild (read-only)
                                         ▼
                              knowledge_index.db (graph)
                                         │ read-only
   ┌───────────────┬───────────────┬─────┴─────────┬───────────────┬───────────────┐
   ▼               ▼               ▼               ▼               ▼               ▼
LEARNING       GOVERNANCE       RUNTIME        SIMULATION      FEDERATION       TEMPORAL
 stores         snapshots        state          forecasts       digests          trends/decay
   └─ every arrow below the wiki is READ-ONLY derived; nothing writes back to canonical
```

---

## ⚙️ Installation

> **Requirements:** Python ≥ 3.10 (3.13 recommended), Kali-style tooling optional for live recon.

```bash
# 1) clone
git clone <your-fork-url> hydra && cd hydra

# 2) install
pip install -r requirements.txt
pip install -r requirements-dev.txt      # tests, linters

# 3) sanity check
python -m pytest -q                       # 499 passing (6 integration deselected)
python mcp_server.py --help               # MCP server entrypoint
```

**MCP server registration** (already provided as `.mcp.json` for Claude Code):

```json
{ "mcpServers": { "hydra-security": { "command": "python", "args": ["mcp_server.py"] } } }
```

For **remote / SSE** transport: `python mcp_server.py --transport sse --port 8900`.

---

## 🚀 Usage

### Via MCP (recommended)
Point any MCP-compatible client (Claude Code, Cursor, Cline) at `hydra-security`, then call tools:

```text
temporal_summary                  # how is knowledge evolving?
temporal_forecast domain=capability
agent_plan target=example.com type=web_app
recon_plan target=example.com
governance_summary                # now includes a temporal_intelligence block
```

### Via CLI workflows

```bash
python -m hydra.main -t example.com -w bounty_hunt        # autonomous campaign
python -m hydra.main -t example.com -w cognitive_auto     # full cognitive pipeline
python -m hydra.main -t example.com -w quick_recon        # fast recon
python -m hydra.main -t example.com -w cognitive_auto --scope-url https://hackerone.com/example
```

> ⚖️ **Authorization required.** HYDRA performs research only within explicit program scope / written
> authorization. Out-of-scope testing is prohibited (`scope.txt` is checked first).

---

## 🗂 Project Layout

```
hydra/
├── knowledge/        # canonical wiki, promotion.py, confidence.py, governance, verification
├── capabilities/     # capability catalog, source/tool learning, selection
├── adapters/         # adapter framework + tool-health learning (Phase K)
├── agents/           # 7 agents + planner/registry (Phase H)
├── runtime/          # workflow engine — STATE only, no execution (Phase I)
├── intelligence/     # decision simulation & forecasting (Phase L)
├── plugins/          # declarative plugin ecosystem (Phase M)
├── federation/       # metadata-only knowledge exchange (Phase N)
└── temporal_intel/   # temporal knowledge intelligence (Phase O)  ← NEW
capabilities/         # YAML catalogs (capabilities, agents, tools, dependencies)
mcp_server.py         # 108 MCP tools
docs/                 # ADRs + HYDRA_SYSTEM_CONTEXT.md (architecture memory)
tests/                # 499 tests
```

---

## 🗺 Roadmap

| Phase | Theme | Status |
|---|---|---|
| A–G | Knowledge OS foundations → capability orchestration | ✅ |
| H–J | Multi-agent · runtime · governance | ✅ |
| K–M | Adapters · simulation · marketplace | ✅ |
| **N** | Federated knowledge exchange | ✅ |
| **O** | **Temporal knowledge intelligence** | ✅ **current** |
| P | Unified cross-store correlation layer | 🔜 next |
| Q–Z | Trust graph · reporting synthesis · compaction · multi-tenant · self-audit | 🧭 planned |

See [`docs/HYDRA_SYSTEM_CONTEXT.md`](docs/HYDRA_SYSTEM_CONTEXT.md) for the full lineage, risk
registry, and Phase-P→Z roadmap.

---

## 🤝 Contributing

Contributions are welcome! Before opening a PR:

1. **Read** [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), and
   [`docs/HYDRA_SYSTEM_CONTEXT.md`](docs/HYDRA_SYSTEM_CONTEXT.md).
2. **Preserve every invariant** — never modify `promotion.py`/`confidence.py`, never introduce a
   dual-write, never add autonomous execution/exploitation, keep new intelligence layers
   *derived + advisory + deterministic*.
3. **Test** — `python -m pytest -q` must stay green; new MCP tools require a regenerated contract
   baseline **and** a CLAUDE.md entry (doc-sync is enforced).
4. **Stay deterministic & rebuildable** — inject clocks, sort outputs, key learning by stable ids.

New phases follow the **Architecture Steward protocol**: design review → invariant/safety gate →
implementation → benchmarks → memory update.

> The original THENOTHING marketing README is preserved as [`README.thenothing.md`](README.thenothing.md).

---

## 📜 License

Released under the **MIT License** — see [`LICENSE`](LICENSE).

> **Ethical use only.** HYDRA is for authorized security testing, bug-bounty research, CTFs, and
> defensive work. You are responsible for operating within the law and within program scope.

<p align="center"><sub>HYDRA · THENOTHING v7.1 — cognitive, deterministic, advisory, canonical-wiki-centered offensive <b>research</b>.</sub></p>
