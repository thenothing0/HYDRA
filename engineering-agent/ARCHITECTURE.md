# HYDRA architecture and maintenance boundaries

The public command is `python -m hydra`, or `run.ps1` on Windows. Engineering is
the default runtime; security is an explicit optional runtime. Existing security
flags and `hydra.main` imports remain compatible.

```powershell
.\run.ps1 --help
.\run.ps1 engineering --help
.\run.ps1 security --help
.\run.ps1 security --list-workflows
.\run.ps1 security -t hydra/config.py -w code_review --no-ai --no-learn
```

## Components

| Responsibility | Location | Contract |
| --- | --- | --- |
| Command routing | `hydra/cli.py` | Explicit runtime names; compatibility for recognized security flags; no engine initialization while routing |
| Environment and settings | `hydra/config.py` | Lazy `.env` loading, process environment precedence, per-instance defaults, cached settings snapshot |
| Agent lifecycle | `hydra/engineering/agent.py` | Bounded observe/action/verify loop; only enabled session tools accepted |
| Terminal presentation | `hydra/engineering/tui/` | Textual widgets over an independent controller; asynchronous approval uses the same process boundary |
| Tool registry | `hydra/engineering/registry.py` | Named capability ownership, duplicate refusal, defensive schema copies, dispatch |
| Capability packs | `hydra/engineering/capabilities/` | File, process, session and opt-in browser handlers own their tool contracts |
| Process execution | `hydra/engineering/process.py` | Authorized argv execution, bounded output, timeout and cancellation cleanup |
| Workspace and durability | `hydra/engineering/workspace.py`, `session.py` | Path guards, instruction checks, edit conflicts, durable sessions, verification and rollback |
| Browser transport | `hydra/browser/`, `extensions/hydra-browser/` | Authenticated loopback bridge and explicitly paired tabs |
| Security lifecycle | `hydra/security/engine.py` | Scope gates, initialization, tool boundary and workflow lifecycle |
| Security workflows | `hydra/security/discovery.py`, `local.py`, `investigation.py`, `swarm.py` | Related workflow implementations over engine-owned state |
| Security results | `hydra/security/results.py` | Learning/enrichment, engagement, chains and reports |
| Security presentation | `hydra/security/parser.py`, `console.py`, `cli.py` | Argument parsing, rendering, process exit codes |
| Confirmation evidence | `hydra/hunt/confirm.py`, `confirmation/` | Stable public engine/result API; separated evidence models, signatures and related check groups |

Security workflow/check groups are internal mixins over their respective engine
state, not independent plugins or services. Their existing checks and scope
boundaries were preserved during extraction. All confirmation requests still go
through `SafeProber`. The engineering runtime does not import or automatically
enable the security runtime. The architectural tests enforce these import edges
and prevent circular imports from confirmation components back into the facade.

## Settings lifecycle

Importing `hydra.config` defines settings and paths. It neither reads `.env` nor
creates storage directories. `load_environment()` loads the project `.env`
explicitly; `get_config()` lazily constructs and caches the shared settings
snapshot. A direct `HydraConfig()` creates a fresh snapshot. Dataclass environment
defaults are evaluated when the instance is constructed, so an earlier import
cannot freeze them. A failed initialization is not cached.

`reset_config()` clears the snapshot cache for tests or deliberate runtime
reconfiguration. It does not remove variables already loaded into the process
environment. Storage is created explicitly at the security CLI boundary or by
the subsystem that owns it. Provider resolution uses environment loading and
shared default-model definitions without constructing unrelated security settings.
Inspection output omits connection passwords; connection methods retain the
credentials needed to authenticate.

## Adding tools

Each engineering capability owns its `SCHEMAS` and handler. Register its class
once in the module-level `CAPABILITIES` mapping in `hydra/engineering/tools.py`.
The facade builds a separate registry for each session. Browser handlers are
registered only for a browser-enabled session; interaction and read-only gates
remain outside the model. Do not put new cross-capability dispatch branches into
the agent. New capabilities must define their permission checks and integration
tests before being enabled. This registry is an internal Python extension point;
it does not load arbitrary third-party plugins.

## Deployment defaults

Compose is development scaffolding. Published ports now bind to loopback,
PostgreSQL and Grafana require operator-supplied passwords, PostgreSQL connection
settings are forwarded to dependent services, and workers have no fixed container
name or shared hardcoded node ID; an unspecified node ID uses the hostname and
process ID. The dashboard's direct-process default also
binds to loopback. Docker build exclusions now cover `.venv`, `.hydra`, local MCP
configuration, environment variants, output and bundled unrelated archives.
Existing `.env` files were not rewritten; replace any old example passwords
before using that infrastructure.

Docker is unavailable on the development machine, so Compose was structurally
checked but images/services were not started. Floating image/tool versions,
distributed transport policy review and full production deployment validation
remain outstanding. These changes do not establish production readiness.

## Validation and remaining limits

`tests/test_architecture.py` checks routing without runtime initialization,
configuration side effects and recovery, provider/settings independence, registry
ownership, capability-limited model actions and read-only process enforcement.
Existing scope, confirmation, session, process and provider tests remain required.
The CI suite runs once with coverage, checks extension protocol/build output, and
treats undefined-name and extracted-component import checks as required failures.

Local results are recorded in `output/architecture-tests.xml` and
`output/browser-e2e.json`. No paid API, external security target or user browser
profile is needed for these checks. Model quality and provider account access
still require live validation. Firefox runtime validation, OS-level isolation,
native tool-call streaming, financial budgets and matched-task AlphaCode
benchmarks remain separate work. A passing suite is evidence of the tested
contracts, not a guarantee that the entire repository is defect-free.
