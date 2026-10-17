# Contributing to HYDRA

Thank you for your interest in contributing to HYDRA! We welcome contributions of all kinds.

## 🚀 Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/yourusername/hydra.git`
3. **Create a branch**: `git checkout -b feature/amazing-feature`
4. **Install dependencies**: `pip install -r requirements.txt`
5. **Run tests**: `pytest tests/`

## 📋 What We Need

### High Priority
- **New agent types** — Specialized agents for different target domains
- **Tool integrations** — Add new security tools to `TOOL_REGISTRY` in `hydra/mcp/tool_server.py`
- **Workflow templates** — Pre-built scan profiles in `hydra/workflows/`
- **Bug bounty platform adapters** — Add platforms to `hydra/scope/`
- **Hunt strategies** — New vuln-class strategies in `hydra/hunt/strategies.py`

### Medium Priority
- **Exploit chain patterns** — Add chain patterns to `hydra/chains/`
- **RAG writeup corpus** — Contribute public writeup sources
- **Plugin development** — Create plugins for `hydra/plugins/`
- **Tests** — Expand test coverage in `tests/`
- **Documentation** — Improve docs and examples

### Low Priority
- **IDE provider bundles** — Add or improve IDE-specific configurations
- **Dashboard improvements** — Frontend enhancements
- **Performance optimization**

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_scope.py -v

# Run with coverage
pytest tests/ --cov=hydra --cov-report=html
```

## 📏 Code Standards

- **Python 3.10+**
- **Type hints** on all public functions
- **Docstrings** on all classes and public methods
- **Logging** via `logging.getLogger("hydra.<module>")`
- **No global state** — use dependency injection
- **Async-first** — use `async/await` for I/O-bound operations

## 🔒 Security

- **Never** commit API keys, tokens, or credentials
- **Never** bypass the `SecuritySandbox` or `ScopePolicyEngine`
- **All tools** must go through the MCP Tool Server
- **All findings** require evidence for reporting

## 📝 Pull Request Process

1. Update documentation if you change public APIs
2. Add tests for new functionality
3. Ensure all tests pass
4. Update `README.md` if you add new features
5. Describe your changes clearly in the PR description

## 🐛 Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, Python version, tool versions)

## ⚖️ License

By contributing, you agree that your contributions will be licensed under the MIT License.
