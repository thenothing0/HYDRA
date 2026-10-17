"""Behavioral boundaries for the unified CLI, settings and capability registry."""

import ast
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hydra.cli import route
from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "argv,runtime,arguments",
    [
        (["security", "--help"], "security", ["--help"]),
        (["engineering", "run", "goal"], "engineering", ["run", "goal"]),
        (["run", "goal"], "engineering", ["run", "goal"]),
        (["--list-workflows"], "security", ["--list-workflows"]),
        (["--target=example.com"], "security", ["--target=example.com"]),
        (["-texample.com"], "security", ["-texample.com"]),
        (["--unknown"], "engineering", ["--unknown"]),
        (["--help"], "engineering", ["--help"]),
    ],
)
def test_router_uses_explicit_names_and_known_legacy_options(argv, runtime, arguments):
    original = list(argv)
    assert route(argv) == (runtime, arguments)
    assert argv == original


def test_cli_router_does_not_initialize_either_runtime():
    command = "import sys; from hydra.cli import route; route(['security', '--help']); route(['--list-workflows']); assert 'hydra.security.engine' not in sys.modules; assert 'hydra.config' not in sys.modules; assert 'hydra.engineering.agent' not in sys.modules"
    subprocess.run(
        [sys.executable, "-c", command], cwd=ROOT, check=True, capture_output=True
    )


@pytest.mark.parametrize("command", ["security", "engineering"])
def test_explicit_runtime_help(command):
    result = subprocess.run(
        [sys.executable, "-m", "hydra", command, "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert ("--target" if command == "security" else "providers") in result.stdout


def test_importing_settings_has_no_environment_or_storage_side_effects(tmp_path):
    package = tmp_path / "hydra"
    package.mkdir()
    config = package / "config.py"
    config.write_text(
        (ROOT / "hydra/config.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / ".env").write_text("HYDRA_IMPORT_TEST_MARKER=must-not-be-loaded\n")
    command = "import os,runpy,sys; from pathlib import Path; os.environ['MCP_PORT']='invalid-before-runtime'; runpy.run_path(sys.argv[1]); assert 'HYDRA_IMPORT_TEST_MARKER' not in os.environ; assert not (Path(sys.argv[1]).parents[1]/'data').exists()"
    environment = {
        k: v for k, v in os.environ.items() if k != "HYDRA_IMPORT_TEST_MARKER"
    }
    subprocess.run(
        [sys.executable, "-c", command, str(config)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=True,
    )


def test_settings_snapshot_refresh_and_failure_recovery(monkeypatch):
    from hydra.config import get_config, reset_config

    reset_config()
    try:
        monkeypatch.setenv("MCP_PORT", "invalid-port")
        with pytest.raises(ValueError):
            get_config()
        monkeypatch.setenv("MCP_PORT", "17891")
        first = get_config()
        monkeypatch.setenv("MCP_PORT", "17892")
        assert get_config() is first
        assert first.mcp.port == 17891
        reset_config()
        assert get_config().mcp.port == 17892
    finally:
        reset_config()


def test_provider_settings_do_not_construct_security_configuration(monkeypatch):
    from hydra.engineering.providers import settings

    monkeypatch.setenv("MCP_PORT", "not-a-security-runtime")
    monkeypatch.setenv("OLLAMA_MODEL", "local-fixture")
    assert settings("ollama").model == "local-fixture"


def test_configuration_inspection_omits_password(monkeypatch):
    from hydra.config import HydraConfig

    monkeypatch.setenv("REDIS_PASSWORD", "private-fixture-value")
    config = HydraConfig()
    assert "private-fixture-value" not in json.dumps(config.to_dict())
    assert "private-fixture-value" not in repr(config.redis)


def test_unspecified_node_ids_are_distinct_across_processes(tmp_path):
    package = tmp_path / "hydra"
    package.mkdir()
    config = package / "config.py"
    config.write_text(
        (ROOT / "hydra/config.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    environment = {k: v for k, v in os.environ.items() if k != "HYDRA_NODE_ID"}
    command = "import runpy,sys; c=runpy.run_path(sys.argv[1]); print(c['get_config']().node_id)"

    def identity():
        return subprocess.check_output(
            [sys.executable, "-c", command, str(config)], env=environment, text=True
        ).strip()

    assert identity() != identity()
    environment["HYDRA_NODE_ID"] = "operator-selected-node"
    assert identity() == "operator-selected-node"


def test_registry_ownership_and_defensive_contracts():
    registry = ToolRegistry()

    async def handler(name, arguments):
        return {"name": name, "arguments": arguments}

    schema = {"values": ["original"]}
    registry.register("custom", schema, handler, capability="fixture")
    schema["values"].append("changed")
    registry.schemas["custom"]["values"].append("changed")
    assert registry.schemas["custom"]["values"] == ["original"]
    assert asyncio.run(registry.execute("custom", {"test": 1}))["arguments"] == {
        "test": 1
    }
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register("custom", {}, handler, capability="another-pack")
    with pytest.raises(ValueError, match="Unknown"):
        asyncio.run(registry.execute("unregistered", {}))
    with pytest.raises(ValueError, match="object"):
        asyncio.run(registry.execute("custom", []))


@pytest.mark.parametrize(
    "action",
    ['{"tool": [], "arguments": {}}', '{"tool":"browser_tabs","arguments":{}}'],
)
def test_model_protocol_accepts_only_session_capabilities(action):
    with pytest.raises(ValueError):
        EngineeringAgent.parse(action, {"finish": {}})


def test_core_packages_do_not_import_the_other_runtime():
    boundaries = {
        "hydra/engineering": ("hydra.main", "hydra.security", "hydra.hunt"),
        "hydra/browser": ("hydra.main", "hydra.security", "hydra.hunt"),
        "hydra/security": ("hydra.engineering",),
        "hydra/hunt/confirmation": ("hydra.hunt.confirm",),
    }
    for folder, forbidden in boundaries.items():
        for path in (ROOT / folder).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                modules = (
                    [node.module]
                    if isinstance(node, ast.ImportFrom)
                    else [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else []
                )
                for module in modules:
                    assert not any(
                        module == prefix or module.startswith(prefix + ".")
                        for prefix in forbidden
                    ), path


def test_read_only_process_facade_cannot_bypass_capability_guard(tmp_path):
    from hydra.engineering.session import Session
    from hydra.engineering.tools import EngineeringTools
    from hydra.engineering.workspace import Workspace

    tools = EngineeringTools(
        Session(Workspace(tmp_path), goal="Inspect only"),
        read_only=True,
        approve=lambda argv: True,
    )
    with pytest.raises(PermissionError):
        asyncio.run(tools.run([sys.executable, "-c", "print('should not run')"], 2))
