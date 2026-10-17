"""Real file/process regressions; model decisions are deterministic test fixtures."""
import asyncio
import json
import subprocess
import sys

import pytest

from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace, digest


@pytest.fixture
def workspace(tmp_path):
    return Workspace(tmp_path)


@pytest.mark.parametrize("name", ["../escape.py", "a/../../escape.py", ".git/config", ".env",
                                  ".env.production", "private.key", ".hydra/sessions/state.json",
                                  ".GIT/config", ".ENV", ".git./config", "file.py:stream", "NUL.txt"])
def test_protected_paths_are_rejected(workspace, name):
    with pytest.raises(ValueError):
        workspace.resolve(name)


def test_listing_prunes_dependencies_and_secrets(workspace):
    for name in ("src/app.py", ".venv/secret.py", "node_modules/pkg/file.js", ".env"):
        path = workspace.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("example")
    assert workspace.files() == ["src/app.py"]


def test_edit_requires_current_hash_and_rollback_preserves_bytes(workspace):
    path = workspace.root / "hello.py"
    path.write_bytes(b"value = 1\r\n")
    session = Session(workspace, "update value")
    session.change("hello.py", "value = 2\n", digest(path.read_bytes()))
    with pytest.raises(ValueError, match="changed since read"):
        session.change("hello.py", "value = 3\n", "stale")
    assert session.rollback() == 1
    assert path.read_bytes() == b"value = 1\r\n"


def test_rollback_refuses_to_overwrite_later_user_edits(workspace):
    session = Session(workspace, "create file")
    session.change("new.py", "original", None)
    (workspace.root / "new.py").write_text("user change")
    with pytest.raises(ValueError, match="Rollback conflict"):
        session.rollback()
    assert (workspace.root / "new.py").read_text() == "user change"


def test_rollback_preflights_all_files_before_any_change(workspace):
    session = Session(workspace)
    session.change("a.py", "a", None)
    session.change("b.py", "b", None)
    (workspace.root / "a.py").write_text("user")
    with pytest.raises(ValueError):
        session.rollback()
    assert (workspace.root / "b.py").read_text() == "b"


def test_resume_integrity_and_optimistic_concurrency(workspace):
    original = Session(workspace, "goal")
    stale = Session(workspace, session_id=original.state["id"])
    original.event("observed", evidence="fact")
    with pytest.raises(ValueError, match="Concurrent"):
        stale.event("overwrite")
    state = json.loads(original.path.read_text(encoding="utf-8"))
    state["goal"] = "tampered"
    original.path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        Session(workspace, session_id=original.state["id"])


def test_nested_project_instructions_must_be_read(workspace):
    (workspace.root / "AGENTS.md").write_text("Use tests")
    (workspace.root / "src").mkdir()
    (workspace.root / "src/AGENTS.md").write_text("Use small changes")
    session = Session(workspace)
    tools = EngineeringTools(session)
    async def run():
        args = {"path": "src/new.py", "content": "pass\n", "expected_sha256": None}
        with pytest.raises(ValueError, match="AGENTS.md"):
            await tools.execute("write_file", args)
        await tools.execute("read_file", {"path": "AGENTS.md"})
        with pytest.raises(ValueError, match="src/AGENTS.md"):
            await tools.execute("write_file", args)
        await tools.execute("read_file", {"path": "src/AGENTS.md"})
        assert (await tools.execute("write_file", args))["changed"]
    asyncio.run(run())


def test_partial_instruction_read_does_not_authorize_edits(workspace):
    (workspace.root / "AGENTS.md").write_text("Follow this instruction\n" * 350)
    tools = EngineeringTools(Session(workspace))
    args = {"path": "new.py", "content": "pass\n", "expected_sha256": None}
    async def run():
        await tools.execute("read_file", {"path": "AGENTS.md", "lines": 200})
        with pytest.raises(ValueError, match="Read applicable instructions"):
            await tools.execute("write_file", args)
        await tools.execute("read_file", {"path": "AGENTS.md", "start": 201, "lines": 150})
        assert (await tools.execute("write_file", args))["changed"]
    asyncio.run(run())


def test_read_only_blocks_writes_and_processes(workspace):
    tools = EngineeringTools(Session(workspace), read_only=True, approve=lambda argv: True)
    async def run():
        with pytest.raises(PermissionError):
            await tools.execute("write_file", {"path": "x", "content": "x", "expected_sha256": None})
        with pytest.raises(PermissionError):
            await tools.execute("run_command", {"argv": [sys.executable, "--version"]})
    asyncio.run(run())


def test_commands_require_authorization(workspace):
    tools = EngineeringTools(Session(workspace))
    with pytest.raises(PermissionError):
        asyncio.run(tools.run([sys.executable, "-c", "open('unwanted', 'w').write('x')"], 2))
    assert not (workspace.root / "unwanted").exists()


def test_process_output_is_bounded_and_timeout_stops_process(workspace):
    tools = EngineeringTools(Session(workspace), approve=lambda argv: True)
    result = asyncio.run(tools.run([sys.executable, "-c", "print('x'*100000)"], 10))
    assert result["success"] and result["truncated"] and len(result["output"]) <= 16000
    result = asyncio.run(tools.run([sys.executable, "-c", "import time; time.sleep(20)"], 0.15))
    assert result["timed_out"] and not result["success"]


def test_finish_cannot_bypass_failed_verification(workspace):
    session = Session(workspace)
    tools = EngineeringTools(session, approve=lambda argv: True,
                             verify_command=[sys.executable, "-c", "raise SystemExit(1)"])
    session.change("code.py", "pass\n", None)
    async def run():
        assert not (await tools.execute("verify", {}))["success"]
        with pytest.raises(ValueError, match="Cannot finish"):
            await tools.execute("finish", {"summary": "pretend done"})
    asyncio.run(run())


def test_external_edit_invalidates_completion_evidence(workspace):
    session = Session(workspace)
    session.change("code.py", "pass\n", None)
    tools = EngineeringTools(session, approve=lambda argv: True,
                             verify_command=[sys.executable, "-c", "pass"])
    async def run():
        assert (await tools.execute("verify", {}))["success"]
        (workspace.root / "code.py").write_text("user change\n")
        with pytest.raises(ValueError, match="changed after verification"):
            await tools.execute("finish", {"summary": "done"})
    asyncio.run(run())


class FixtureModel:
    """Tool decisions only; actual file changes and tests use real implementations."""
    def __init__(self):
        self.turn = 0
    async def respond(self, prompt):
        self.turn += 1
        context = json.loads(prompt.split("SESSION DATA:\n", 1)[1])
        if self.turn == 1:
            action = {"tool": "set_plan", "arguments": {"steps": ["Reproduce", "Fix addition", "Run tests"]}}
        elif self.turn == 2:
            action = {"tool": "read_file", "arguments": {"path": "calc.py"}}
        elif self.turn == 3:
            action = {"tool": "verify", "arguments": {}}
        elif self.turn == 4:
            read = next(e["result"] for e in context["recent_events"]
                        if e["kind"] == "result" and e["tool"] == "read_file")
            action = {"tool": "edit_file", "arguments": {
                "path": "calc.py", "old": "return a - b", "new": "return a + b", "expected_sha256": read["sha256"]}}
        elif self.turn == 5:
            action = {"tool": "verify", "arguments": {}}
        else:
            action = {"tool": "finish", "arguments": {"summary": "Fixed addition; both regression assertions pass."}}
        return json.dumps(action)


def test_agent_fixes_real_bug_runs_real_test_and_resumes(workspace):
    (workspace.root / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    verification = [sys.executable, "-B", "-c", "from calc import add; assert add(2,3)==5; assert add(-2,3)==1"]
    session = Session(workspace, "Fix addition")
    tools = EngineeringTools(session, approve=lambda argv: True, verify_command=verification)
    # Stop before editing, then reload from disk and continue the SAME fixture model.
    model = FixtureModel()
    first = asyncio.run(EngineeringAgent(session, model, tools, max_steps=3).run())
    assert first["status"] == "budget_exhausted"
    resumed = Session(workspace, session_id=session.state["id"])
    tools = EngineeringTools(resumed, approve=lambda argv: True, verify_command=verification)
    final = asyncio.run(EngineeringAgent(resumed, model, tools).run())
    assert final["status"] == "completed"
    assert final["verified_revision"] == final["revision"] == 1
    verifications = [e["result"]["exit_code"] for e in final["events"]
                     if e["kind"] == "result" and e["tool"] == "verify"]
    assert verifications == [1, 0]
    assert resumed.rollback() == 1
    assert "return a - b" in (workspace.root / "calc.py").read_text()


def test_protocol_errors_are_bounded_and_do_not_modify_files(workspace):
    class BadModel:
        async def respond(self, prompt):
            return "not JSON"
    result = asyncio.run(EngineeringAgent(Session(workspace), BadModel()).run())
    assert result["status"] == "blocked"
    assert len([e for e in result["events"] if e["kind"] == "protocol_error"]) == 3


def test_model_deadline_is_enforced(workspace):
    class SlowModel:
        async def respond(self, prompt):
            await asyncio.sleep(20)
    result = asyncio.run(EngineeringAgent(Session(workspace), SlowModel(), max_seconds=1).run())
    assert result["status"] == "budget_exhausted"


def test_cli_entry_points_and_provider_status(tmp_path):
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for argv in (["--help"], ["providers", "--json"], ["--list-workflows"]):
        result = subprocess.run([sys.executable, "-m", "hydra", *argv], cwd=root,
                                capture_output=True, text=True, encoding="utf-8", timeout=15)
        assert result.returncode == 0, result.stderr
        assert "Traceback" not in result.stderr
        if argv[0] == "providers":
            profiles = json.loads(result.stdout)
            assert len(profiles) == 60
