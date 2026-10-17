"""Real headless terminal interactions and local processes; no paid models."""

import asyncio
import json
import sys

import pytest

pytest.importorskip("textual")
from textual.widgets import Input, Select

from hydra.engineering.tui.app import EngineeringApp
from hydra.engineering.tui.controller import EngineeringController, RunOptions
from hydra.engineering.tui.widgets import CommandApproval, Prompt, safe_text
from hydra.engineering.workspace import digest


class ScriptModel:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = 0

    async def initialize(self):
        pass

    async def respond(self, prompt):
        self.calls += 1
        await asyncio.sleep(0)
        return json.dumps(self.actions.pop(0))


def action(tool, **arguments):
    return {"tool": tool, "arguments": arguments, "note": f"Using {tool}"}


async def until(predicate, timeout=8):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(wait(), timeout)


@pytest.mark.asyncio
async def test_tui_starts_offline_and_adapts_to_small_terminal(tmp_path):
    model = ScriptModel([])
    app = EngineeringApp(tmp_path, RunOptions(provider="ollama", model="fixture"), model_factory=lambda *_: model)
    async with app.run_test(size=(90, 28)) as pilot:
        assert not app.query_one("#sessions-panel").display
        assert not app.query_one("#inspector").display
        assert model.calls == 0
        assert not (tmp_path / ".hydra/sessions").exists()
        await pilot.press("ctrl+b")
        assert app.query_one("#sessions-panel").display
        await pilot.resize_terminal(160, 48)
        await until(lambda: app.query_one("#inspector").display)
        assert app.query_one("#inspector").display
        assert app.query_one("#provider", Select).value == "ollama"
        assert app.query_one("#model", Input).value == "fixture"


@pytest.mark.asyncio
async def test_tui_edits_verifies_and_finishes_with_real_approval(tmp_path):
    original = "def add(a, b):\n    return a - b\n"
    (tmp_path / "calc.py").write_text(original)
    model = ScriptModel(
        [
            action("set_plan", steps=["Read addition", "Fix addition", "Verify result"]),
            action("read_file", path="calc.py"),
            action(
                "edit_file",
                path="calc.py",
                old="a - b",
                new="a + b",
                expected_sha256=digest((tmp_path / "calc.py").read_bytes()),
            ),
            action("verify"),
            action("finish", summary="Addition fixed and verified."),
        ]
    )
    options = RunOptions(
        provider="ollama",
        model="fixture",
        verify_command=[sys.executable, "-c", "from calc import add; assert add(2,3)==5"],
    )
    app = EngineeringApp(tmp_path, options, model_factory=lambda *_: model)
    async with app.run_test(size=(160, 48)) as pilot:
        app.query_one("#prompt", Prompt).load_text("Fix addition")
        await pilot.press("enter")
        await until(lambda: isinstance(app.screen, CommandApproval))
        assert app.screen.focused.id == "deny"
        assert app.controller.session.state["verified_revision"] is None
        await pilot.click("#allow")
        await until(lambda: not app.busy)
        assert app.controller.session.state["status"] == "completed"
        assert app.controller.session.state["verification"]["success"]
        assert "a + b" in (tmp_path / "calc.py").read_text()
        assert "a + b" in app.controller.session.diff()
        assert len(app.controller.sessions()) == 1


@pytest.mark.asyncio
async def test_tui_denies_command_without_spawning_it(tmp_path):
    model = ScriptModel([action("run_command", argv=[sys.executable, "-c", "open('unwanted','w').write('x')"])])
    app = EngineeringApp(
        tmp_path, RunOptions(provider="ollama", model="fixture", max_steps=1), model_factory=lambda *_: model
    )
    async with app.run_test(size=(120, 36)) as pilot:
        app.query_one("#prompt", Prompt).load_text("Inspect execution")
        await pilot.press("enter")
        await until(lambda: isinstance(app.screen, CommandApproval))
        await pilot.press("escape")
        await until(lambda: not app.busy)
        assert not (tmp_path / "unwanted").exists()
        results = [e for e in app.controller.session.state["events"] if e["kind"] == "result"]
        assert results[0]["result"]["success"] is False


@pytest.mark.asyncio
async def test_tui_cancellation_saves_an_interrupted_session(tmp_path):
    entered = asyncio.Event()

    class WaitingModel:
        async def initialize(self):
            pass

        async def respond(self, prompt):
            entered.set()
            await asyncio.Event().wait()

    app = EngineeringApp(
        tmp_path, RunOptions(provider="ollama", model="fixture"), model_factory=lambda *_: WaitingModel()
    )
    async with app.run_test(size=(120, 36)) as pilot:
        app.query_one("#prompt", Prompt).load_text("Wait for response")
        await pilot.press("enter")
        await asyncio.wait_for(entered.wait(), 5)
        await pilot.press("ctrl+c")
        await until(lambda: not app.busy)
        assert app.controller.session.state["status"] == "interrupted"
        assert app.query_one("#provider", Select).disabled is False


@pytest.mark.asyncio
async def test_controller_resumes_and_emits_real_results(tmp_path):
    models = [
        ScriptModel([action("set_plan", steps=["Inspect"])]),
        ScriptModel([action("finish", summary="Inspection complete")]),
    ]
    events = []
    options = RunOptions(provider="ollama", model="fixture", max_steps=1)
    controller = EngineeringController(tmp_path, options, lambda argv: False, events.append, lambda *_: models.pop(0))
    first = await controller.run("Inspect project")
    ident = first["id"]
    controller.new()
    controller.load(ident)
    result = await controller.run(resume=True)
    assert result["status"] == "completed"
    assert result["id"] == ident
    assert any(e["kind"] == "result" and e["tool"] == "set_plan" for e in events)


@pytest.mark.asyncio
async def test_async_approval_cancellation_never_spawns_process(tmp_path):
    requested = asyncio.Event()

    async def approve(argv):
        requested.set()
        await asyncio.Event().wait()

    model = ScriptModel([action("run_command", argv=[sys.executable, "-c", "open('unwanted','w').write('x')"])])
    controller = EngineeringController(
        tmp_path, RunOptions(provider="ollama", model="fixture"), approve, model_factory=lambda *_: model
    )
    task = asyncio.create_task(controller.run("Check approval"))
    await asyncio.wait_for(requested.wait(), 5)
    assert not (tmp_path / "unwanted").exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not (tmp_path / "unwanted").exists()
    assert controller.session.state["status"] == "interrupted"


def test_terminal_content_cannot_inject_escape_sequences():
    assert safe_text("before\x1b[31mafter\x1b[0m\x00\x9b") == "beforeafter"
    assert safe_text("\x1b]0;untrusted title\x07visible") == "visible"
    assert safe_text("[bold]literal markup[/bold]") == "[bold]literal markup[/bold]"


@pytest.mark.asyncio
async def test_expired_budget_removes_approval_without_execution(tmp_path):
    model = ScriptModel([action("run_command", argv=[sys.executable, "-c", "open('unwanted','w').write('x')"])])
    app = EngineeringApp(
        tmp_path, RunOptions(provider="ollama", model="fixture", max_seconds=1), model_factory=lambda *_: model
    )
    async with app.run_test(size=(120, 36)) as pilot:
        app.query_one("#prompt", Prompt).load_text("Check command timeout")
        await pilot.press("enter")
        await until(lambda: isinstance(app.screen, CommandApproval))
        await until(lambda: not app.busy)
        await pilot.pause()
        assert not isinstance(app.screen, CommandApproval)
        assert app.controller.session.state["status"] == "budget_exhausted"
        assert not (tmp_path / "unwanted").exists()


@pytest.mark.asyncio
async def test_provider_error_leaves_a_recoverable_session(tmp_path):
    class BrokenModel:
        async def initialize(self):
            raise ValueError("Configure the selected provider")

    app = EngineeringApp(
        tmp_path, RunOptions(provider="ollama", model="fixture"), model_factory=lambda *_: BrokenModel()
    )
    async with app.run_test(size=(120, 36)) as pilot:
        app.query_one("#prompt", Prompt).load_text("Inspect the application")
        await pilot.press("enter")
        await until(lambda: app.controller.session is not None and not app.busy)
        assert app.controller.session.state["status"] == "blocked"
        assert not app.query_one("#model", Input).disabled
        assert app.controller.sessions()[0]["goal"] == "Inspect the application"
