"""Render the real TUI with a deterministic model and a local verified edit."""

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

os.environ.setdefault("TEXTUAL_COLOR_SYSTEM", "truecolor")
# Render the intended palette in this preview process; the actual app honors NO_COLOR.
os.environ.pop("NO_COLOR", None)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hydra.engineering.tui.app import EngineeringApp
from hydra.engineering.tui.controller import RunOptions
from hydra.engineering.tui.widgets import CommandApproval, Prompt
from hydra.engineering.workspace import digest


async def render(destination):
    with tempfile.TemporaryDirectory(prefix="hydra-tui-preview-") as temporary:
        workspace = Path(temporary)
        original = b"def add(a, b):\n    return a - b\n"
        (workspace / "calculator.py").write_bytes(original)
        actions = [
            {
                "tool": "set_plan",
                "arguments": {
                    "steps": ["Inspect the calculation", "Repair the arithmetic", "Run the regression check"]
                },
                "note": "Check the implementation and verify the smallest fix.",
            },
            {"tool": "read_file", "arguments": {"path": "calculator.py"}, "note": "Read the current implementation."},
            {
                "tool": "edit_file",
                "arguments": {
                    "path": "calculator.py",
                    "old": "a - b",
                    "new": "a + b",
                    "expected_sha256": digest(original),
                },
                "note": "Addition currently subtracts; correct the operator.",
            },
            {"tool": "verify", "arguments": {}, "note": "Run the configured regression check."},
            {
                "tool": "finish",
                "arguments": {
                    "summary": "Fixed addition and verified add(2, 3) == 5. The change is saved in this session."
                },
                "note": "Report the verified result.",
            },
        ]

        class FixtureModel:
            async def initialize(self):
                pass

            async def respond(self, prompt):
                await asyncio.sleep(0.12)
                return json.dumps(actions.pop(0))

        options = RunOptions(
            provider="ollama",
            model="deterministic-preview-fixture",
            verify_command=[
                sys.executable,
                "-c",
                "from calculator import add; assert add(2,3)==5; print('Regression check passed')",
            ],
        )
        app = EngineeringApp(workspace, options, model_factory=lambda *_: FixtureModel())
        destination.mkdir(parents=True, exist_ok=True)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.save_screenshot("terminal-welcome.svg", path=str(destination))
            await app.slash_command("/model")
            await pilot.pause()
            app.save_screenshot("terminal-model.svg", path=str(destination))
            await pilot.press("escape")
            app.query_one("#prompt", Prompt).load_text("Fix the incorrect addition and verify the change.")
            await pilot.press("enter")

            async def wait_for_approval():
                while not isinstance(app.screen, CommandApproval):
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(wait_for_approval(), 15)
            await pilot.pause()
            app.save_screenshot("terminal-approval.svg", path=str(destination))
            await pilot.click("#allow")

            async def wait_for_completion():
                while app.busy:
                    await asyncio.sleep(0.02)

            await asyncio.wait_for(wait_for_completion(), 15)
            assert app.controller.session.state["status"] == "completed"
            app.action_diff()
            await pilot.pause()
            await pilot.pause()
            app.save_screenshot("terminal-verified.svg", path=str(destination))
    print(destination.resolve())


if __name__ == "__main__":
    asyncio.run(render(Path(sys.argv[1] if len(sys.argv) > 1 else "output/tui-preview")))
