"""Opt-in live OpenCode check on a temporary project; never prints credentials."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.providers import ProviderModel
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace


async def check(model_id):
    with TemporaryDirectory(prefix="hydra-opencode-smoke-") as directory:
        root = Path(directory)
        (root / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
        verification = [
            sys.executable,
            "-c",
            "from calc import add; assert add(2, 3) == 5; print('verification passed')",
        ]
        session = Session(
            Workspace(root),
            goal="Fix add() in calc.py so it adds its arguments. Read the file, edit the bug, run verify, and finish.",
        )
        tools = EngineeringTools(session, verify_command=verification, approve=lambda argv: argv == verification)
        model = ProviderModel("opencode", model_id)
        await model.initialize()
        model.config.max_tokens = 2048
        model.config.timeout = 45
        agent = EngineeringAgent(
            session,
            model,
            tools,
            max_steps=8,
            max_seconds=180,
            on_event=lambda event: print(f"Step {event['step']}: {event['tool']}", flush=True),
        )
        result = await agent.run()
        success = result["status"] == "completed" and result.get("verification", {}).get("success") is True
        report = {
            "provider": "opencode",
            "model": model_id,
            "status": result["status"],
            "verified": success,
            "usage": model.usage,
            "errors": [e.get("error", "")[:300] for e in result["events"] if e["kind"] in ("runtime_error", "protocol_error")][-3:],
        }
        print(json.dumps(report, indent=2))
        return 0 if success else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=os.getenv("OPENCODE_MODEL"), required=not bool(os.getenv("OPENCODE_MODEL")))
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(check(args.model)))
    except (ValueError, OSError) as error:
        # Provider transport already redacts response bodies.
        print(f"OpenCode check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
