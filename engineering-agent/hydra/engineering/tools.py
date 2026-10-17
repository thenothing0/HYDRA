"""Engineering tool facade. Capability selection and permissions stay outside the model."""

import json
import os
import sys
from pathlib import Path
from hydra.engineering.registry import ToolRegistry
from hydra.engineering.process import ProcessRunner
from hydra.engineering.capabilities import files, process, session, browser, burp

CAPABILITIES = {
    "files": files.FileCapability,
    "process": process.ProcessCapability,
    "session": session.SessionCapability,
    "browser": browser.BrowserCapability,
    "burp": burp.BurpCapability,
}
BROWSER_TOOLS = browser.SCHEMAS
TOOLS = {
    name: schema
    for pack in CAPABILITIES.values()
    for name, schema in pack.schemas.items()
}


def detect_verification(root):
    if (root / "tests").is_dir() and any(
        (root / n).exists() for n in ("pyproject.toml", "requirements.txt", "setup.py")
    ):
        return [sys.executable, "-m", "pytest", "-q"]
    if (root / "Cargo.toml").exists():
        return ["cargo", "test", "--locked"]
    if (root / "go.mod").exists():
        return ["go", "test", "./..."]
    if (root / "package.json").exists():
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        if package.get("scripts", {}).get("test"):
            return ["npm.cmd" if os.name == "nt" else "npm", "test"]
    return None


class EngineeringTools:
    def __init__(
        self,
        session,
        approve=None,
        read_only=False,
        verify_command=None,
        browser=False,
        allow_browser_actions=False,
        burp_url=None,
        approve_burp=None,
    ):
        self.session = session
        self.workspace = session.workspace
        self.approve = approve or (lambda argv: False)
        self.read_only = read_only
        self.verify_command = verify_command or detect_verification(self.workspace.root)
        self.read_hashes = {}
        self.read_pages = {}
        self.browser_enabled = browser
        self.allow_browser_actions = allow_browser_actions
        self.burp_url = burp_url
        self.approve_burp = approve_burp or self.approve
        self.registry = ToolRegistry()
        for name, pack in CAPABILITIES.items():
            if name == "browser" and not self.browser_enabled:
                continue
            capability = pack(self)
            for tool, schema in pack.schemas.items():
                self.registry.register(
                    tool, schema, capability.execute, capability=name
                )
        self.runner = ProcessRunner(self.workspace, lambda argv: self.approve(argv))

    @property
    def available_tools(self):
        return self.registry.schemas

    def instructions(self, name):
        relative = Path(name)
        parents = [*reversed(relative.parent.parents), relative.parent]
        found = []
        for parent in parents:
            candidate = (parent / "AGENTS.md").as_posix()
            if candidate not in found and (self.workspace.root / candidate).is_file():
                self.workspace.resolve(candidate)
                found.append(candidate)
        return found

    async def execute(self, tool, args):
        if not isinstance(tool, str):
            raise ValueError("Tool name must be text")
        if tool in BROWSER_TOOLS and not self.browser_enabled:
            raise PermissionError("Browser capability was not enabled for this session")
        return await self.registry.execute(tool, args)

    async def run(self, argv, timeout):
        if self.read_only:
            raise PermissionError("Read-only sessions cannot execute commands")
        return await self.runner.run(argv, timeout)
