"""ProcessCapability handlers and public tool contracts."""

from hydra.engineering.workspace import digest

SCHEMAS = {
    "run_command": {
        "argv": ["executable", "argument"],
        "timeout": "optional <=120 seconds",
    },
    "verify": {},
}


class ProcessCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        if tool in ("run_command", "verify"):
            if self.runtime.read_only:
                raise PermissionError("Read-only sessions cannot execute commands")
            argv = self.runtime.verify_command if tool == "verify" else args.get("argv")
            if not argv:
                raise ValueError(
                    "No verification command configured; supply --verify-command as JSON argv"
                )
            # Persist invalidation before spawning: interrupted commands can
            # already have changed files even when they return no tool result.
            self.runtime.session.state["verified_revision"] = None
            if tool == "run_command":
                self.runtime.session.state["command_dirty"] = True
            self.runtime.session.save()
            result = await self.runtime.run(argv, args.get("timeout", 120))
            if tool == "verify":
                self.runtime.session.state["verified_revision"] = (
                    self.runtime.session.state["revision"]
                    if result["success"]
                    else None
                )
                self.runtime.session.state["verification"] = result
                self.runtime.session.state["verified_files"] = (
                    {
                        c["path"]: digest(self.runtime.workspace.read_bytes(c["path"]))
                        for c in self.runtime.session.state["changes"]
                        if c["status"] == "applied"
                    }
                    if result["success"]
                    else {}
                )
                self.runtime.session.save()
            else:
                # Arbitrary commands may edit files too: invalidate previous verification.
                self.runtime.session.state["verified_revision"] = None
                self.runtime.session.state["command_dirty"] = True
                self.runtime.session.save()
            return result
