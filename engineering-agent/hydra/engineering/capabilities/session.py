"""SessionCapability handlers and public tool contracts."""

from hydra.engineering.workspace import digest

SCHEMAS = {
    "set_plan": {"steps": ["concrete acceptance step"]},
    "finish": {"summary": "what changed and verification evidence"},
}


class SessionCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        if tool == "set_plan":
            steps = args.get("steps")
            if (
                not isinstance(steps, list)
                or not 1 <= len(steps) <= 20
                or any(not isinstance(s, str) for s in steps)
            ):
                raise ValueError("Plan requires 1..20 text steps")
            self.runtime.session.state["plan"] = steps
            self.runtime.session.save()
            return {"plan": steps}
        if tool == "finish":
            state = self.runtime.session.state
            if (state["revision"] or state.get("command_dirty")) and state[
                "verified_revision"
            ] != state["revision"]:
                raise ValueError(
                    "Cannot finish changed code: run configured verification successfully after the last edit"
                )
            for name, verified_hash in state.get("verified_files", {}).items():
                path = self.runtime.workspace.resolve(name)
                if (
                    not path.is_file()
                    or digest(self.runtime.workspace.read_bytes(name)) != verified_hash
                ):
                    state["verified_revision"] = None
                    self.runtime.session.save()
                    raise ValueError(
                        "Workspace changed after verification; verify again before finishing"
                    )
            summary = args.get("summary", "").strip()
            if not summary:
                raise ValueError("A concrete summary is required")
            state.update(status="completed", summary=summary)
            self.runtime.session.save()
            return {
                "completed": True,
                "summary": summary,
                "verified_revision": state["verified_revision"],
            }
