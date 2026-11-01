"""Opt-in reporting capability; model claims never replace operator-owned checks."""

from hydra.engineering.hackerone_api import HackerOneClient
from hydra.engineering.hackerone_reporting import HackerOneReporting

SCHEMAS = {
    "hackerone_status": {},
    "hackerone_program": {"program": "authorized program handle", "structured_scope_id": "positive asset ID"},
    "hackerone_submit": {"finding_path": "relative path to the completed finding JSON"},
}


class HackerOneCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        runtime = self.runtime
        if not runtime.hackerone_enabled:
            raise PermissionError("HackerOne was not enabled for this session")
        store = HackerOneReporting(runtime.workspace)
        if tool == "hackerone_status":
            return store.status()
        if tool == "hackerone_submit" and runtime.read_only:
            raise PermissionError("Read-only sessions cannot submit disclosures")
        store.client = HackerOneClient()
        if tool == "hackerone_program":
            return await store.client.snapshot(args["program"], args["structured_scope_id"])
        import json

        finding = json.loads(runtime.workspace.read_bytes(args["finding_path"]))

        async def run_check(argv, timeout):
            return await runtime.registry.execute("run_command", {"argv": argv, "timeout": timeout})

        result = await store.submit(finding, run_check=run_check, read_only=runtime.read_only)
        runtime.session.event("hackerone_disclosure", result=result)
        return result
