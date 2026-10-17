"""Burp MCP tools with approval enforced outside the model."""

SCHEMAS = {
    "burp_status": {},
    "burp_tools": {},
    "burp_call": {"name": "exact name from burp_tools", "arguments": {"tool parameter": "value"}},
}


class BurpCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        from hydra.engineering.burp import BurpClient

        client = BurpClient(self.runtime.burp_url)
        if tool in ("burp_status", "burp_tools"):
            return await client.status()
        return await client.call(
            args["name"], args.get("arguments", {}), approve=self.runtime.approve_burp, read_only=self.runtime.read_only
        )
