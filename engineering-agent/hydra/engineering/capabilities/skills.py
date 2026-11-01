"""Skill discovery and reading are local; helpers use the ordinary process gate."""

SCHEMAS = {
    "skill_search": {"query": "boundary, technology or skill name; use English metadata terms", "limit": "optional 1..20"},
    "skill_use": {"name": "exact skill ID from the catalog"},
    "skill_read": {"name": "skill ID", "resource": "SKILL.md or a listed references/assets/scripts path", "start": "optional line", "lines": "optional <=300"},
    "skill_run": {"name": "skill ID", "script": "listed scripts/helper.py or .mjs", "arguments": ["argument"], "timeout": "optional <=120 seconds"},
}


class SkillsCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        catalog = self.runtime.skill_catalog
        if tool == "skill_search":
            return {"skills": catalog.search(args.get("query", ""), args.get("limit", 10)), "total": len(catalog.entries)}
        if tool == "skill_use":
            return self.runtime.skill_selection.use(args["name"])
        if tool == "skill_read":
            return catalog.read(args["name"], args.get("resource", "SKILL.md"), args.get("start", 1), args.get("lines", 200))
        if self.runtime.read_only:
            raise PermissionError("Read-only sessions cannot execute skill helpers")
        argv = catalog.helper_argv(args["name"], args["script"], args.get("arguments", []))
        return await self.runtime.registry.execute("run_command", {"argv": argv, "timeout": args.get("timeout", 60)})
