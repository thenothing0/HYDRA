"""FileCapability handlers and public tool contracts."""

from hydra.engineering.workspace import digest

SCHEMAS = {
    "list_files": {"pattern": "optional glob"},
    "read_file": {
        "path": "relative path",
        "start": "optional 1-based line",
        "lines": "optional <=300",
    },
    "search": {"query": "literal text", "pattern": "optional glob"},
    "show_diff": {},
    "write_file": {
        "path": "relative path",
        "content": "full UTF-8 text",
        "expected_sha256": "read hash, null for new file",
    },
    "edit_file": {
        "path": "relative path",
        "old": "unique exact text",
        "new": "replacement",
        "expected_sha256": "read hash",
    },
}


class FileCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        if tool == "list_files":
            return {"files": self.runtime.workspace.files(args.get("pattern", "*"))}
        if tool == "read_file":
            result = self.runtime.workspace.read(
                args["path"], args.get("start", 1), args.get("lines", 200)
            )
            name = args["path"]
            pages = self.runtime.read_pages.get(name)
            if not pages or pages["hash"] != result["sha256"]:
                pages = {"hash": result["sha256"], "ranges": []}
                self.runtime.read_pages[name] = pages
                self.runtime.read_hashes.pop(name, None)
            pages["ranges"].append((result["start_line"], result["end_line"]))
            covered = 0
            for start, end in sorted(pages["ranges"]):
                if start > covered + 1:
                    break
                covered = max(covered, end)
            if covered >= result["total_lines"]:
                self.runtime.read_hashes[name] = result["sha256"]
            return result
        if tool == "search":
            return {
                "matches": self.runtime.workspace.search(
                    args["query"], args.get("pattern", "*")
                )
            }
        if tool == "show_diff":
            return {"diff": self.runtime.session.diff()[:16000]}
        if tool in ("write_file", "edit_file"):
            if self.runtime.read_only:
                raise PermissionError("Session is read-only")
            name = args["path"]
            self.runtime.workspace.resolve(name)
            for instruction in self.runtime.instructions(name):
                current = digest(self.runtime.workspace.read_bytes(instruction))
                if self.runtime.read_hashes.get(instruction) != current:
                    raise ValueError(
                        f"Read applicable instructions before editing: {instruction}"
                    )
            if "expected_sha256" not in args:
                raise ValueError(
                    "expected_sha256 is required (null only for a new file)"
                )
            content = args.get("content")
            if tool == "edit_file":
                old = args["old"]
                original = self.runtime.workspace.read_bytes(name).decode("utf-8")
                if not old or original.count(old) != 1:
                    raise ValueError("old text must match exactly once")
                content = original.replace(old, args["new"], 1)
            if not isinstance(content, str):
                raise ValueError("content must be text")
            return self.runtime.session.change(name, content, args["expected_sha256"])
