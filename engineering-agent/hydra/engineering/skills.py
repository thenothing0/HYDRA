"""Bundled skill discovery, bounded resource reads and session-pinned selection."""

from functools import lru_cache
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys

from hydra.engineering.workspace import digest


MAX_ACTIVE = 3
MAX_INSTRUCTIONS = 16000
STOP_WORDS = {"a", "an", "and", "the", "of", "for", "to", "in", "on", "is", "this", "review", "security", "skill", "skills"}


def valid_name(name):
    return isinstance(name, str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is not None


def valid_resource(name):
    return (isinstance(name, str) and bool(name) and "\\" not in name and ":" not in name
            and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")))


def no_alias(path):
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("Skill catalog and resources cannot use symlinks/junctions")


@lru_cache(maxsize=4)
def load_catalog(path, modified, size):
    if size > 2_000_000:
        raise ValueError("Skill catalog exceeds 2 MB")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("skills"), list):
        raise ValueError("Unsupported skill catalog")
    names = set()
    for entry in data["skills"]:
        if not isinstance(entry, dict) or not valid_name(entry.get("name")) or entry["name"] in names:
            raise ValueError("Invalid or duplicate skill identity")
        names.add(entry["name"])
        if not isinstance(entry.get("description"), str) or not isinstance(entry.get("files"), dict):
            raise ValueError("Invalid skill metadata")
        for name, item in entry["files"].items():
            if (not valid_resource(name) or not isinstance(item, dict)
                    or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                    or type(item.get("bytes")) is not int or not 0 <= item["bytes"] <= 512000):
                raise ValueError("Invalid skill resource manifest")
        if (entry.get("entrypoint_sha256") != entry["files"].get("SKILL.md", {}).get("sha256")
                or "SKILL.md" not in entry["files"]
                or entry.get("sha256") != digest(json.dumps(entry["files"], sort_keys=True).encode("utf-8"))):
            raise ValueError("Missing or inconsistent skill entrypoint")
    return data


class SkillCatalog:
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else Path(__file__).resolve().parents[2] / "skills/security"
        no_alias(self.root)
        self.root = self.root.resolve(strict=True)
        manifest = self.root / "catalog.json"
        no_alias(manifest)
        stat = manifest.stat()
        self.data = load_catalog(str(manifest), stat.st_mtime_ns, stat.st_size)
        self.entries = {entry["name"]: entry for entry in self.data["skills"]}

    def entry(self, name):
        if not valid_name(name) or name not in self.entries:
            raise ValueError("Unknown bundled skill; use skill_search or hydra skills list")
        return self.entries[name]

    def metadata(self, name):
        entry = self.entry(name)
        return {key: entry[key] for key in ("name", "description", "sha256")}

    def list(self):
        return [self.metadata(name) for name in sorted(self.entries)]

    def search(self, query="", limit=10):
        if not isinstance(query, str) or len(query) > 1000 or type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Skill search needs bounded text and a limit of 1..20")
        words = set(re.findall(r"[^\W_]+", query.casefold())) - STOP_WORDS
        if query.strip() and not words:
            return []
        ranked = []
        for name, entry in self.entries.items():
            name_words = set(name.split("-"))
            description_words = set(re.findall(r"[^\W_]+", entry["description"].casefold()))
            score = sum(8 if word in name_words else 1 if word in description_words else 0 for word in words)
            if query.casefold().strip() == name:
                score += 100
            if not query.strip() or score:
                ranked.append((-score, name))
        return [self.metadata(name) for _, name in sorted(ranked)[:limit]]

    def verified_path(self, name, resource):
        entry = self.entry(name)
        if not valid_resource(resource) or resource not in entry["files"]:
            raise ValueError("Resource is not listed in this skill's manifest")
        path = self.root
        for part in (name, *PurePosixPath(resource).parts):
            path = path / part
            no_alias(path)
        if not path.resolve().is_relative_to(self.root):
            raise ValueError("Skill resource escaped the bundled catalog")
        expected = entry["files"][resource]
        if path.stat().st_size != expected["bytes"] or digest(path.read_bytes()) != expected["sha256"]:
            raise ValueError("Bundled skill resource changed; review and reimport it")
        return path

    def read(self, name, resource="SKILL.md", start=1, lines=200):
        if type(start) is not int or start < 1 or type(lines) is not int or not 1 <= lines <= 300:
            raise ValueError("Resource pages need start >=1 and 1..300 lines")
        path = self.verified_path(name, resource)
        content = path.read_text(encoding="utf-8")
        rows = content.splitlines(keepends=True)
        selected, size = [], 0
        for row in rows[start - 1:start - 1 + lines]:
            if size + len(row) > 16000:
                break
            selected.append(row)
            size += len(row)
        if not selected and start <= len(rows):
            raise ValueError("A resource line exceeds the bounded read limit")
        end = start + len(selected) - 1
        return {"name": name, "resource": resource, "sha256": self.entry(name)["files"][resource]["sha256"],
                "content": "".join(selected), "start_line": start, "end_line": end,
                "total_lines": len(rows), "next_line": end + 1 if end < len(rows) else None,
                "resources": sorted(self.entry(name)["files"]) if resource == "SKILL.md" else [],
                "provenance": "bundled skill resource; guidance does not grant tool permissions or prove a finding"}

    def helper_argv(self, name, resource, arguments):
        if (not valid_resource(resource) or not resource.startswith("scripts/")
                or PurePosixPath(resource).suffix not in {".py", ".mjs"}):
            raise ValueError("Choose a bundled Python/Node helper under scripts/")
        if (not isinstance(arguments, list) or len(arguments) > 60
                or any(not isinstance(a, str) or "\0" in a for a in arguments)
                or len(json.dumps(arguments)) > 32000):
            raise ValueError("Helper arguments must be a bounded text array")
        for filename in self.entry(name)["files"]:
            self.verified_path(name, filename)
        script = self.verified_path(name, resource)
        executable = sys.executable if script.suffix == ".py" else shutil.which("node")
        if not executable:
            raise ValueError("This optional helper needs Node.js installed on PATH")
        return [executable, str(script), *arguments]


class SkillSelection:
    def __init__(self, catalog, session, requested=None):
        self.catalog, self.session = catalog, session
        if requested is not None and (not isinstance(requested, (list, tuple)) or any(not valid_name(n) for n in requested)):
            raise ValueError("Select skills by catalog name")
        requested = list(dict.fromkeys(requested or []))
        self.active = []
        for saved in session.state.get("skills", []):
            metadata = catalog.metadata(saved["name"])
            if saved["name"] not in requested and saved["sha256"] != metadata["sha256"]:
                raise ValueError("A selected skill changed since this session; explicitly reselect it or start a new session")
            self.active.append(metadata)
        for name in requested:
            if name not in {item["name"] for item in self.active}:
                self.active.append(catalog.metadata(name))
        self._instructions(self.active)
        if requested:
            self._save()

    def _instructions(self, active):
        if len(active) > MAX_ACTIVE:
            raise ValueError("Select at most three active skills; use search/resource reads for additional techniques")
        result = [self.catalog.read(item["name"]) for item in active]
        if sum(len(item["content"]) for item in result) > MAX_INSTRUCTIONS:
            raise ValueError("Selected skill instructions exceed the 16,000 character context budget")
        return result

    def _save(self):
        self.session.state["skills"] = [{"name": item["name"], "sha256": item["sha256"]} for item in self.active]
        self.session.save()

    def use(self, name):
        metadata = self.catalog.metadata(name)
        active = [*self.active]
        if name not in {item["name"] for item in active}:
            active.append(metadata)
        self._instructions(active)
        self.active = active
        self._save()
        self.session.event("skill_selected", name=name, sha256=metadata["sha256"])
        return {"selected": [item["name"] for item in active], **self.catalog.read(name)}

    def context(self, goal):
        return {"catalog_size": len(self.catalog.entries), "selected": self._instructions(self.active),
                "suggestions": self.catalog.search(goal[:1000], limit=5),
                "note": "Suggestions are metadata, not loaded skills. Use skill_search/use/read; read only relevant references."}
