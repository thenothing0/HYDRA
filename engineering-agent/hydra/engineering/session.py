"""Durable session snapshots, change journal and conflict-aware rollback."""
import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone

from hydra.engineering.workspace import atomic_write, digest


def now():
    return datetime.now(timezone.utc).isoformat()


class Session:
    def __init__(self, workspace, goal="", session_id=None):
        self.workspace = workspace
        self.directory = workspace.root / ".hydra" / "sessions"
        for directory in (workspace.root / ".hydra", self.directory):
            if (directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction())
                    or not directory.resolve().is_relative_to(workspace.root)):
                raise ValueError("Session storage must stay inside the workspace")
        self._generation = 0
        if session_id:
            if not re.fullmatch(r"[a-f0-9]{32}", session_id):
                raise ValueError("Invalid session id")
            self.path = self.directory / f"{session_id}.json"
            if self.path.is_symlink():
                raise ValueError("Session snapshots cannot be symlinks")
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
            if (self.state.get("schema") != 1 or self.state.get("id") != session_id
                    or self.state.get("workspace") != str(workspace.root)):
                raise ValueError("Session schema or workspace mismatch")
            expected = self.state.get("checksum")
            content = {k: v for k, v in self.state.items() if k != "checksum"}
            if digest(json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")) != expected:
                raise ValueError("Session checksum mismatch")
            self._generation = self.state["generation"]
        else:
            session_id = uuid.uuid4().hex
            self.path = self.directory / f"{session_id}.json"
            self.state = {"schema": 1, "id": session_id, "workspace": str(workspace.root),
                          "goal": goal, "status": "created", "created_at": now(),
                          "revision": 0, "verified_revision": None, "events": [],
                          "changes": [], "summary": "", "plan": []}
            self.save()

    def save(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        lock = self.path.with_suffix(".lock")
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise ValueError("Session is being saved elsewhere; inspect any stale .lock after a crash") from None
        try:
            os.close(fd)
            if self.path.exists():
                disk = json.loads(self.path.read_text(encoding="utf-8"))
                if disk.get("generation") != self._generation:
                    raise ValueError("Concurrent session update detected; reload the session")
            self.state["updated_at"] = now()
            self.state["generation"] = self._generation + 1
            content = {k: v for k, v in self.state.items() if k != "checksum"}
            self.state["checksum"] = digest(json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8"))
            atomic_write(self.path, json.dumps(self.state, ensure_ascii=False, indent=2).encode("utf-8"))
            self._generation += 1
        finally:
            lock.unlink(missing_ok=True)

    def event(self, kind, **data):
        self.state["events"].append({"time": now(), "kind": kind, **data})
        self.save()

    def change(self, name, content, expected_sha256):
        path = self.workspace.resolve(name)
        before = self.workspace.read_bytes(name) if path.exists() else None
        actual = digest(before) if before is not None else None
        if actual != expected_sha256:
            raise ValueError("File changed since read; read it again before editing")
        after = content.encode("utf-8")
        if len(after) > 512_000 or "\0" in content:
            raise ValueError("Unsupported file size or binary content")
        if before == after:
            return {"changed": False, "sha256": digest(after)}
        change = {"path": name, "before": base64.b64encode(before).decode() if before is not None else None,
                  "before_sha256": actual, "after_sha256": digest(after), "status": "pending"}
        self.state["changes"].append(change)
        self.state["revision"] += 1
        self.state["verified_revision"] = None
        self.save()  # write-ahead snapshot: recoverable even if file write crashes
        try:
            atomic_write(path, after)
        except Exception:
            change["status"] = "failed"
            self.save()
            raise
        change["status"] = "applied"
        self.save()
        return {"changed": True, "sha256": digest(after),
                "diff": self.workspace.diff(name, before, after)[:16000]}

    def rollback(self):
        # Preflight the complete reverse chain before modifying any user files.
        virtual = {}
        changes = [c for c in self.state["changes"] if c["status"] in ("applied", "pending")]
        operations = []
        for change in reversed(changes):
            name = change["path"]
            path = self.workspace.resolve(name)
            if name not in virtual:
                virtual[name] = path.read_bytes() if path.exists() else None
            current = digest(virtual[name]) if virtual[name] is not None else None
            if change["status"] == "pending" and current == change["before_sha256"]:
                continue
            if current != change["after_sha256"]:
                raise ValueError(f"Rollback conflict: {name} was changed outside this session")
            before = base64.b64decode(change["before"]) if change["before"] is not None else None
            if before is not None and digest(before) != change["before_sha256"]:
                raise ValueError("Corrupt rollback snapshot")
            virtual[name] = before
            operations.append((change, path, before))
        for change, path, before in operations:
            if before is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, before)
            change["status"] = "reverted"
            self.save()
        self.state["status"] = "rolled_back"
        self.state["verified_revision"] = None
        self.save()
        return len(operations)

    def diff(self):
        originals = {}
        for change in self.state["changes"]:
            if change["status"] in ("pending", "applied") and change["path"] not in originals:
                originals[change["path"]] = (
                    base64.b64decode(change["before"]) if change["before"] is not None else None)
        parts = []
        for name, original in originals.items():
            path = self.workspace.resolve(name)
            current = self.workspace.read_bytes(name) if path.exists() else b""
            parts.append(self.workspace.diff(name, original, current))
        return "".join(parts)
