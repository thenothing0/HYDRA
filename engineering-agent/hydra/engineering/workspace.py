"""Bounded workspace access and content-addressed file changes."""
import difflib
import fnmatch
import hashlib
import os
import tempfile
from pathlib import Path


EXCLUDED = {".git", ".hydra", ".venv", "venv", "node_modules", ".tools",
            "__pycache__", ".pytest_cache", "dist", "build", "target", "output", "logs", "coverage"}
SECRET_SUFFIXES = {".pem", ".key", ".pfx", ".p12"}
MAX_FILE_BYTES = 512_000


def digest(content):
    return hashlib.sha256(content).hexdigest()


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".hydra-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists():
            os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Workspace:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Workspace must be a directory")

    def resolve(self, name):
        if not isinstance(name, str) or not name or Path(name).is_absolute():
            raise ValueError("Use a relative workspace path")
        parts = Path(name).parts
        if any(p.casefold() in EXCLUDED or p == ".." for p in parts):
            raise ValueError("Protected or parent path")
        if any(":" in p or p.endswith((".", " ")) for p in parts):
            raise ValueError("Ambiguous path or alternate data stream")
        if any(p.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
                                             *[f"LPT{i}" for i in range(1, 10)]} for p in parts):
            raise ValueError("Reserved device path")
        if any(p.casefold() == ".env" or p.casefold().startswith(".env.") for p in parts):
            if Path(name).name.casefold() != ".env.example" or any(p.casefold() == ".env" for p in parts[:-1]):
                raise ValueError("Secret files cannot be accessed")
        if Path(name).suffix.lower() in SECRET_SUFFIXES:
            raise ValueError("Private-key files cannot be accessed")
        path = (self.root / name).resolve()
        if not path.is_relative_to(self.root) or path == self.root:
            raise ValueError("Path escapes workspace")
        # Reject aliases through symlinks/junctions, including ones inside root.
        current = self.root
        for part in parts:
            current = current / part
            if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
                raise ValueError("Symlink/junction access is not allowed")
        return path

    def files(self, pattern="*", limit=250):
        found = []
        for directory, dirs, names in os.walk(self.root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d.casefold() not in EXCLUDED
                             and not Path(directory, d).is_symlink()
                             and not (hasattr(Path(directory, d), "is_junction")
                                      and Path(directory, d).is_junction()))
            for name in sorted(names):
                relative = Path(directory, name).relative_to(self.root).as_posix()
                try:
                    self.resolve(relative)
                except ValueError:
                    continue
                if fnmatch.fnmatch(relative, pattern):
                    found.append(relative)
                    if len(found) >= limit:
                        return found
        return found

    def read_bytes(self, name):
        path = self.resolve(name)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("File exceeds 512 KB tool limit")
        content = path.read_bytes()
        if b"\0" in content:
            raise ValueError("Binary files are not supported")
        content.decode("utf-8")
        return content

    def read(self, name, start=1, lines=200):
        if type(start) is not int or start < 1 or type(lines) is not int or not 1 <= lines <= 300:
            raise ValueError("start must be positive; lines must be 1..300")
        content = self.read_bytes(name)
        all_lines = content.decode("utf-8").splitlines()
        selected = []
        size = 0
        for i, line in enumerate(all_lines[start-1:start-1+lines], start):
            item = f"{i}: {line}"
            if size + len(item) + 1 > 16000:
                if not selected:
                    raise ValueError("A source line exceeds the bounded read limit")
                break
            selected.append(item)
            size += len(item) + 1
        return {"path": name, "sha256": digest(content), "total_lines": len(all_lines),
                "start_line": start, "end_line": start + len(selected) - 1,
                "content": "\n".join(selected)}

    def search(self, query, pattern="*", limit=50):
        if not isinstance(query, str) or not query:
            raise ValueError("Search query must be nonempty text")
        matches = []
        for name in self.files(pattern, limit=2000):
            try:
                content = self.read_bytes(name).decode("utf-8")
            except (OSError, ValueError, UnicodeError):
                continue
            for number, line in enumerate(content.splitlines(), 1):
                if query in line:
                    matches.append({"path": name, "line": number, "text": line[:400]})
                    if len(matches) >= limit:
                        return matches
        return matches

    @staticmethod
    def diff(name, before, after):
        return "".join(difflib.unified_diff(
            (before or b"").decode("utf-8").splitlines(keepends=True),
            after.decode("utf-8").splitlines(keepends=True),
            fromfile=f"a/{name}", tofile=f"b/{name}"))
