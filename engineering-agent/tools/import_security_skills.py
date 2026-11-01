"""Copy the user's security/OWASP skill packages, preserving resources and provenance."""

import argparse
import ast
from datetime import date
import hashlib
import json
from pathlib import Path
import re

import yaml


def sha(data):
    return hashlib.sha256(data).hexdigest()


def import_skills(source, destination, imported_on):
    source, destination = Path(source).resolve(strict=True), Path(destination).resolve()
    previous_path = destination / "catalog.json"
    previous = json.loads(previous_path.read_text(encoding="utf-8")) if previous_path.exists() else {"skills": []}
    previous_files = {f"{entry['name']}/{name}": item["sha256"]
                      for entry in previous["skills"] for name, item in entry["files"].items()}
    packages = sorted(p for p in source.iterdir() if p.is_dir()
                      and p.name.startswith(("security-", "owasp-2025-")) and (p / "SKILL.md").is_file())
    if not packages:
        raise ValueError("No security/OWASP SKILL.md packages found")
    entries, pending, warnings = [], [], []
    for directory in packages:
        if directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction()):
            raise ValueError("Skill packages cannot be aliases")
        content = (directory / "SKILL.md").read_text(encoding="utf-8")
        sections = content.split("---", 2)
        if len(sections) != 3 or sections[0].strip():
            raise ValueError(f"Missing skill frontmatter: {directory.name}")
        metadata = yaml.safe_load(sections[1])
        name, description = metadata.get("name"), metadata.get("description")
        if name != directory.name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            raise ValueError(f"Skill identity mismatch: {directory.name}")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"Missing skill description: {name}")
        files = {}
        for path in sorted(directory.rglob("*")):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError(f"Aliased skill resource: {name}")
            if not path.is_file():
                continue
            relative = path.relative_to(directory).as_posix()
            if any(part.startswith(".") for part in path.relative_to(directory).parts):
                raise ValueError(f"Hidden resource requires review: {name}/{relative}")
            data = path.read_bytes()
            if len(data) > 512000:
                raise ValueError(f"Oversized resource: {name}/{relative}")
            if re.search(rb'(?:oc_sk_|cc_|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{16,}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----', data):
                raise ValueError(f"Credential-like resource requires review: {name}/{relative}")
            if path.suffix == ".py":
                ast.parse(data.decode("utf-8"), filename=relative)
            target = destination / name / relative
            checked = destination
            for part in (name, *Path(relative).parts):
                checked = checked / part
                if checked.is_symlink() or (hasattr(checked, "is_junction") and checked.is_junction()):
                    raise ValueError(f"Aliased import destination: {name}/{relative}")
            if target.exists() and target.read_bytes() != data and sha(target.read_bytes()) != previous_files.get(f"{name}/{relative}"):
                raise ValueError(f"Independent bundled changes preserved: {name}/{relative}")
            files[relative] = {"sha256": sha(data), "bytes": len(data)}
            pending.append((target, data))
        for match in re.finditer(r'\[[^\]\n]*\]\(([^)\n]+)\)', content):
            target = match.group(1).split("#", 1)[0]
            if target and not re.match(r"[a-z]+://", target) and not (directory / target).is_file():
                warnings.append(f"{name}: {target}")
        entries.append({"name": name, "description": description.strip(),
                        "family": "owasp-2025" if name.startswith("owasp-") else "security",
                        "sha256": sha(json.dumps(files, sort_keys=True).encode("utf-8")),
                        "entrypoint_sha256": files["SKILL.md"]["sha256"], "files": files})
    catalog = {"schema": 1, "imported_on": imported_on, "source": "user-authored local security and OWASP skills",
               "skills": entries, "source_link_warnings": warnings}
    # Validate everything before writing; never delete unlisted or independently edited files.
    for target, data in pending:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
    destination.mkdir(parents=True, exist_ok=True)
    previous_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"skills": len(entries), "files": len(pending), "bytes": sum(len(d) for _, d in pending),
                      "source_link_warnings": warnings}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path.home() / ".codex/skills")
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parents[1] / "skills/security")
    parser.add_argument("--imported-on", default=date.today().isoformat())
    args = parser.parse_args()
    import_skills(args.source, args.destination, args.imported_on)
