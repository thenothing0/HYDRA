"""Progressive skill use with real helpers, guarded resources and durable selection."""

import json
import os
import runpy
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.cli import main, parser
from hydra.engineering.session import Session
from hydra.engineering.skills import SkillCatalog
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace, digest


@pytest.fixture
def fixture_catalog(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    package = root / "security-fixture"
    (package / "scripts").mkdir(parents=True)
    (package / "references").mkdir()
    (package / "SKILL.md").write_text("---\nname: security-fixture\ndescription: Review the owned fixture boundary\n---\n\nRead references/procedure.md before checking the fixture.\n", encoding="utf-8")
    (package / "references/procedure.md").write_text("Compare the owned fixture and its permitted control.\n", encoding="utf-8")
    (package / "scripts/helper.py").write_text("from pathlib import Path\nimport sys\nPath('marker.txt').write_text(sys.argv[1])\nprint('owned helper executed')\n", encoding="utf-8")

    def refresh():
        files = {p.relative_to(package).as_posix(): {"bytes": len(p.read_bytes()), "sha256": digest(p.read_bytes())}
                 for p in package.rglob("*") if p.is_file()}
        entry = {"name": package.name, "description": "Review the owned fixture boundary", "files": files,
                 "entrypoint_sha256": files["SKILL.md"]["sha256"],
                 "sha256": digest(json.dumps(files, sort_keys=True).encode("utf-8"))}
        (root / "catalog.json").write_text(json.dumps({"schema": 1, "skills": [entry]}), encoding="utf-8")
        return SkillCatalog(root)

    catalog = refresh()
    monkeypatch.setattr("hydra.engineering.tools.SkillCatalog", lambda: catalog)
    return catalog, package, refresh


def test_bundled_catalog_preserves_all_packages_and_resources():
    catalog = SkillCatalog()
    assert len(catalog.list()) == 300
    assert catalog.search("xss")[0]["name"] == "security-xss-review"
    assert catalog.search("security-api-bola-review")[0]["name"] == "security-api-bola-review"
    assert "content" not in catalog.search("xss")[0]
    resources = 0
    for name, entry in catalog.entries.items():
        for resource in entry["files"]:
            assert catalog.verified_path(name, resource).is_file()
            resources += 1
    assert resources == 2069


def test_resource_pagination_reconstructs_the_original(fixture_catalog):
    catalog, package, _ = fixture_catalog
    pages, start = [], 1
    while start:
        result = catalog.read("security-fixture", "SKILL.md", start=start, lines=2)
        pages.append(result["content"])
        start = result["next_line"]
    assert "".join(pages) == (package / "SKILL.md").read_text(encoding="utf-8")
    assert "scripts/helper.py" in result["resources"]


@pytest.mark.parametrize("resource", ["../secret.txt", "/etc/passwd", "C:/private.txt", "references/../../secret", ".env", "scripts\\helper.py"])
def test_only_manifest_resources_can_be_read(fixture_catalog, resource):
    catalog, _, _ = fixture_catalog
    with pytest.raises(ValueError):
        catalog.read("security-fixture", resource)


def test_modified_resource_fails_integrity_check(fixture_catalog):
    catalog, package, _ = fixture_catalog
    (package / "references/procedure.md").write_text("changed guidance", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        catalog.read("security-fixture", "references/procedure.md")


def test_resource_symlink_is_refused_even_with_matching_content(fixture_catalog, tmp_path):
    catalog, package, _ = fixture_catalog
    outside = tmp_path / "outside.txt"
    original = package / "references/procedure.md"
    outside.write_bytes(original.read_bytes())
    original.unlink()
    try:
        original.symlink_to(outside)
    except OSError:
        pytest.skip("Symlinks unavailable to this account")
    with pytest.raises(ValueError, match="symlink"):
        catalog.read("security-fixture", "references/procedure.md")


@pytest.mark.asyncio
async def test_reading_and_selecting_do_not_execute_helpers(fixture_catalog, tmp_path):
    session = Session(Workspace(tmp_path), goal="Review the owned fixture")
    tools = EngineeringTools(session, read_only=True)
    result = await tools.execute("skill_use", {"name": "security-fixture"})
    assert result["selected"] == ["security-fixture"]
    assert (await tools.execute("skill_read", {"name": "security-fixture", "resource": "references/procedure.md"}))["content"]
    assert not (tmp_path / "marker.txt").exists()
    saved = Session(session.workspace, session_id=session.state["id"])
    assert saved.state["skills"][0]["sha256"] == fixture_catalog[0].metadata("security-fixture")["sha256"]
    with pytest.raises(PermissionError):
        await tools.execute("skill_run", {"name": "security-fixture", "script": "scripts/helper.py", "arguments": ["not allowed"]})


@pytest.mark.asyncio
async def test_helper_needs_approval_and_invalidates_prior_verification(fixture_catalog, tmp_path):
    session = Session(Workspace(tmp_path), goal="Run owned helper")
    denied = EngineeringTools(session, approve=lambda argv: False)
    with pytest.raises(PermissionError):
        await denied.execute("skill_run", {"name": "security-fixture", "script": "scripts/helper.py", "arguments": ["denied"]})
    assert not (tmp_path / "marker.txt").exists()
    approvals = []
    def approve(argv):
        approvals.append(argv)
        return True
    allowed = EngineeringTools(session, approve=approve)
    session.state["verified_revision"] = 0
    session.save()
    result = await allowed.execute("skill_run", {"name": "security-fixture", "script": "scripts/helper.py", "arguments": ["allowed"]})
    assert result["success"] and (tmp_path / "marker.txt").read_text() == "allowed"
    assert approvals[0][0] == sys.executable
    assert session.state["verified_revision"] is None and session.state["command_dirty"]


def test_resume_pins_the_entire_package_not_only_the_entrypoint(fixture_catalog, tmp_path, monkeypatch):
    catalog, package, refresh = fixture_catalog
    session = Session(Workspace(tmp_path), goal="Review fixture")
    tools = EngineeringTools(session, skills=["security-fixture"])
    old = session.state["skills"][0]["sha256"]
    (package / "references/procedure.md").write_text("Revised control procedure\n", encoding="utf-8")
    updated = refresh()
    assert updated.metadata("security-fixture")["sha256"] != old
    monkeypatch.setattr("hydra.engineering.tools.SkillCatalog", lambda: updated)
    resumed = Session(session.workspace, session_id=session.state["id"])
    with pytest.raises(ValueError, match="changed since"):
        EngineeringTools(resumed)
    reviewed = EngineeringTools(resumed, skills=["security-fixture"])
    assert reviewed.skill_selection.active[0]["sha256"] == updated.metadata("security-fixture")["sha256"]
    assert tools.skill_selection.active[0]["sha256"] == old


def test_default_prompt_uses_small_metadata_hints_not_all_instructions(tmp_path):
    session = Session(Workspace(tmp_path), goal="Inspect XSS data flow")
    agent = EngineeringAgent(session, object())
    context = json.loads(agent.prompt().split("SESSION DATA:\n", 1)[1])
    assert context["skills"]["catalog_size"] == 300
    assert not context["skills"]["selected"]
    assert len(context["skills"]["suggestions"]) <= 5
    assert len(agent.prompt()) < 24000
    assert "hackerone_submit" not in context["tools"]
    session.state["goal"] = "Long valid task context " * 100
    assert len(agent.prompt()) > 1000


@pytest.mark.asyncio
async def test_model_selects_a_skill_and_receives_its_instructions(fixture_catalog, tmp_path):
    prompts = []
    actions = [{"tool": "skill_use", "arguments": {"name": "security-fixture"}},
               {"tool": "skill_read", "arguments": {"name": "security-fixture", "resource": "references/procedure.md"}},
               {"tool": "finish", "arguments": {"summary": "Inspected the fixture procedure; no execution requested"}}]
    class Model:
        async def respond(self, prompt):
            prompts.append(prompt)
            return json.dumps(actions.pop(0))
    session = Session(Workspace(tmp_path), goal="Read the fixture skill and its procedure")
    result = await EngineeringAgent(session, Model()).run()
    assert result["status"] == "completed"
    second = json.loads(prompts[1].split("SESSION DATA:\n", 1)[1])
    assert "Read references/procedure.md" in second["skills"]["selected"][0]["content"]
    assert not (tmp_path / "marker.txt").exists()
    assert result["skills"][0]["name"] == "security-fixture"


@pytest.mark.asyncio
async def test_cli_discovery_does_not_create_sessions(tmp_path, capsys):
    assert await main(["skills", "search", "xss", "--json", "--workspace", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["total"] == 300 and result["skills"][0]["name"] == "security-xss-review"
    assert not (tmp_path / ".hydra").exists()
    parsed = parser().parse_args(["tui", "--skill", "security-xss-review"])
    assert parsed.skills == ["security-xss-review"]


@pytest.mark.parametrize("invalid", [["name"], [{"name": "security-fixture", "sha256": "bad"}], [{"name": "../other", "sha256": "a" * 64}]])
def test_selected_skill_state_must_validate(tmp_path, invalid):
    session = Session(Workspace(tmp_path), goal="Inspect")
    session.state["skills"] = invalid
    with pytest.raises(ValueError, match="skill"):
        session.save()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,script", [
    ("security-finding-report", "scripts/security_reports.py"),
    ("owasp-2025-a01-broken-access-control", "scripts/security_workflow.py"),
])
async def test_imported_offline_helpers_run_through_the_real_cli(tmp_path, capsys, name, script):
    result = await main(["skills", "run", "--workspace", str(tmp_path), "--allow-run", name, script, "--", "--help"])
    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["success"] and "usage:" in report["output"].lower()


def test_importer_preserves_independent_changes_and_checks_credentials(tmp_path):
    importer = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/import_security_skills.py"))["import_skills"]
    source, destination = tmp_path / "source", tmp_path / "destination"
    package = source / "security-fixture"
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text("---\nname: security-fixture\ndescription: Review the fixture\n---\nOwned fixture.\n", encoding="utf-8")
    importer(source, destination, "2026-11-01")
    imported = destination / "security-fixture/SKILL.md"
    imported.write_text("An independent local edit", encoding="utf-8")
    with pytest.raises(ValueError, match="Independent"):
        importer(source, destination, "2026-11-01")
    assert imported.read_text(encoding="utf-8") == "An independent local edit"
    (package / "secret.txt").write_text("ghp_" + "x" * 36, encoding="utf-8")
    second = tmp_path / "second-destination"
    with pytest.raises(ValueError, match="Credential-like"):
        importer(source, second, "2026-11-01")
    assert not second.exists()


def test_git_checkout_preserves_resource_hashes_with_autocrlf(fixture_catalog, tmp_path):
    executable = os.environ.get("GIT_EXECUTABLE") or shutil.which("git")
    if not executable:
        pytest.skip("Git is needed for the cross-platform snapshot check")
    _, package, refresh = fixture_catalog
    for path in package.rglob("*"):
        if path.is_file():
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    catalog = refresh()
    repository = tmp_path / "git-fixture"
    repository.mkdir()
    (repository / ".gitattributes").write_bytes((Path(__file__).resolve().parents[1] / ".gitattributes").read_bytes())
    shutil.copytree(catalog.root, repository / "skills/security")
    def git(*args):
        return subprocess.run([executable, *args], cwd=repository, check=True, capture_output=True)
    git("init", "-q")
    git("-c", "core.autocrlf=true", "add", ".")
    restored = tmp_path / "fresh-checkout"
    git("-c", "core.autocrlf=true", "checkout-index", "--all", "--prefix=" + restored.as_posix() + "/")
    checkout = SkillCatalog(restored / "skills/security")
    for resource in checkout.entry("security-fixture")["files"]:
        assert checkout.verified_path("security-fixture", resource).read_bytes() == catalog.verified_path("security-fixture", resource).read_bytes()
