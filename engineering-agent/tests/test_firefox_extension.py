import json
from pathlib import Path
from zipfile import ZipFile

from tools.build_firefox_extension import build


def test_firefox_build_uses_shared_sources_and_event_page(tmp_path):
    import shutil
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "extensions/hydra-browser", tmp_path / "extensions/hydra-browser")
    result = build(tmp_path)
    manifest = json.loads((result / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["background"] == {"page": "background.html", "persistent": False}
    assert "minimum_chrome_version" not in manifest
    assert manifest["browser_specific_settings"]["gecko"]["id"]
    assert 'type="module"' in (result / "background.html").read_text()
    assert (result / "background.js").read_text(encoding="utf-8") == (root / "extensions/hydra-browser/background.js").read_text(encoding="utf-8")
    with ZipFile(tmp_path / "output/hydra-browser-firefox.zip") as archive:
        assert "manifest.json" in archive.namelist()
        assert "background.html" in archive.namelist()
        assert not any("tests/" in name for name in archive.namelist())
