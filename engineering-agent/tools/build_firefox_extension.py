"""Build an unsigned Firefox variant from the shared extension sources."""
import json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED


def build(root):
    root = Path(root)
    source = root / "extensions/hydra-browser"
    destination = root / "output/hydra-browser-firefox"
    destination.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    manifest.pop("minimum_chrome_version", None)
    manifest["background"] = {"page": "background.html", "persistent": False}
    manifest["browser_specific_settings"] = {"gecko": {
        "id": "hydra-browser@hydra.local", "strict_min_version": "128.0"}}
    files = {name: (source / name).read_text(encoding="utf-8") for name in (
        "background.js", "protocol.js", "popup.html", "popup.css", "popup.js")}
    files["manifest.json"] = json.dumps(manifest, indent=2)
    files["background.html"] = '<!doctype html><meta charset="utf-8"><script type="module" src="background.js"></script>\n'
    with ZipFile(root / "output/hydra-browser-firefox.zip", "w", ZIP_DEFLATED) as archive:
        for name, content in files.items():
            (destination / name).write_bytes(content.encode("utf-8"))
            archive.writestr(name, content)
    return destination


if __name__ == "__main__":
    print(build(Path(__file__).resolve().parents[1]))
