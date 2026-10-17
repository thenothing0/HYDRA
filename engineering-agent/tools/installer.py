"""
╔══════════════════════════════════════════════════════════════╗
║  Cross-IDE Installer — Install HYDRA for any AI coding tool ║
║  Supports: Claude, Codex, Gemini, Cursor, Windsurf, etc.   ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import logging
import shutil
from pathlib import Path

logger = logging.getLogger("hydra.installer")

REPO_ROOT = Path(__file__).parent.parent
PROVIDERS_DIR = REPO_ROOT / "providers"

TARGETS = {
    "claude": {"src": "claude", "dest_files": {"CLAUDE.md": "CLAUDE.md"}},
    "codex": {"src": "codex", "dest_files": {"AGENTS.md": "AGENTS.md"}},
    "gemini": {"src": "gemini", "dest_files": {"GEMINI.md": "GEMINI.md"}},
    "cursor": {"src": "cursor", "dest_dir": ".cursor"},
    "windsurf": {"src": "windsurf", "dest_dir": ".windsurf"},
    "copilot": {"src": "copilot", "dest_dir": ".github"},
    "openclaw": {"src": "openclaw", "dest_files": {"AGENTS.md": "AGENTS.md"}},
}


def install(target: str, project_dir: str = ".", scope: str = "project"):
    """Install HYDRA provider configs for a specific IDE target."""
    project = Path(project_dir)
    if target == "all":
        for t in TARGETS:
            install(t, project_dir, scope)
        return

    info = TARGETS.get(target)
    if not info:
        print(f"Unknown target: {target}. Available: {', '.join(TARGETS.keys())}, all")
        return

    src_dir = PROVIDERS_DIR / info["src"]
    if not src_dir.exists():
        print(f"Provider directory not found: {src_dir}")
        return

    # Copy files
    if "dest_files" in info:
        for src_name, dest_name in info["dest_files"].items():
            src_file = src_dir / src_name
            dest_file = project / dest_name
            if src_file.exists():
                shutil.copy2(src_file, dest_file)
                print(f"  ✅ {target}: {dest_file}")

    if "dest_dir" in info:
        dest = project / info["dest_dir"]
        if src_dir.exists():
            shutil.copytree(src_dir / info.get("src_subdir", info["dest_dir"]),
                          dest, dirs_exist_ok=True)
            print(f"  ✅ {target}: {dest}/")

    # Copy MCP config
    mcp_src = REPO_ROOT / ".mcp.json"
    if mcp_src.exists() and target in ("claude", "codex", "cursor"):
        mcp_dest = project / ".mcp.json"
        if not mcp_dest.exists():
            shutil.copy2(mcp_src, mcp_dest)
            print(f"  ✅ Copied .mcp.json")


def main():
    parser = argparse.ArgumentParser(description="Install HYDRA for AI coding tools")
    sub = parser.add_subparsers(dest="command")

    install_cmd = sub.add_parser("install", help="Install provider configs")
    install_cmd.add_argument("--target", required=True,
                            choices=list(TARGETS.keys()) + ["all"])
    install_cmd.add_argument("--scope", default="project",
                            choices=["project", "global"])
    install_cmd.add_argument("--dir", default=".", help="Project directory")

    list_cmd = sub.add_parser("list", help="List available targets")

    args = parser.parse_args()
    if args.command == "install":
        install(args.target, args.dir, args.scope)
    elif args.command == "list":
        for name in TARGETS:
            print(f"  {name}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
