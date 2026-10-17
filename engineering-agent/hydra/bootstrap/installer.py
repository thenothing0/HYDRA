"""
╔══════════════════════════════════════════════════════════════╗
║  Auto-Installer — Detects and installs missing tools        ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

from hydra.mcp.tool_server import TOOL_REGISTRY

logger = logging.getLogger("hydra.bootstrap.installer")


def detect_package_manager() -> Optional[str]:
    """Detect the available system package manager."""
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("brew"):
        return "brew"
    if shutil.which("apk"):
        return "apk"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("pacman"):
        return "pacman"
    return None


def detect_go() -> bool:
    """Check if Go is installed."""
    return shutil.which("go") is not None


def detect_pip() -> bool:
    """Check if pip is available."""
    return shutil.which("pip") is not None or shutil.which("pip3") is not None


def get_missing_tools() -> List[str]:
    """Return list of tools that are not installed."""
    missing = []
    for name, tool_def in TOOL_REGISTRY.items():
        if not shutil.which(tool_def["binary"]):
            missing.append(name)
    return missing


def install_tool(name: str, dry_run: bool = False) -> bool:
    """
    Attempt to install a single tool.
    
    Tries in order: go install → pip install → system package manager
    """
    tool_def = TOOL_REGISTRY.get(name)
    if not tool_def:
        logger.error(f"Unknown tool: {name}")
        return False
    
    install_methods = tool_def.get("install", {})
    
    # Try Go install first
    if "go" in install_methods and detect_go():
        cmd = install_methods["go"]
        logger.info(f"  Installing {name} via Go: {cmd}")
        if dry_run:
            return True
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=300,
                env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
            )
            if result.returncode == 0:
                logger.info(f"  ✅ {name} installed successfully via Go")
                return True
            logger.warning(f"  Go install failed: {result.stderr[:200]}")
        except Exception as e:
            logger.warning(f"  Go install error: {e}")
    
    # Try pip install
    if "pip" in install_methods and detect_pip():
        cmd = install_methods["pip"]
        logger.info(f"  Installing {name} via pip: {cmd}")
        if dry_run:
            return True
        try:
            parts = [sys.executable, "-m", "pip", *cmd.split()[1:]]
            result = subprocess.run(parts, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                logger.info(f"  ✅ {name} installed successfully via pip")
                return True
            logger.warning(f"  pip install failed: {result.stderr[:200]}")
        except Exception as e:
            logger.warning(f"  pip install error: {e}")
    
    # Try system package manager
    pkg_mgr = detect_package_manager()
    if pkg_mgr and pkg_mgr in install_methods:
        cmd = install_methods[pkg_mgr]
        logger.info(f"  Installing {name} via {pkg_mgr}: {cmd}")
        if dry_run:
            return True
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                logger.info(f"  ✅ {name} installed successfully via {pkg_mgr}")
                return True
            logger.warning(f"  {pkg_mgr} install failed: {result.stderr[:200]}")
        except Exception as e:
            logger.warning(f"  {pkg_mgr} install error: {e}")
    
    logger.error(f"  ❌ Could not install {name} — install manually")
    return False


def auto_install_all(dry_run: bool = False) -> Dict[str, bool]:
    """Detect and install all missing tools."""
    missing = get_missing_tools()
    
    if not missing:
        logger.info("✅ All security tools are already installed")
        return {}
    
    logger.info(f"🔧 {len(missing)} tools missing: {', '.join(missing)}")
    logger.info(f"  System: {platform.system()} {platform.machine()}")
    logger.info(f"  Package manager: {detect_package_manager() or 'none detected'}")
    logger.info(f"  Go: {'yes' if detect_go() else 'no'}")
    logger.info(f"  pip: {'yes' if detect_pip() else 'no'}")
    
    results = {}
    for tool_name in missing:
        results[tool_name] = install_tool(tool_name, dry_run=dry_run)
    
    installed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    logger.info(f"📊 Install results: {installed} installed, {failed} failed")
    
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    auto_install_all(dry_run="--dry-run" in sys.argv)
