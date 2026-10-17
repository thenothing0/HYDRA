"""Live subprocess boundary, independently covered by the security harness."""
import shutil
import subprocess
import sys
import time
from typing import List, Optional


def execute_tool(cmd: List[str], timeout: int = 120, stdin_data: Optional[str] = None, *,
                 finalize, use_tor=False, proxychains_bin=None, max_output_chars=500_000) -> dict:
    """Execute a real system tool via subprocess. No mocking. shell=False."""
    binary = cmd[0]
    path = shutil.which(binary)
    if not path:
        return finalize(binary, cmd, {
            "success": False,
            "error": f"Tool '{binary}' not installed. Install it first.",
            "output": "",
        })

    if use_tor and proxychains_bin:
        cmd = [proxychains_bin, "-q"] + cmd

    print(f"[HYDRA] {'[TOR] ' if use_tor else ''}Running: {' '.join(cmd)}", file=sys.stderr)
    start = time.time()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
        )
        elapsed = round(time.time() - start, 2)
        stdout = proc.stdout
        stderr = proc.stderr

        # Truncate oversized output to prevent MCP protocol overload
        truncated = False
        if len(stdout) > max_output_chars:
            stdout = stdout[:max_output_chars] + f"\n... [TRUNCATED — {len(proc.stdout)} total chars]"
            truncated = True

        return finalize(binary, cmd, {
            "success": proc.returncode == 0,
            "output": stdout,
            "stderr": stderr[:50000] if len(stderr) > 50000 else stderr,
            "return_code": proc.returncode,
            "elapsed_seconds": elapsed,
            "truncated": truncated,
        }, elapsed)
    except subprocess.TimeoutExpired as e:
        # Capture whatever the tool emitted before it was killed — crawlers
        # (katana/gau/hakrawler) often produce useful partial output before timeout.
        partial = e.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        truncated = False
        if len(partial) > max_output_chars:
            partial = partial[:max_output_chars] + f"\n... [TRUNCATED — partial output before {timeout}s timeout]"
            truncated = True
        note = f"Timeout after {timeout}s" + (" (partial output returned)" if partial else "")
        return finalize(binary, cmd,
                         {"success": bool(partial), "error": note,
                          "output": partial, "timed_out": True, "truncated": truncated},
                         round(time.time() - start, 2))
    except Exception as e:
        return finalize(binary, cmd,
                         {"success": False, "error": str(e), "output": ""},
                         round(time.time() - start, 2))

