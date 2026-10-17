"""Authorized subprocess lifecycle and bounded output capture."""

import asyncio
import inspect
import os
import signal


class ProcessRunner:
    def __init__(self, workspace, approve):
        self.workspace = workspace
        self.approve = approve

    async def run(self, argv, timeout):
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 80
            or any(not isinstance(a, str) or "\0" in a for a in argv)
        ):
            raise ValueError("argv must be a nonempty list of text arguments")
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise ValueError("Command timeout must be between 0 and 120 seconds")
        approval = self.approve(argv)
        if inspect.isawaitable(approval):
            approval = await approval
        if not approval:
            raise PermissionError("Command not authorized by the operator")
        # stdout is drained continuously but only the first 16 KB is retained.
        options = {"start_new_session": True} if os.name != "nt" else {}
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=self.workspace.root,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **options,
        )
        captured = bytearray()
        total = 0

        async def collect():
            nonlocal total
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                total += len(chunk)
                captured.extend(chunk[: max(0, 16000 - len(captured))])
            await process.wait()

        timed_out = False
        try:
            await asyncio.wait_for(collect(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            if process.returncode is None:
                if os.name == "nt":
                    killer = await asyncio.create_subprocess_exec(
                        "taskkill",
                        "/PID",
                        str(process.pid),
                        "/T",
                        "/F",
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await killer.wait()
                    if process.returncode is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            # Drain remaining pipe data after stopping the process; waiting on
            # an exited child alone can hang when its stdout buffer is full.
            await asyncio.wait_for(process.communicate(), timeout=5)
            if isinstance(exc, asyncio.CancelledError):
                raise
            timed_out = True
        return {
            "success": process.returncode == 0 and not timed_out,
            "argv": argv,
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "output": captured.decode("utf-8", errors="replace"),
            "truncated": total > len(captured),
        }
