"""Console setup shared by all command entry points; no import-time mutation."""

import os
import sys


def configure_console():
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
