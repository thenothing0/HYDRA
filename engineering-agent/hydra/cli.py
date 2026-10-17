"""Unified HYDRA command router with explicit runtime boundaries."""

import sys


def route(argv):
    """Select a runtime without importing either execution engine."""
    arguments = list(argv)
    if arguments and arguments[0] in ("security", "engineering"):
        return arguments[0], arguments[1:]
    # Compatibility is based on recognized security options, not any leading '-'.
    if arguments:
        from hydra.security.parser import build_parser

        security_options = build_parser()._option_string_actions
        option = arguments[0].split("=", 1)[0]
        if (
            option not in security_options
            and option.startswith("-")
            and not option.startswith("--")
        ):
            option = option[:2]  # argparse also accepts -tHOST and -wWORKFLOW.
        if option not in ("-h", "--help") and option in security_options:
            return "security", arguments
    return "engineering", arguments


def entry(argv=None):
    runtime, arguments = route(sys.argv[1:] if argv is None else argv)
    if runtime == "security":
        from hydra.security.cli import entry as launch
    else:
        from hydra.engineering.cli import entry as launch
    return launch(arguments)
