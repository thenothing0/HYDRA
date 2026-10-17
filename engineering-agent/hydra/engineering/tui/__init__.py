"""Optional terminal presentation; the core runtime does not require Textual."""


def launch(args):
    try:
        from hydra.engineering.tui.app import EngineeringApp
    except ModuleNotFoundError as error:
        if error.name and error.name.split(".")[0] == "textual":
            raise RuntimeError("Install the terminal UI: python -m pip install -r requirements-tui.txt") from None
        raise
    from hydra.engineering.tui.controller import RunOptions

    EngineeringApp(args.workspace, RunOptions.from_args(args)).run()
