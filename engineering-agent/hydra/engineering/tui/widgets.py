"""Small terminal widgets. Repository/model content is always rendered as text."""

import json
import re

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static, TextArea


def safe_text(value, limit=16000):
    text = str(value)
    text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", text)
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32 and not 127 <= ord(c) < 160)[:limit]


class Prompt(TextArea):
    BINDINGS = [
        Binding("enter", "send", show=False, priority=True),
        Binding("ctrl+enter", "send", show=False, priority=True),
        Binding("ctrl+j", "line_break", show=False, priority=True),
    ]

    class Submitted(Message):
        def __init__(self, text):
            super().__init__()
            self.text = text

    def action_send(self):
        if self.text.strip():
            self.post_message(self.Submitted(self.text))

    def action_line_break(self):
        self.insert("\n")


class CommandApproval(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "deny", "Deny", priority=True)]

    def __init__(self, argv):
        super().__init__()
        self.argv = list(argv)

    def compose(self) -> ComposeResult:
        with Vertical(id="approval-dialog"):
            yield Label("Command approval", classes="dialog-title")
            yield Static(Text(safe_text(json.dumps(self.argv, ensure_ascii=False, indent=2))), id="command-preview")
            yield Label("This command runs with your OS permissions. Allow this execution once?")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Deny", id="deny")
                yield Button("Allow once", id="allow", variant="primary")

    def on_mount(self):
        self.query_one("#deny", Button).focus()

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(event.button.id == "allow")

    def action_deny(self):
        self.dismiss(False)
