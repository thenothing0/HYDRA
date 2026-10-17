"""Small terminal widgets. Repository/model content is always rendered as text."""

import json
import re

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Select, Static, TextArea


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

    def __init__(self, argv, *, title="Command approval", description=None):
        super().__init__()
        self.argv = list(argv)
        self.title_text = title
        self.description = description or "This command runs with your OS permissions. Allow this execution once?"

    def compose(self) -> ComposeResult:
        with Vertical(id="approval-dialog"):
            yield Label(self.title_text, classes="dialog-title")
            yield Static(Text(safe_text(json.dumps(self.argv, ensure_ascii=False, indent=2))), id="command-preview")
            yield Label(self.description)
            with Horizontal(classes="dialog-buttons"):
                yield Button("Deny", id="deny")
                yield Button("Allow once", id="allow", variant="primary")

    def on_mount(self):
        self.query_one("#deny", Button).focus()

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(event.button.id == "allow")

    def action_deny(self):
        self.dismiss(False)


class ModelSelection(ModalScreen[tuple[str, str] | None]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel", priority=True),
        Binding("ctrl+f", "favorite", "Favorite", priority=True),
        Binding("ctrl+o", "default", "Set default", priority=True),
    ]

    def __init__(self, providers, provider, model, *, preferences=None, discover=None):
        super().__init__()
        self.providers = {p["id"]: p for p in providers}
        self.provider = provider
        self.model = model or ""
        from hydra.engineering.models import ModelPreferences, local_models

        self.preferences = preferences or ModelPreferences()
        self.discover = discover
        self.entries = local_models(providers, (provider, model), self.preferences)
        self.visible_entries = []

    def compose(self) -> ComposeResult:
        with Vertical(id="model-dialog"):
            yield Label("Choose model", classes="dialog-title")
            yield Input(placeholder="Search provider or model", id="model-search")
            yield DataTable(id="model-list", cursor_type="row")
            yield Static(
                "Saved/configured models. Refresh fetches the selected provider's current catalog.",
                id="model-list-status",
            )
            yield Label("Provider")
            yield Select(
                [(p["id"], p["id"]) for p in self.providers.values()],
                value=self.provider,
                allow_blank=False,
                id="model-provider",
            )
            yield Label("Exact model ID")
            yield Input(self.model, placeholder="Enter the model ID for this provider", id="model-id")
            yield Static("Enter a row to select. Ctrl+F favorite · Ctrl+O default. Changes apply to the next request.")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Refresh list", id="model-refresh", disabled=self.discover is None)
                yield Button("Cancel", id="model-cancel")
                yield Button("Apply", id="model-apply", variant="primary")

    def on_mount(self):
        self.query_one("#model-list", DataTable).add_columns("★", "Provider", "Model", "Method")
        self.refresh_rows()
        self.query_one("#model-id", Input).focus()

    def refresh_rows(self):
        table = self.query_one("#model-list", DataTable)
        table.clear()
        search = self.query_one("#model-search", Input).value.casefold()
        self.visible_entries = [
            entry for entry in self.entries if search in (entry["provider"] + " " + entry["id"]).casefold()
        ]
        self.visible_entries.sort(
            key=lambda entry: (
                (entry["provider"], entry["id"]) not in self.preferences.favorites,
                entry["provider"],
                entry["id"],
            )
        )
        for entry in self.visible_entries:
            pair = (entry["provider"], entry["id"])
            marker = ("★" if pair in self.preferences.favorites else "") + (
                " ✓" if pair == self.preferences.default else ""
            )
            table.add_row(
                Text(marker), Text(safe_text(entry["provider"])), Text(safe_text(entry["id"])), entry["method"]
            )

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "model-search" and self.is_mounted:
            self.refresh_rows()

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        entry = self.visible_entries[event.cursor_row]
        self.provider = entry["provider"]
        self.query_one("#model-provider", Select).value = self.provider
        self.query_one("#model-id", Input).value = entry["id"]
        self.apply_selection()

    def selected_pair(self):
        table = self.query_one("#model-list", DataTable)
        if table.has_focus and self.visible_entries:
            entry = self.visible_entries[table.cursor_row]
            return entry["provider"], entry["id"]
        return self.provider, self.query_one("#model-id", Input).value.strip()

    def action_favorite(self):
        provider, model = self.selected_pair()
        if model:
            try:
                self.preferences.toggle(provider, model)
                if not any(e["provider"] == provider and e["id"] == model for e in self.entries):
                    from hydra.engineering.models import auth_method

                    self.entries.append({"provider": provider, "id": model, "method": auth_method(provider)})
                self.refresh_rows()
            except OSError:
                self.notify("Unable to save model preferences.", severity="error")

    def action_default(self):
        provider, model = self.selected_pair()
        if model:
            try:
                self.preferences.set_default(provider, model)
                self.refresh_rows()
                self.notify("Default model saved for future launches.")
            except OSError:
                self.notify("Unable to save model preferences.", severity="error")

    async def load_models(self):
        import aiohttp

        button = self.query_one("#model-refresh", Button)
        button.disabled = True
        provider = self.provider
        status = self.query_one("#model-list-status", Static)
        status.update("Loading " + provider + " models…")
        try:
            entries = await self.discover(provider)
            existing = {(e["provider"], e["id"]): e for e in self.entries}
            existing.update({(e["provider"], e["id"]): e for e in entries})
            self.entries = list(existing.values())
            self.refresh_rows()
            status.update(Text(f"Loaded {len(entries)} models from {provider}. Availability depends on your account."))
        except (ValueError, OSError, aiohttp.ClientError) as error:
            status.update(Text(safe_text(error, 300)))
        finally:
            button.disabled = False

    def on_select_changed(self, event: Select.Changed):
        if event.select.id != "model-provider" or event.value == self.provider:
            return
        self.provider = str(event.value)
        # Keep model IDs scoped to their provider; configured defaults are local metadata.
        self.query_one("#model-id", Input).value = self.providers[self.provider].get("model") or ""

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "model-search":
            self.query_one("#model-list", DataTable).focus()
        else:
            self.apply_selection()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "model-apply":
            self.apply_selection()
        elif event.button.id == "model-refresh":
            self.run_worker(self.load_models(), exclusive=True, exit_on_error=False)
        else:
            self.action_cancel()

    def apply_selection(self):
        model = self.query_one("#model-id", Input).value.strip()
        if not model:
            self.notify("Enter a model ID before applying.", severity="warning")
            self.query_one("#model-id", Input).focus()
            return
        self.dismiss((self.provider, model))

    def action_cancel(self):
        self.dismiss(None)
