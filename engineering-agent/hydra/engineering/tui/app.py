"""Chat-first terminal UI over the real engineering runtime."""

import asyncio
import json

from rich.syntax import Syntax
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Footer, Input, Label, ListItem, ListView, Select, Static, TabbedContent, TabPane
from textual.worker import WorkerCancelled, WorkerFailed

from hydra.engineering.providers import describe_providers, settings
from hydra.engineering.tui.controller import EngineeringController
from hydra.engineering.tui.widgets import CommandApproval, ModelSelection, Prompt, safe_text

HELP = "/new  /sessions  /resume ID  /diff  /plan  /model [ID]  /provider NAME MODEL  /cancel  /help  /quit"


class SessionItem(ListItem):
    def __init__(self, state):
        super().__init__(Label(Text(safe_text(state["goal"], 42) + "\n" + state["status"])), classes="session-item")
        self.session_id = state["id"]


class EngineeringApp(App):
    TITLE = "HYDRA · Engineering"
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "cancel", "Cancel run", priority=True),
        Binding("ctrl+b", "sidebar", "Sessions"),
        Binding("ctrl+d", "diff", "Changes"),
        Binding("ctrl+n", "new", "New session"),
    ]

    def __init__(self, workspace, options, *, model_factory=None):
        super().__init__()
        self.options = options
        self.controller = EngineeringController(
            workspace, options, self.approve_command, self.receive_event, model_factory
        )
        self.agent_worker = None
        self.busy = False
        self._terminal_width = None
        self._catalog = [p for p in describe_providers() if p["status"].startswith("implemented")]
        self.options.provider = {"anthropic": "anthropic-api", "custom": "openai-compatible"}.get(
            self.options.provider, self.options.provider
        )
        if not self.options.provider:
            try:
                config = settings()
                self.options.provider = config.id
                self.options.model = self.options.model or config.model
            except ValueError:
                self.options.provider = "ollama"
        if not self.options.model:
            try:
                self.options.model = settings(self.options.provider).model
            except ValueError:
                self.options.model = ""
        if self.options.provider not in {p["id"] for p in self._catalog}:
            raise ValueError(
                "The selected provider has no implemented transport. Use hydra providers to choose an available profile."
            )

    def compose(self) -> ComposeResult:
        yield Static(" HYDRA  /  ENGINEERING WORKSPACE", id="brand")
        with Horizontal(id="configuration"):
            yield Select(
                [(p["id"] + (" · configured" if p["configured"] else ""), p["id"]) for p in self._catalog],
                value=self.options.provider,
                allow_blank=False,
                id="provider",
            )
            yield Input(self.options.model or "", placeholder="Exact model ID", id="model")
            yield Label(
                "READ ONLY"
                if self.options.read_only
                else "APPROVALS ON"
                if not self.options.allow_run
                else "AUTO APPROVAL",
                id="permissions",
            )
        with Horizontal(id="workspace"):
            with Vertical(id="sessions-panel"):
                yield Label("WORKSPACE", classes="eyebrow")
                yield Static(Text(str(self.controller.workspace.root)), id="workspace-path")
                yield Button("+ New session", id="new-session")
                yield Label("RECENT SESSIONS", classes="eyebrow")
                yield ListView(id="sessions")
                yield Button("Resume selected", id="resume-session")
            with Vertical(id="conversation-column"):
                with VerticalScroll(id="conversation"):
                    yield Static(Text("HYDRA", style="bold cyan"), id="welcome-logo")
                    yield Static(
                        "Build. Fix. Understand.\n\nDescribe a task to inspect your project, make changes and verify them.\nSessions, tool activity and evidence stay in your workspace.\n\nChoose a provider and model above or type /model. Credentials come from your local environment.\nType /help for commands.",
                        id="welcome",
                    )
                yield Static("Ready · no model request sent", id="run-status")
                yield Prompt(id="prompt", show_line_numbers=False)
                yield Static("Enter send  ·  Ctrl+J newline  ·  / commands", id="prompt-help")
            with Vertical(id="inspector"):
                with TabbedContent():
                    with TabPane("Plan", id="plan-tab"):
                        yield Static("The agent's plan appears here.", id="plan")
                    with TabPane("Changes", id="changes-tab"):
                        with VerticalScroll():
                            yield Static("No tracked changes.", id="diff")
        yield Footer()

    def on_mount(self):
        self.query_one("#prompt", Prompt).focus()
        self.query_one("#prompt", Prompt).border_title = "Message HYDRA"
        self.refresh_sessions()
        self.check_terminal_size()
        self.set_interval(0.1, self.check_terminal_size)

    def check_terminal_size(self):
        if self.size.width != self._terminal_width:
            self._terminal_width = self.size.width
            self.update_panels()

    def update_panels(self):
        self.query_one("#sessions-panel").display = self.size.width >= 110
        self.query_one("#inspector").display = self.size.width >= 145

    def refresh_sessions(self):
        try:
            items = [SessionItem(state) for state in self.controller.sessions()]
            view = self.query_one("#sessions", ListView)
            view.clear()
            if items:
                view.extend(items)
        except (ValueError, OSError) as error:
            self.add_message("Session storage", str(error), "error")

    def add_message(self, title, body, kind="activity"):
        self.call_later(self.mount_message, title, body, kind)

    async def mount_message(self, title, body, kind):
        conversation = self.query_one("#conversation", VerticalScroll)
        text = Text()
        text.append(safe_text(title, 200) + "\n", style="bold cyan" if kind != "error" else "bold red")
        text.append(safe_text(body))
        await conversation.mount(Static(text, classes=f"message {kind}"))
        # Bound live rendering; complete records remain in the durable session.
        if len(conversation.children) > 100:
            conversation.children[0].remove()
        self.call_after_refresh(conversation.scroll_end, animate=False)

    def receive_event(self, event):
        kind = event["kind"]
        if kind == "action":
            self.query_one("#run-status", Static).update(
                Text(f"Step {event['step']}/{self.options.max_steps} · {event['tool']}")
            )
            self.add_message(event["tool"], event.get("note", ""))
        elif kind == "result":
            result, tool = event["result"], event["tool"]
            if tool == "set_plan":
                self.show_plan()
            if tool in ("write_file", "edit_file"):
                self.show_diff()
            if tool == "finish":
                return
            if "output" in result:
                body = result["output"] or "No output."
                title = f"{tool} · exit {result.get('exit_code')}"
            elif "error" in result:
                body, title = str(result["error"]), f"{tool} · refused or failed"
            elif tool == "read_file":
                title = f"Read {result.get('path', 'file')} · lines {result.get('start_line', 1)}–{result.get('end_line', '')}"
                body = result.get("content", "")
            elif tool == "list_files":
                files = result.get("files", [])
                title, body = f"Files · {len(files)}", "\n".join(files[:40])
            elif tool == "set_plan":
                title, body = "Plan", "\n".join(f"{i}. {step}" for i, step in enumerate(result.get("plan", []), 1))
            elif "diff" in result:
                title, body = "Tracked changes", result["diff"] or "No changes needed."
            else:
                body, title = json.dumps(result, ensure_ascii=False, indent=2)[:5000], f"{tool} · result"
            self.add_message(title, body, "error" if result.get("success") is False or "error" in result else "result")
        elif kind == "finished":
            state = self.controller.session.state if self.controller.session else {}
            usage = state.get("model_usage", {})
            tokens = f" · {usage.get('input_tokens', 0)} in / {usage.get('output_tokens', 0)} out" if usage else ""
            self.query_one("#run-status", Static).update(Text(event["status"] + tokens))
            self.add_message(event["status"], event.get("summary", ""))
        elif kind == "error":
            self.query_one("#run-status", Static).update("Blocked · check provider/model configuration")
            self.add_message("Unable to continue", event["message"], "error")
        elif kind == "session":
            self.query_one("#run-status", Static).update(f"Session {event['id'][:8]} · connecting to model")

    async def approve_command(self, argv):
        if self.options.allow_run:
            return True
        self.query_one("#run-status", Static).update("Waiting for command approval")
        screen = CommandApproval(argv)
        try:
            return bool(await self.push_screen_wait(screen))
        except asyncio.CancelledError:
            # A time budget can expire while an operator is considering a command.
            # Remove the dialog without resolving its already-cancelled future.
            if self.screen is screen:
                self.pop_screen()
            raise

    @on(Prompt.Submitted)
    async def submit(self, event):
        text = event.text.strip()
        if text.startswith("/"):
            await self.slash_command(text)
            self.query_one("#prompt", Prompt).clear()
            return
        if self.busy:
            self.notify("A run is active. Cancel it or wait; your draft is retained.")
            return
        self.query_one("#prompt", Prompt).clear()
        self.add_message("You", text, "user")
        self.start_goal(text)

    def start_goal(self, goal=None, *, resume=False):
        if self.busy:
            return
        self.options.provider = str(self.query_one("#provider", Select).value)
        self.options.model = self.query_one("#model", Input).value.strip() or None
        self.busy = True
        self.query_one("#provider", Select).disabled = True
        self.query_one("#model", Input).disabled = True
        self.agent_worker = self.run_worker(self.run_goal(goal, resume=resume), group="agent", exit_on_error=False)

    async def run_goal(self, goal, *, resume=False):
        try:
            await self.controller.run(goal, resume=resume)
        except (ValueError, OSError, RuntimeError) as error:
            # The controller records and emits the concrete error.
            self.notify(safe_text(error, 400), severity="error")
        finally:
            self.busy = False
            self.query_one("#provider", Select).disabled = False
            self.query_one("#model", Input).disabled = False
            self.refresh_sessions()
            self.show_plan()
            self.show_diff()

    @on(Select.Changed, "#provider")
    def provider_changed(self, event):
        if self.busy or event.value == Select.BLANK or str(event.value) == self.options.provider:
            return
        self.select_provider(str(event.value))

    def select_provider(self, name, model=None):
        self.options.provider = name
        try:
            default_model = settings(name).model
        except ValueError:
            default_model = ""
        self.query_one("#provider", Select).value = name
        selected_model = model if model is not None else default_model
        self.options.model = selected_model or None
        self.query_one("#model", Input).value = selected_model

    def apply_model_selection(self, selection):
        if selection is None:
            return
        if self.busy:
            self.notify("Cancel or finish the current run before changing the model.")
            return
        provider, model = selection
        self.select_provider(provider, model)
        self.add_message("Model selected", f"{provider} · {model}\nApplies to the next request.")
        self.query_one("#prompt", Prompt).focus()

    @on(ListView.Selected, "#sessions")
    def select_session(self, event):
        if not self.busy:
            try:
                state = self.controller.load(event.item.session_id)
                if state.get("provider") in {p["id"] for p in self._catalog}:
                    self.select_provider(state["provider"], state.get("model"))
                self.add_message("Session selected", f"{state['id']}\n{state['goal']}\nStatus: {state['status']}")
                self.show_plan()
                self.show_diff()
            except (ValueError, OSError) as error:
                self.add_message("Cannot load session", str(error), "error")

    @on(Button.Pressed)
    def button_pressed(self, event):
        if event.button.id == "new-session":
            self.action_new()
        elif event.button.id == "resume-session" and not self.busy:
            self.start_goal(resume=True)

    def show_plan(self):
        session = self.controller.session
        steps = session.state["plan"] if session else []
        self.query_one("#plan", Static).update(
            Text("\n\n".join(f"{i}. {safe_text(step)}" for i, step in enumerate(steps, 1)) or "No plan yet.")
        )

    def show_diff(self):
        session = self.controller.session
        diff = session.diff() if session else ""
        self.query_one("#diff", Static).update(
            Syntax(safe_text(diff, 32000), "diff", word_wrap=True) if diff else Text("No tracked changes.")
        )

    def action_diff(self):
        self.query_one("#inspector").display = True
        self.query_one(TabbedContent).active = "changes-tab"
        self.show_diff()

    def action_sidebar(self):
        panel = self.query_one("#sessions-panel")
        panel.display = not panel.display

    def action_new(self):
        if self.busy:
            self.notify("Cancel or finish the current run first.")
            return
        self.controller.new()
        self.add_message("New session", "Describe your next engineering task.")
        self.query_one("#run-status", Static).update("Ready")
        self.show_plan()
        self.show_diff()
        self.query_one("#prompt", Prompt).focus()

    async def action_cancel(self):
        if isinstance(self.screen, CommandApproval):
            self.screen.dismiss(False)
        if self.busy and self.agent_worker:
            self.agent_worker.cancel()
            try:
                await self.agent_worker.wait()
            except (WorkerCancelled, WorkerFailed, asyncio.CancelledError):
                pass

    async def action_quit(self):
        await self.action_cancel()
        self.exit()

    async def slash_command(self, text):
        command, _, argument = text.partition(" ")
        if command == "/help":
            self.add_message("Commands", HELP)
        elif command == "/new":
            self.action_new()
        elif command == "/cancel":
            await self.action_cancel()
        elif command == "/quit":
            await self.action_quit()
        elif command == "/diff":
            self.action_diff()
        elif command == "/plan":
            self.query_one("#inspector").display = True
            self.query_one(TabbedContent).active = "plan-tab"
            self.show_plan()
        elif command == "/sessions":
            self.refresh_sessions()
            self.query_one("#sessions-panel").display = True
        elif command == "/model":
            if self.busy:
                self.notify("Cancel or finish the current run before changing the model.")
                return
            provider = str(self.query_one("#provider", Select).value)
            if argument.strip():
                self.apply_model_selection((provider, argument.strip()))
            else:
                self.push_screen(
                    ModelSelection(self._catalog, provider, self.query_one("#model", Input).value),
                    self.apply_model_selection,
                )
        elif command == "/resume" and argument and not self.busy:
            try:
                self.controller.load(argument.strip())
                self.start_goal(resume=True)
            except (ValueError, OSError) as error:
                self.add_message("Cannot resume", str(error), "error")
        elif command == "/provider" and argument and not self.busy:
            name, _, model = argument.partition(" ")
            if name not in {p["id"] for p in self._catalog}:
                self.add_message("Unknown provider", "Choose an implemented provider from the selector.", "error")
                return
            self.select_provider(name, model.strip() if model else None)
        else:
            self.add_message("Command unavailable", HELP, "error")
