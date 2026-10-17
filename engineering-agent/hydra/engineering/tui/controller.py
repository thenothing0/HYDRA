"""Presentation-independent orchestration for interactive engineering sessions."""

import asyncio
import json
from dataclasses import dataclass

from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.providers import ProviderModel
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace


@dataclass
class RunOptions:
    provider: str | None = None
    model: str | None = None
    max_steps: int = 30
    max_seconds: int = 600
    read_only: bool = False
    browser: bool = False
    allow_browser_actions: bool = False
    allow_run: bool = False
    verify_command: list[str] | None = None
    burp_url: str | None = None

    @classmethod
    def from_args(cls, args):
        values = {name: getattr(args, name, None) for name in cls.__dataclass_fields__}
        if args.verify_command:
            values["verify_command"] = json.loads(args.verify_command)
        return cls(**values)


class EngineeringController:
    def __init__(self, workspace, options, approve, emit=None, model_factory=None, approve_burp=None):
        self.workspace = Workspace(workspace)
        self.options = options
        self.approve = approve
        self.approve_burp = approve_burp or approve
        self.emit = emit or (lambda event: None)
        self.model_factory = model_factory or ProviderModel
        self.session = None
        self.running = False

    def new(self):
        if self.running:
            raise ValueError("Cancel the active run before starting a new session")
        self.session = None

    def load(self, ident):
        if self.running:
            raise ValueError("Cancel the active run before switching sessions")
        self.session = Session(self.workspace, session_id=ident)
        return self.session.state

    def sessions(self):
        directory = self.workspace.root / ".hydra/sessions"
        for candidate in (directory.parent, directory):
            if (
                candidate.is_symlink()
                or (hasattr(candidate, "is_junction") and candidate.is_junction())
                or not candidate.resolve().is_relative_to(self.workspace.root)
            ):
                raise ValueError("Session storage must stay inside the workspace")
        result = []
        for path in sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:30]:
            try:
                state = Session(self.workspace, session_id=path.stem).state
                result.append({key: state.get(key) for key in ("id", "goal", "status", "updated_at")})
            except (ValueError, OSError, KeyError):
                continue
        return result

    async def run(self, goal=None, *, resume=False):
        if self.running:
            raise ValueError("A run is already active")
        options = self.options
        if options.allow_browser_actions and not options.browser:
            raise ValueError("Browser actions require the browser capability")
        if options.verify_command is not None and (
            not isinstance(options.verify_command, list)
            or not options.verify_command
            or any(not isinstance(a, str) for a in options.verify_command)
        ):
            raise ValueError("Verification must be a nonempty JSON array of strings")
        if resume:
            if self.session is None or self.session.state["status"] in ("completed", "rolled_back"):
                raise ValueError("Select an interrupted or unfinished session to resume")
        elif not isinstance(goal, str) or not goal.strip():
            raise ValueError("Enter a concrete engineering goal")
        self.running = True
        try:
            if not resume:
                if self.session is None or self.session.state["status"] == "rolled_back":
                    self.session = Session(self.workspace, goal=goal.strip())
                else:
                    self.session.event("user_followup", previous_goal=self.session.state["goal"], goal=goal.strip())
                    self.session.state.update(goal=goal.strip(), status="created", summary="")
                    self.session.save()
            session = self.session
            verification = options.verify_command or session.state.get("verification_command")
            tools = EngineeringTools(
                session,
                approve=self.approve,
                read_only=options.read_only,
                verify_command=verification,
                browser=options.browser,
                allow_browser_actions=options.allow_browser_actions,
                burp_url=options.burp_url,
                approve_burp=self.approve_burp,
            )
            session.state["verification_command"] = tools.verify_command
            session.save()
            self.emit({"kind": "session", "id": session.state["id"]})
            model = self.model_factory(options.provider, options.model)
            await model.initialize()
            agent = EngineeringAgent(
                session,
                model,
                tools,
                options.max_steps,
                options.max_seconds,
                on_event=lambda event: self.emit({"kind": "action", **event}),
                on_result=lambda event: self.emit({"kind": "result", **event}),
            )
            result = await agent.run()
            self.emit({"kind": "finished", "status": result["status"], "summary": result.get("summary", "")})
            return result
        except asyncio.CancelledError:
            if self.session:
                self.session.state["status"] = "interrupted"
                self.session.save()
            self.emit({"kind": "finished", "status": "interrupted", "summary": "Run cancelled; session saved."})
            raise
        except Exception as error:
            if self.session:
                self.session.state["status"] = "blocked"
                self.session.event("configuration_or_ui_error", error=str(error))
            self.emit({"kind": "error", "message": str(error)})
            raise
        finally:
            self.running = False
