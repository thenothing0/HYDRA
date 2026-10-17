"""Validate the existing session format without reinterpreting or migrating it."""

import base64
from datetime import datetime
import math
import re

from hydra.engineering.workspace import digest

STATUSES = {"created", "running", "completed", "blocked", "failed", "interrupted", "budget_exhausted", "rolled_back"}


def require(condition, field):
    if not condition:
        raise ValueError(f"Invalid session state: {field}")


def timestamp(value):
    try:
        return isinstance(value, str) and datetime.fromisoformat(value).utcoffset() is not None
    except (ValueError, TypeError):
        return False


def validate_state(state, workspace, ident, *, persisted=True):
    require(isinstance(state, dict), "expected an object")
    require(
        {
            "schema",
            "id",
            "workspace",
            "goal",
            "status",
            "created_at",
            "updated_at",
            "generation",
            "revision",
            "verified_revision",
            "events",
            "changes",
            "summary",
            "plan",
        }.issubset(state),
        "required fields",
    )
    require(type(state.get("schema")) is int and state["schema"] == 1, "unsupported schema")
    require(state.get("id") == ident and bool(re.fullmatch(r"[a-f0-9]{32}", ident)), "id")
    require(state.get("workspace") == str(workspace.root), "workspace mismatch")
    require(isinstance(state.get("status"), str) and state["status"] in STATUSES, "status")
    for name in ("goal", "summary"):
        require(isinstance(state.get(name), str), name)
    for name in ("created_at", "updated_at"):
        require(timestamp(state.get(name)), name)
    revision = state.get("revision")
    require(type(revision) is int and revision >= 0, "revision")
    verified = state.get("verified_revision")
    require(verified is None or type(verified) is int and 0 <= verified <= revision, "verified_revision")
    require(type(state.get("generation")) is int and state["generation"] >= 1, "generation")
    require(isinstance(state.get("plan"), list) and all(isinstance(s, str) for s in state["plan"]), "plan")
    require(isinstance(state.get("events"), list), "events")
    for event in state["events"]:
        require(isinstance(event, dict), "event object")
        require(isinstance(event.get("kind"), str) and bool(event["kind"]), "event kind")
        require(timestamp(event.get("time")), "event time")
        if event["kind"] in ("action", "result"):
            require(isinstance(event.get("tool"), str), "event tool")
            payload = "arguments" if event["kind"] == "action" else "result"
            require(isinstance(event.get(payload), dict), "event " + payload)
    require(isinstance(state.get("changes"), list), "changes")
    for change in state["changes"]:
        require(isinstance(change, dict) and isinstance(change.get("path"), str), "change path")
        require({"path", "before", "before_sha256", "after_sha256", "status"}.issubset(change), "change fields")
        workspace.resolve(change["path"])
        require(
            isinstance(change.get("status"), str) and change["status"] in {"pending", "applied", "failed", "reverted"},
            "change status",
        )
        require(
            isinstance(change.get("after_sha256"), str) and bool(re.fullmatch(r"[a-f0-9]{64}", change["after_sha256"])),
            "change hash",
        )
        before = change.get("before")
        if before is None:
            require(change.get("before_sha256") is None, "original hash")
        else:
            require(isinstance(before, str), "original content")
            try:
                original = base64.b64decode(before, validate=True)
            except ValueError:
                raise ValueError("Invalid session state: original content encoding") from None
            require(digest(original) == change.get("before_sha256"), "original content hash")
    command = state.get("verification_command")
    require(
        command is None or isinstance(command, list) and bool(command) and all(isinstance(a, str) for a in command),
        "verification_command",
    )
    if "command_dirty" in state:
        require(type(state["command_dirty"]) is bool, "command_dirty")
    if "verified_files" in state:
        require(isinstance(state["verified_files"], dict), "verified_files")
        for path, hashed in state["verified_files"].items():
            workspace.resolve(path)
            require(isinstance(hashed, str) and bool(re.fullmatch(r"[a-f0-9]{64}", hashed)), "verified file hash")
    for field in ("model_usage", "run"):
        if field in state:
            require(isinstance(state[field], dict), field)
    for value in state.get("model_usage", {}).values():
        require(type(value) is int and value >= 0, "model usage counter")
    if "run" in state:
        from hydra.engineering.governor import RunLimits

        run = state["run"]
        require(isinstance(run.get("run_id"), str) and bool(re.fullmatch(r"[a-f0-9]{32}", run["run_id"])), "run id")
        require(timestamp(run.get("started_at")), "run started_at")
        require(isinstance(run.get("limits"), dict), "run limits")
        try:
            RunLimits(**run["limits"])
        except (ValueError, TypeError):
            raise ValueError("Invalid session state: run limits") from None
        for key in ("model_requests", "tool_calls", "observed_tokens", "failures"):
            require(type(run.get(key)) is int and run[key] >= 0, "run " + key)
        elapsed = run.get("elapsed_seconds")
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0, "run elapsed time")
        require(run.get("stop_reason") is None or isinstance(run["stop_reason"], str), "run stop reason")
        require(
            run.get("token_usage_available") is None or type(run["token_usage_available"]) is bool,
            "run token usage availability",
        )
    if persisted:
        checksum = state.get("checksum")
        require(isinstance(checksum, str) and bool(re.fullmatch(r"[a-f0-9]{64}", checksum)), "checksum")
