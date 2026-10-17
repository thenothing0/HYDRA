"""Budgets and state validation must hold even when the model is wrong."""

import asyncio
from copy import deepcopy
import json
import subprocess
import sys

import pytest

from hydra.engineering.agent import EngineeringAgent
from hydra.engineering.governor import RunLimits
from hydra.engineering.session import Session
from hydra.engineering.workspace import Workspace, digest


class Model:
    def __init__(self, action, *, tokens=1, usage_available=True):
        self.action = action
        self.usage = {"input_tokens": 0, "output_tokens": 0, "requests": 0}
        self.usage_available = usage_available
        self.tokens = tokens

    async def respond(self, prompt):
        self.usage["input_tokens"] += self.tokens
        self.usage["requests"] += 1
        return json.dumps(self.action)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda state: state.update(status="imaginary"),
        lambda state: state.update(status=[]),
        lambda state: state.update(revision=True),
        lambda state: state.update(verified_revision=4),
        lambda state: state.update(events={}),
        lambda state: state.update(plan=[1]),
        lambda state: state.pop("verified_revision"),
        lambda state: state.update(created_at="2026-01-01T00:00:00"),
        lambda state: state.update(model_usage={"input_tokens": -2}),
    ],
)
def test_checksummed_but_invalid_state_is_rejected(tmp_path, mutation):
    session = Session(Workspace(tmp_path), goal="Inspect state")
    state = deepcopy(session.state)
    mutation(state)
    content = {key: value for key, value in state.items() if key != "checksum"}
    state["checksum"] = digest(json.dumps(content, sort_keys=True, ensure_ascii=False).encode())
    session.path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid session state"):
        Session(session.workspace, session_id=session.state["id"])


def test_save_refuses_same_generation_disk_corruption(tmp_path):
    session = Session(Workspace(tmp_path), goal="Original")
    state = deepcopy(session.state)
    state["goal"] = "Unexpected disk mutation"
    session.path.write_text(json.dumps(state), encoding="utf-8")
    before = session.path.read_bytes()
    with pytest.raises(ValueError, match="checksum"):
        session.event("observe")
    assert session.path.read_bytes() == before
    assert not session.path.with_suffix(".lock").exists()


def test_tool_budget_prevents_next_model_request(tmp_path):
    model = Model({"tool": "list_files", "arguments": {}})
    session = Session(Workspace(tmp_path), goal="Inspect")
    result = asyncio.run(EngineeringAgent(session, model, max_tool_calls=1).run())
    assert result["status"] == "budget_exhausted"
    assert result["run"]["stop_reason"] == "max_tool_calls"
    assert result["run"]["tool_calls"] == model.usage["requests"] == 1
    assert result["events"][-1]["kind"] == "run_stopped"


def test_token_ceiling_refuses_action_after_in_flight_request(tmp_path):
    model = Model(
        {"tool": "write_file", "arguments": {"path": "unwanted.py", "content": "x", "expected_sha256": None}}, tokens=11
    )
    session = Session(Workspace(tmp_path), goal="Observe ceiling")
    result = asyncio.run(EngineeringAgent(session, model, max_tokens=10).run())
    assert result["run"]["stop_reason"] == "max_tokens"
    assert result["run"]["observed_tokens"] == 11
    assert result["run"]["tool_calls"] == 0
    assert not (tmp_path / "unwanted.py").exists()


def test_missing_or_unreported_token_usage_blocks_actions(tmp_path):
    model = Model({"tool": "finish", "arguments": {"summary": "Done"}}, usage_available=False)
    result = asyncio.run(EngineeringAgent(Session(Workspace(tmp_path)), model, max_tokens=100).run())
    assert result["status"] == "blocked"
    assert result["run"]["stop_reason"] == "token_usage_unavailable"
    assert result["run"]["tool_calls"] == 0


def test_token_budget_requires_observable_usage_before_first_request(tmp_path):
    class UnmeteredModel:
        async def respond(self, prompt):
            raise AssertionError("Unmetered provider must not be called with a token budget")

    result = asyncio.run(EngineeringAgent(Session(Workspace(tmp_path)), UnmeteredModel(), max_tokens=10).run())
    assert result["status"] == "blocked"
    assert result["run"]["stop_reason"] == "token_usage_unavailable"
    assert result["run"]["model_requests"] == 0


@pytest.mark.parametrize(
    "protocol,data",
    [
        (
            "openai_chat",
            {"choices": [{"message": {"content": "text"}}], "usage": {"prompt_tokens": "10", "completion_tokens": 1}},
        ),
        ("ollama", {"response": "text"}),
        ("gemini", {"candidates": [{"content": {"parts": [{"text": "text"}]}}]}),
    ],
)
def test_provider_does_not_invent_or_store_invalid_usage(protocol, data):
    from hydra.engineering.providers import ProviderModel, ProviderSettings

    model = ProviderModel()
    assert model.usage_available is False
    model.config = ProviderSettings("fixture", protocol, "http://127.0.0.1", "fixture")
    assert model.parse(data) == "text"
    assert model.usage_available is False
    assert model.usage["input_tokens"] == model.usage["output_tokens"] == 0


def test_resume_uses_a_new_recorded_budget_and_cumulative_model_baseline(tmp_path):
    model = Model({"tool": "list_files", "arguments": {}}, tokens=2)
    session = Session(Workspace(tmp_path))
    first = asyncio.run(EngineeringAgent(session, model, max_tool_calls=1, max_tokens=10).run())
    first_id = first["run"]["run_id"]
    resumed = Session(session.workspace, session_id=first["id"])
    second = asyncio.run(EngineeringAgent(resumed, model, max_tool_calls=1, max_tokens=10).run())
    assert second["run"]["run_id"] != first_id
    assert second["run"]["observed_tokens"] == 2
    assert model.usage["input_tokens"] == 4
    assert len([e for e in second["events"] if e["kind"] == "run_stopped"]) == 2


def test_context_budget_stops_before_any_provider_call(tmp_path):
    model = Model({"tool": "finish", "arguments": {"summary": "Done"}})
    result = asyncio.run(EngineeringAgent(Session(Workspace(tmp_path)), model, max_context_chars=1).run())
    assert result["run"]["stop_reason"] == "max_context_chars"
    assert model.usage["requests"] == 0


def test_failed_response_still_records_observed_usage(tmp_path):
    class FailedResponse(Model):
        async def respond(self, prompt):
            self.usage.update(input_tokens=12, output_tokens=3, requests=1)
            raise RuntimeError("Provider returned no usable text")

    model = FailedResponse({})
    result = asyncio.run(EngineeringAgent(Session(Workspace(tmp_path)), model).run())
    assert result["status"] == "failed"
    assert result["run"]["observed_tokens"] == 15
    assert result["model_usage"]["requests"] == 1
    assert result["run"]["token_usage_available"] is True


def test_identical_failed_actions_stop_before_another_attempt(tmp_path):
    model = Model({"tool": "read_file", "arguments": {"path": "missing.py"}})
    result = asyncio.run(EngineeringAgent(Session(Workspace(tmp_path)), model).run())
    assert result["status"] == "blocked"
    assert result["run"]["stop_reason"] == "repeated_failure"
    assert result["run"]["tool_calls"] == 3


def test_failure_limit_is_enforced_on_first_failure(tmp_path):
    model = Model({"tool": "read_file", "arguments": {"path": "missing.py"}})
    result = asyncio.run(EngineeringAgent(Session(Workspace(tmp_path)), model, max_failures=1).run())
    assert result["run"]["stop_reason"] == "max_failures"
    assert result["run"]["tool_calls"] == 1


@pytest.mark.parametrize("limits", [{"max_tool_calls": 0}, {"max_tokens": -1}, {"max_steps": True}, {"max_seconds": 0}])
def test_invalid_limits_are_rejected(limits):
    with pytest.raises(ValueError):
        RunLimits(**limits)


def test_handoff_is_read_only_verifiable_and_excludes_raw_tool_data(tmp_path):
    workspace = Workspace(tmp_path)
    session = Session(workspace, goal="Inspect")
    session.event(
        "result", tool="run_command", result={"success": True, "exit_code": 0, "output": "sensitive-fixture-output"}
    )
    before = session.path.read_bytes()
    report = session.handoff()
    checksum = report.pop("checksum")
    assert checksum == digest(json.dumps(report, sort_keys=True, ensure_ascii=False).encode())
    assert report["source_checksum"] == session.state["checksum"]
    assert report["evidence"][0]["success"] is True
    assert "sensitive-fixture-output" not in json.dumps(report)
    assert session.path.read_bytes() == before
    command = [sys.executable, "-m", "hydra", "handoff", session.state["id"], "--workspace", str(tmp_path)]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["source_checksum"] == report["source_checksum"]


def test_stale_handoff_does_not_misrepresent_newer_disk_state(tmp_path):
    session = Session(Workspace(tmp_path), goal="Inspect")
    other = Session(session.workspace, session_id=session.state["id"])
    other.event("updated")
    with pytest.raises(ValueError, match="Concurrent"):
        session.handoff()
