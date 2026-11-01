"""Real local validators and a captured Hacker API ledger; never submit a live report."""

import asyncio
import copy
import json
import sys
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from hydra.engineering.cli import parser
from hydra.engineering.hackerone_api import HackerOneAPIError, HackerOneClient
from hydra.engineering.hackerone_reporting import HackerOneReporting, REQUIRED_CHECKS, fingerprint, scope_allows_url
from hydra.engineering.process import ProcessRunner
from hydra.engineering.session import Session
from hydra.engineering.tools import EngineeringTools
from hydra.engineering.workspace import Workspace, digest


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "fixture-researcher")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "fixture-only-private-token")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    verifier = tmp_path / "verifier.py"
    verifier.write_text(
        "import json,sys\nf=json.load(open(sys.argv[1],encoding='utf-8'))\n"
        "assert f['observed_result']=='fixture observation'\n"
        "assert f['evidence'][0]['text']=='fixture evidence\\n'\n"
        "print('fixture check passed')\n", encoding="utf-8"
    )
    evidence = workspace / "evidence.txt"
    evidence.write_bytes(b"fixture evidence\n")
    finding = {"title": "Fixture authorization boundary", "vulnerability_information": "An isolated test case",
               "impact": "Fixture data from a second test account", "affected_url": "https://app.example.test/private",
               "root_cause": "missing object ownership check", "asset_identifier": "app.example.test",
               "expected_result": "deny", "observed_result": "fixture observation", "impact_bounds": "Only test accounts; all approved checks exhausted",
               "limitations": "Fixture only; no real vulnerability claim", "severity_rating": "medium", "weakness_id": 123,
               "reproduction_steps": ["Create two owned fixture accounts", "Compare their record access"],
               "evidence": [{"path": "evidence.txt", "sha256": digest(evidence.read_bytes())}]}
    plan = {"program": "fixture", "structured_scope_id": 7, "max_reports": 1,
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "checks": [{"id": name, "argv": [sys.executable, str(verifier), "{finding}"],
                        "pinned_files": [str(verifier)], "timeout": 10} for name in sorted(REQUIRED_CHECKS)]}
    snapshot = {"program": "fixture", "policy": "Only owned fixture accounts; no disruption",
                "submission_state": "open", "scope": {"id": "7", "type": "structured-scope", "attributes": {
                    "asset_identifier": "app.example.test", "asset_type": "URL", "eligible_for_submission": True,
                    "eligible_for_bounty": False}}, "exclusions": [],
                "weaknesses": [{"id": "123", "type": "weakness", "attributes": {"name": "Fixture weakness"}}]}
    plan["reviewed_snapshot_digest"] = fingerprint(snapshot)
    requests = []
    controls = {"post_status": 201, "post_error": False, "snapshot": snapshot}

    def handler(request):
        requests.append(request)
        assert request.url.host == "api.hackerone.com"
        assert request.headers["authorization"].startswith("Basic ")
        state = controls["snapshot"]
        if request.method == "POST":
            if controls["post_error"]:
                raise httpx.ReadTimeout("fixture secret must not reach logs", request=request)
            return httpx.Response(controls["post_status"], json={"data": {"type": "report", "id": "501"}})
        if request.url.path.endswith("/structured_scopes"):
            return httpx.Response(200, json={"data": [state["scope"]]})
        if request.url.path.endswith("/scope_exclusions"):
            return httpx.Response(200, json={"data": state["exclusions"], "links": {"next": None}})
        if request.url.path.endswith("/weaknesses"):
            return httpx.Response(200, json={"data": state["weaknesses"]})
        return httpx.Response(200, json={"data": {"id": "1", "type": "program", "attributes": {
            "handle": state["program"], "policy": state["policy"], "submission_state": state["submission_state"]}}})

    client = HackerOneClient(transport=httpx.MockTransport(handler))
    store = HackerOneReporting(workspace, client)
    runner = ProcessRunner(Workspace(workspace), lambda argv: True)
    return store, runner, plan, finding, requests, controls, verifier


async def authorized(scenario):
    store, runner, plan, finding, requests, controls, verifier = scenario
    await store.authorize(plan, policy_reviewed=True)
    requests.clear()
    return store, runner, finding, requests, controls, verifier


def writes(requests):
    return [r for r in requests if r.method == "POST"]


@pytest.mark.asyncio
async def test_verified_report_is_created_once_with_official_hacker_payload(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    result = await store.submit(finding, run_check=runner.run)
    assert result["success"] and result["report_id"] == "501"
    assert {c["id"] for c in result["checks"]} == REQUIRED_CHECKS
    assert all(c["exit_code"] == 0 and c["success"] for c in result["checks"])
    assert len(writes(requests)) == 1
    request = writes(requests)[0]
    assert request.url.path == "/v1/hackers/reports"
    body = json.loads(request.content)
    assert body["data"]["type"] == "report"
    assert body["data"]["attributes"]["team_handle"] == "fixture"
    assert body["data"]["attributes"]["structured_scope_id"] == 7
    assert "fixture evidence" in body["data"]["attributes"]["vulnerability_information"]
    assert "fixture-only-private-token" not in request.content.decode()
    assert (await store.submit(finding, run_check=runner.run))["duplicate_prevented"]
    assert len(writes(requests)) == 1


@pytest.mark.asyncio
async def test_failed_real_validator_blocks_post(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    finding["observed_result"] = "unverified model assertion"
    result = await store.submit(finding, run_check=runner.run)
    assert result["status"] == "blocked"
    assert result["checks"][0]["exit_code"] != 0
    assert not writes(requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["closed", "scope", "policy", "exclusion"])
async def test_live_program_changes_block_post(scenario, change):
    store, runner, finding, requests, controls, _ = await authorized(scenario)
    if change == "closed":
        controls["snapshot"]["submission_state"] = "closed"
    elif change == "scope":
        controls["snapshot"]["scope"]["attributes"]["eligible_for_submission"] = False
    elif change == "policy":
        controls["snapshot"]["policy"] += " Updated restriction"
    else:
        controls["snapshot"]["exclusions"] = [{"id": "8", "attributes": {"category": "fixture category"}}]
    with pytest.raises(ValueError):
        await store.submit(finding, run_check=runner.run)
    assert not writes(requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["evidence", "verifier", "asset", "origin", "expiry", "secret"])
async def test_changed_or_unauthorized_inputs_never_post(scenario, change):
    store, runner, finding, requests, _, verifier = await authorized(scenario)
    if change == "evidence":
        (store.workspace.root / "evidence.txt").write_text("changed")
    elif change == "verifier":
        verifier.write_text("print('replaced verifier')")
    elif change == "asset":
        finding["asset_identifier"] = "unrelated.example.test"
    elif change == "origin":
        finding["affected_url"] = "https://unrelated.example.test/private"
    elif change == "secret":
        finding["impact"] = "fixture-only-private-token"
    else:
        policy = store.read("policy.json")
        policy["expires_at"] = "2000-01-01T00:00:00Z"
        store.write("policy.json", policy)
    with pytest.raises(ValueError):
        await store.submit(finding, run_check=runner.run)
    assert not writes(requests)


@pytest.mark.asyncio
async def test_command_approval_denial_and_read_only_block_submission(scenario):
    store, _, finding, requests, _, _ = await authorized(scenario)
    runner = ProcessRunner(store.workspace, lambda argv: False)
    with pytest.raises(PermissionError):
        await store.submit(finding, run_check=runner.run)
    with pytest.raises(PermissionError):
        await store.submit(finding, run_check=runner.run, read_only=True)
    assert not writes(requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(422, "rejected"), (429, "rejected"), (500, "unknown"), (408, "unknown")])
async def test_http_failures_are_durable_and_never_automatically_retried(scenario, status, expected):
    store, runner, finding, requests, controls, _ = await authorized(scenario)
    controls["post_status"] = status
    result = await store.submit(finding, run_check=runner.run)
    assert result["status"] == expected and not result["success"]
    assert (await store.submit(finding, run_check=runner.run))["duplicate_prevented"]
    assert len(writes(requests)) == 1


@pytest.mark.asyncio
async def test_ambiguous_transport_failure_is_not_retried(scenario):
    store, runner, finding, requests, controls, _ = await authorized(scenario)
    controls["post_error"] = True
    with pytest.raises(ValueError, match="withheld") as error:
        await store.submit(finding, run_check=runner.run)
    assert "fixture secret" not in str(error.value)
    repeated = await store.submit(finding, run_check=runner.run)
    assert repeated["status"] == "unknown" and repeated["duplicate_prevented"]
    assert len(writes(requests)) == 1


@pytest.mark.asyncio
async def test_cancel_during_post_records_unknown(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    async def cancelled(_):
        raise asyncio.CancelledError()
    store.client.create_report = cancelled
    with pytest.raises(asyncio.CancelledError):
        await store.submit(finding, run_check=runner.run)
    assert not store.path("submission.lock").exists()
    assert (await store.submit(finding, run_check=runner.run))["status"] == "unknown"


@pytest.mark.asyncio
async def test_submission_budget_limits_different_findings(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    await store.submit(finding, run_check=runner.run)
    finding["root_cause"] = "different root cause"
    with pytest.raises(ValueError, match="budget exhausted"):
        await store.submit(finding, run_check=runner.run)
    assert len(writes(requests)) == 1


@pytest.mark.asyncio
async def test_plan_missing_check_or_workspace_owned_verifier_is_refused(scenario):
    store, _, plan, _, requests, _, verifier = scenario
    incomplete = copy.deepcopy(plan)
    incomplete["checks"].pop()
    with pytest.raises(ValueError, match="each required"):
        await store.authorize(incomplete, policy_reviewed=True)
    owned = store.workspace.root / "verifier.py"
    owned.write_bytes(verifier.read_bytes())
    plan["checks"][0]["pinned_files"] = [str(owned)]
    with pytest.raises(ValueError, match="outside"):
        await store.authorize(plan, policy_reviewed=True)
    assert not requests


def test_reporting_is_opt_in_and_cannot_be_enabled_by_model_arguments(tmp_path):
    tools = EngineeringTools(Session(Workspace(tmp_path), goal="inspect"))
    assert "hackerone_submit" not in tools.available_tools
    with pytest.raises(ValueError, match="Unknown tool"):
        asyncio.run(tools.execute("hackerone_submit", {"finding_path": "finding.json", "hackerone": True}))
    enabled = EngineeringTools(tools.session, hackerone=True)
    assert "hackerone_submit" in enabled.available_tools
    assert asyncio.run(enabled.execute("hackerone_status", {}))["configured"] is False
    assert parser().parse_args(["tui", "--hackerone"]).hackerone


@pytest.mark.parametrize("identifier,url,allowed", [
    ("*.example.test", "https://a.example.test/x", True),
    ("*.example.test", "https://example.test/x", False),
    ("example.test", "https://example.test.evil.test/x", False),
    ("https://example.test/app", "https://example.test/application", False),
    ("https://example.test/app", "https://example.test/app/x", True),
    ("https://example.test/app", "http://example.test/app/x", False),
    ("https://example.test/app", "https://example.test:444/app/x", False),
    ("https://example.test/app", "https://example.test/app/../admin", False),
    ("https://example.test/app", "https://example.test/app/%2e%2e/admin", False),
])
def test_scope_matching_honors_host_path_scheme_and_port(identifier, url, allowed):
    scope = {"asset_type": "URL", "asset_identifier": identifier}
    if allowed:
        scope_allows_url(scope, url)
    else:
        with pytest.raises(ValueError):
            scope_allows_url(scope, url)


@pytest.mark.asyncio
async def test_redirects_are_not_followed_and_failure_body_is_not_exposed(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "fixture")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "fixture-token")
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://foreign.example.test"}, text="private error")
    client = HackerOneClient(transport=httpx.MockTransport(handler))
    with pytest.raises(HackerOneAPIError) as error:
        await client.request("GET", "/programs/fixture")
    assert error.value.status == 302 and "private error" not in str(error.value)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_changed_evidence_during_checks_blocks_post(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    calls = 0
    async def change_after_checks(argv, timeout):
        nonlocal calls
        result = await runner.run(argv, timeout)
        calls += 1
        if calls == 5:
            (store.workspace.root / "evidence.txt").write_text("changed after last check")
        return result
    with pytest.raises(ValueError, match="Evidence changed"):
        await store.submit(finding, run_check=change_after_checks)
    assert not writes(requests)


@pytest.mark.asyncio
async def test_concurrent_submit_is_exclusive(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    started, release = asyncio.Event(), asyncio.Event()
    async def paused(argv, timeout):
        started.set()
        await release.wait()
        return await runner.run(argv, timeout)
    first = asyncio.create_task(store.submit(finding, run_check=paused))
    await started.wait()
    try:
        with pytest.raises(ValueError, match="active"):
            await store.submit(finding, run_check=runner.run)
    finally:
        release.set()
    assert (await first)["success"]
    assert len(writes(requests)) == 1


@pytest.mark.asyncio
async def test_missing_plan_and_unknown_weakness_do_not_post(scenario):
    store, runner, plan, finding, requests, _, _ = scenario
    with pytest.raises(FileNotFoundError):
        await store.submit(finding, run_check=runner.run)
    await store.authorize(plan, policy_reviewed=True)
    requests.clear()
    finding["weakness_id"] = 999
    with pytest.raises(ValueError, match="weakness_id"):
        await store.submit(finding, run_check=runner.run)
    assert not requests


@pytest.mark.asyncio
async def test_capability_read_only_guard_runs_before_credentials(scenario, monkeypatch):
    store, _, _, _, requests, _, _ = scenario
    from hydra.engineering.capabilities.hackerone import HackerOneCapability
    def unexpected_client():
        raise AssertionError("Read-only disclosure must not construct a client")
    monkeypatch.setattr("hydra.engineering.capabilities.hackerone.HackerOneClient", unexpected_client)
    session = Session(store.workspace, goal="Inspect only")
    tools = EngineeringTools(session, hackerone=True, read_only=True)
    with pytest.raises(PermissionError):
        await HackerOneCapability(tools).execute("hackerone_submit", {"finding_path": "finding.json"})
    assert not requests


def test_reporting_storage_refuses_symlink_escape(tmp_path):
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    try:
        (workspace / ".hydra").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable to this account")
    store = HackerOneReporting(workspace)
    with pytest.raises(ValueError, match="aliases"):
        store.status()
    assert not list(outside.iterdir())


@pytest.mark.asyncio
async def test_account_and_workspace_authority_are_bound_to_the_grant(scenario):
    store, runner, finding, requests, _, _ = await authorized(scenario)
    store.client.username = "different-account"
    with pytest.raises(ValueError, match="another account"):
        await store.submit(finding, run_check=runner.run)
    assert not requests


@pytest.mark.asyncio
async def test_enabled_tool_runs_approved_checks_and_invalidates_code_verification(scenario, monkeypatch):
    store, _, finding, requests, _, _ = await authorized(scenario)
    (store.workspace.root / "finding.json").write_text(json.dumps(finding), encoding="utf-8")
    monkeypatch.setattr("hydra.engineering.capabilities.hackerone.HackerOneClient", lambda: store.client)
    session = Session(store.workspace, goal="Submit the validated fixture finding")
    session.state["verified_revision"] = 0
    session.save()
    approvals = []
    def approve(argv):
        approvals.append(argv)
        return True
    tools = EngineeringTools(session, hackerone=True, approve=approve)
    result = await tools.execute("hackerone_submit", {"finding_path": "finding.json"})
    assert result["success"] and len(approvals) == 5 and len(writes(requests)) == 1
    assert session.state["verified_revision"] is None
    assert session.state["command_dirty"]
    assert session.state["events"][-1]["kind"] == "hackerone_disclosure"


@pytest.mark.asyncio
async def test_cli_status_needs_no_credentials_or_network(scenario, monkeypatch, capsys):
    from hydra.engineering.cli import main
    store = scenario[0]
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    assert await main(["hackerone", "status", "--workspace", str(store.workspace.root)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["configured"] is False


@pytest.mark.asyncio
async def test_foreign_pagination_link_cannot_redirect_credentials(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "fixture")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "fixture-token")
    requests = []
    def handler(request):
        requests.append(request)
        if request.url.params.get("page[number]") == "1":
            return httpx.Response(200, json={"data": [{"id": "1"}], "links": {"next": "https://foreign.example.test/steal"}})
        return httpx.Response(200, json={"data": [{"id": "2"}], "links": {"next": None}})
    client = HackerOneClient(transport=httpx.MockTransport(handler))
    assert len(await client.collection("/programs/fixture/weaknesses")) == 2
    assert len(requests) == 2 and all(r.url.host == "api.hackerone.com" for r in requests)


@pytest.mark.asyncio
async def test_reviewed_policy_digest_must_match_before_authorization(scenario):
    store, _, plan, _, requests, controls, _ = scenario
    controls["snapshot"]["policy"] += " changed after operator review"
    with pytest.raises(ValueError, match="reviewed digest"):
        await store.authorize(plan, policy_reviewed=True)
    assert not store.path("policy.json").exists()
    assert not writes(requests)
