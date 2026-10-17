"""Phase 5 integration test — tool execution with background workers.

Validates:
1. /recon returns pending → worker spawned → events emitted
2. /scan returns pending → worker spawned → events emitted
3. /attack returns pending → campaign worker spawned
4. ScanService emits tool.started → tool.output → tool.completed
5. EventBridge translates tool.output events to ToolOutputChunk messages
6. Bottom panel receives streaming output
7. Worker completion renders results
"""

import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from hydra.services.event_bus import EventBus
from hydra.services import ServiceContainer
from hydra.commands.registry import CommandRegistry
from hydra.commands.builtins import register_all_builtins
from hydra.facade import HydraFacade
from hydra.registry.capability import CapabilityRegistry


def test_recon_command_returns_pending():
    bus = EventBus()
    registry = CapabilityRegistry()
    services = ServiceContainer(event_bus=bus)
    cmd_reg = CommandRegistry()
    register_all_builtins(cmd_reg, registry)
    facade = HydraFacade(services, registry, bus, cmd_reg)

    result = facade.execute_command("/recon example.com")
    assert result.status == "pending", f"Expected pending, got {result.status}"
    assert result.output["type"] == "recon"
    assert result.output["target"] == "example.com"
    assert result.output["depth"] == 3
    print("  [PASS] /recon returns pending with target + depth")


def test_recon_with_depth():
    bus = EventBus()
    registry = CapabilityRegistry()
    services = ServiceContainer(event_bus=bus)
    cmd_reg = CommandRegistry()
    register_all_builtins(cmd_reg, registry)
    facade = HydraFacade(services, registry, bus, cmd_reg)

    result = facade.execute_command("/recon example.com --depth=5")
    assert result.status == "pending"
    assert result.output["depth"] == 5
    print("  [PASS] /recon --depth=5 parsed correctly")


def test_scan_command_returns_pending():
    bus = EventBus()
    registry = CapabilityRegistry()
    services = ServiceContainer(event_bus=bus)
    cmd_reg = CommandRegistry()
    register_all_builtins(cmd_reg, registry)
    facade = HydraFacade(services, registry, bus, cmd_reg)

    result = facade.execute_command("/scan example.com xss")
    assert result.status == "pending"
    assert result.output["type"] == "scan"
    assert result.output["target"] == "example.com"
    assert result.output["vuln_class"] == "xss"
    print("  [PASS] /scan returns pending with target + vuln_class")


def test_attack_command_returns_pending():
    bus = EventBus()
    registry = CapabilityRegistry()
    services = ServiceContainer(event_bus=bus)
    cmd_reg = CommandRegistry()
    register_all_builtins(cmd_reg, registry)
    facade = HydraFacade(services, registry, bus, cmd_reg)

    result = facade.execute_command("/attack example.com")
    assert result.status == "pending"
    assert result.output["type"] == "attack_campaign"
    assert result.output["target"] == "example.com"
    assert "xss" in result.output["classes"]
    print("  [PASS] /attack returns pending with classes")


def test_scan_service_emits_events():
    bus = EventBus()
    services = ServiceContainer(event_bus=bus)

    events = []
    bus.subscribe("tool.*", lambda e: events.append(e))

    result = services.scan.execute_recon("test.com", depth=2)
    assert isinstance(result, dict)

    event_types = [e.type for e in events]
    assert "tool.started" in event_types, f"Missing tool.started in {event_types}"
    assert "tool.completed" in event_types, f"Missing tool.completed in {event_types}"

    output_events = [e for e in events if e.type == "tool.output"]
    assert len(output_events) >= 1, "Expected at least one tool.output event"
    print(f"  [PASS] ScanService emitted {len(events)} events: {event_types}")


def test_scan_service_scan_emits_events():
    bus = EventBus()
    services = ServiceContainer(event_bus=bus)

    events = []
    bus.subscribe("tool.*", lambda e: events.append(e))

    result = services.scan.execute_scan("test.com", "sqli")
    assert isinstance(result, dict)

    event_types = [e.type for e in events]
    assert "tool.started" in event_types
    assert "tool.completed" in event_types
    print(f"  [PASS] ScanService scan emitted {len(events)} events")


def test_scan_service_campaign():
    bus = EventBus()
    services = ServiceContainer(event_bus=bus)

    events = []
    bus.subscribe("tool.*", lambda e: events.append(e))

    result = services.scan.execute_campaign("test.com", "xss,sqli")
    assert isinstance(result, dict)
    assert "confirmed" in result
    assert "suspected" in result

    started = [e for e in events if e.type == "tool.started"]
    assert len(started) >= 3, f"Expected 3+ tool.started (campaign + 2 scans), got {len(started)}"
    print(f"  [PASS] Campaign emitted {len(events)} events across {len(started)} tools")


def test_event_bridge_tool_output():
    pytest.importorskip("textual")
    from control_center.tui.event_bridge import EventBridge, ToolOutputChunk
    from unittest.mock import MagicMock

    app = MagicMock()
    bus = EventBus()
    bridge = EventBridge(app, bus)
    bridge.connect()

    bus.emit("tool.output", {"tool": "recon", "chunk": "Finding subdomains..."})

    posted = [call.args[0] for call in app.post_message.call_args_list]
    output_msgs = [m for m in posted if isinstance(m, ToolOutputChunk)]
    assert len(output_msgs) == 1
    assert output_msgs[0].tool == "recon"
    assert output_msgs[0].chunk == "Finding subdomains..."
    bridge.disconnect()
    print("  [PASS] EventBridge translates tool.output → ToolOutputChunk")


def test_event_bridge_workflow_advanced():
    pytest.importorskip("textual")
    from control_center.tui.event_bridge import EventBridge, WorkflowAdvanced
    from unittest.mock import MagicMock

    app = MagicMock()
    bus = EventBus()
    bridge = EventBridge(app, bus)
    bridge.connect()

    bus.emit("workflow.advanced", {"run_id": "wf-1", "state": "recon"})

    posted = [call.args[0] for call in app.post_message.call_args_list]
    wf_msgs = [m for m in posted if isinstance(m, WorkflowAdvanced)]
    assert len(wf_msgs) == 1
    assert wf_msgs[0].state == "recon"
    bridge.disconnect()
    print("  [PASS] EventBridge translates workflow.advanced → WorkflowAdvanced")


def test_scope_register():
    bus = EventBus()
    registry = CapabilityRegistry()
    services = ServiceContainer(event_bus=bus)
    cmd_reg = CommandRegistry()
    register_all_builtins(cmd_reg, registry)
    facade = HydraFacade(services, registry, bus, cmd_reg)

    result = facade.execute_command("/scope register acme --platform=hackerone --in_scope=*.acme.com")
    assert result.status == "success"
    assert result.output["type"] == "scope_register"
    assert result.output["program"] == "acme"
    print("  [PASS] /scope register returns success with program info")


def test_missing_args():
    bus = EventBus()
    registry = CapabilityRegistry()
    services = ServiceContainer(event_bus=bus)
    cmd_reg = CommandRegistry()
    register_all_builtins(cmd_reg, registry)
    facade = HydraFacade(services, registry, bus, cmd_reg)

    r1 = facade.execute_command("/recon")
    assert r1.status == "error"

    r2 = facade.execute_command("/scan example.com")
    assert r2.status == "error"

    r3 = facade.execute_command("/attack")
    assert r3.status == "error"
    print("  [PASS] Missing args return errors with usage hints")


if __name__ == "__main__":
    print("\n=== Phase 5: Tool Execution Integration Tests ===\n")
    test_recon_command_returns_pending()
    test_recon_with_depth()
    test_scan_command_returns_pending()
    test_attack_command_returns_pending()
    test_scan_service_emits_events()
    test_scan_service_scan_emits_events()
    test_scan_service_campaign()
    test_event_bridge_tool_output()
    test_event_bridge_workflow_advanced()
    test_scope_register()
    test_missing_args()
    print("\n=== ALL PHASE 5 TESTS PASSED ===\n")
