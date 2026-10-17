"""Tests for the Planner Agent and HTN Planning."""

import pytest
from hydra.planner.htn import HTNPlanner


class TestHTNPlanner:
    """Test Hierarchical Task Network planning."""

    def test_planner_creation(self):
        planner = HTNPlanner()
        assert planner is not None

    def test_available_goals(self):
        planner = HTNPlanner()
        goals = planner.get_available_goals()
        assert "full_assessment" in goals
        assert "quick_recon" in goals
        assert "api_assessment" in goals
        assert "web3_audit" in goals

    def test_decompose_quick_recon(self):
        planner = HTNPlanner()
        tasks = planner.plan("quick_recon", "example.com")
        assert len(tasks) > 0
        task_names = [t.name for t in tasks]
        assert "subdomain_enum" in task_names
        assert "http_probe" in task_names

    def test_decompose_full_assessment(self):
        planner = HTNPlanner()
        tasks = planner.plan("full_assessment", "example.com")
        assert len(tasks) >= 5
        # Should include recon, vuln scan, hunt, validate, report phases
        agents = set(t.agent_type for t in tasks)
        assert "recon" in agents

    def test_scope_directive_disables_task(self):
        planner = HTNPlanner()
        tasks = planner.plan("hunt", "example.com",
                            scope_directives=["DISABLE:ssrf"])
        task_names = [t.name for t in tasks]
        assert "hunt_ssrf" not in task_names

    def test_all_tasks_are_primitive(self):
        planner = HTNPlanner()
        tasks = planner.plan("quick_recon", "example.com")
        for task in tasks:
            assert task.is_primitive(), f"Task {task.name} is not primitive"

    def test_task_info_lookup(self):
        planner = HTNPlanner()
        info = planner.get_task_info("nuclei_scan")
        assert info is not None
        assert info["agent"] == "vuln_research"
        assert info["tool"] == "nuclei"
