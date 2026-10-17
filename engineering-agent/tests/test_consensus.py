"""Tests for the Consensus Engine."""

import pytest
from hydra.consensus import ConsensusEngine


class TestConsensusEngine:
    """Test multi-agent consensus voting."""

    def test_engine_creation(self):
        engine = ConsensusEngine()
        assert engine is not None

    def test_submit_vote(self):
        engine = ConsensusEngine()
        engine.submit_vote(
            finding_id="f1",
            agent_id="recon-1",
            agent_type="recon",
            verdict="valid",
            confidence=0.9,
        )
        assert len(engine.get_votes("f1")) == 1

    def test_consensus_reached_with_quorum(self):
        engine = ConsensusEngine()
        # Submit 3 agreeing votes
        for i in range(3):
            engine.submit_vote(
                finding_id="f2",
                agent_id=f"agent-{i}",
                agent_type="vuln_research",
                verdict="valid",
                confidence=0.85,
            )
        result = engine.evaluate("f2")
        assert result is not None
        assert result.get("consensus") == "valid"

    def test_contradiction_detection(self):
        engine = ConsensusEngine()
        engine.submit_vote("f3", "a1", "recon", "valid", 0.9)
        engine.submit_vote("f3", "a2", "validation", "invalid", 0.8)
        result = engine.evaluate("f3")
        assert result.get("has_contradiction", False) is True

    def test_confidence_fusion(self):
        engine = ConsensusEngine()
        engine.submit_vote("f4", "a1", "recon", "valid", 0.7)
        engine.submit_vote("f4", "a2", "vuln_research", "valid", 0.9)
        engine.submit_vote("f4", "a3", "validation", "valid", 0.85)
        result = engine.evaluate("f4")
        fused = result.get("fused_confidence", 0)
        assert 0.7 <= fused <= 1.0
