import asyncio

from config import DeliberationConfig, EngagementContext
from mistcoder_core import DeliberationSession


def _stage_output(summary: str, severity: float = 80.0):
    return {
        "summary": summary,
        "attack_chains": [
            {
                "chain_id": "chain-1",
                "description": "SQL injection to data exfiltration",
                "severity_score": severity,
                "steps": ["source", "sink"],
                "threat_vectors": [
                    {"name": "injection", "impact": 90, "stealth": 70, "novelty": 60}
                ],
                "cwe_mappings": ["CWE-89"],
                "owasp_mappings": ["A03:2021"],
            }
        ],
        "remediation": ["Use parameterized queries"],
        "token_usage": {"total": 120},
    }


def test_orchestration_and_context_passing():
    call_order = []

    def phantom(payload):
        call_order.append("PHANTOM")
        assert "phantom" not in payload
        return _stage_output("phantom")

    def oracle(payload):
        call_order.append("ORACLE")
        assert payload["phantom"]["summary"] == "phantom"
        return _stage_output("oracle", severity=75)

    def covenant(payload):
        call_order.append("COVENANT")
        assert payload["phantom"]["summary"] == "phantom"
        assert payload["oracle"]["summary"] == "oracle"
        return _stage_output("covenant", severity=70)

    session = DeliberationSession(
        context=EngagementContext("threat_model", "deep", "payments api"),
        phantom_engine=phantom,
        oracle_engine=oracle,
        covenant_engine=covenant,
    )
    result = session.run()
    assert call_order == ["PHANTOM", "ORACLE", "COVENANT"]
    assert result["completed_stages"] == ("PHANTOM", "ORACLE", "COVENANT")
    assert result["consensus"]["high_confidence_truths"] == (
        "SQL injection to data exfiltration",
    )


def test_token_limit_graceful_degradation_preserves_completed_stages():
    session = DeliberationSession(
        context=EngagementContext("code_audit", "rapid", "service"),
        phantom_engine=lambda _p: _stage_output("phantom"),
        oracle_engine=lambda _p: _stage_output("oracle"),
        covenant_engine=lambda _p: _stage_output("covenant"),
        config=DeliberationConfig(token_limit_total=350, token_warning_threshold=0.5),
    )
    result = session.run()
    assert result["completed_stages"] == ("PHANTOM",)
    assert any("Token limit exceeded" in err for err in result["errors"])


def test_api_failure_keeps_partial_results():
    def oracle_failure(_payload):
        raise RuntimeError("upstream timeout")

    session = DeliberationSession(
        context=EngagementContext("arch_review", "rapid", "edge gateway"),
        phantom_engine=lambda _p: _stage_output("phantom"),
        oracle_engine=oracle_failure,
        covenant_engine=lambda _p: _stage_output("covenant"),
    )
    result = session.run()
    assert result["completed_stages"] == ("PHANTOM",)
    assert any("ORACLE failure" in err for err in result["errors"])
    assert any("COVENANT failure" in err for err in result["errors"])


def test_async_execution_supported():
    async def phantom(_payload):
        return _stage_output("phantom")

    async def oracle(payload):
        assert payload["phantom"]["summary"] == "phantom"
        return _stage_output("oracle")

    async def covenant(payload):
        assert payload["oracle"]["summary"] == "oracle"
        return _stage_output("covenant")

    session = DeliberationSession(
        context=EngagementContext("api_sec", "apex", "partner api"),
        phantom_engine=phantom,
        oracle_engine=oracle,
        covenant_engine=covenant,
    )
    result = asyncio.run(session.run_async())
    assert result["completed_stages"] == ("PHANTOM", "ORACLE", "COVENANT")
    assert result["errors"] == []


def test_consensus_is_deterministic_for_same_engine_outputs():
    def build():
        return DeliberationSession(
            context=EngagementContext("threat_model", "deep", "same target"),
            phantom_engine=lambda _p: _stage_output("phantom", severity=90),
            oracle_engine=lambda _p: _stage_output("oracle", severity=80),
            covenant_engine=lambda _p: _stage_output("covenant", severity=70),
        )

    first = build().run()["consensus"]["consensus_hash"]
    second = build().run()["consensus"]["consensus_hash"]
    assert first == second
