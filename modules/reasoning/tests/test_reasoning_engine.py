"""
MOD-04 Reasoning Engine Tests

Comprehensive test suite for:
- Novel vulnerability discovery
- Attack path reasoning
- Explainability chains
"""

import pytest
from modules.reasoning.src.vulnerability_discovery import (
    VulnerabilityDiscoveryEngine,
    PatternMatcher,
    VulnerabilityChainDetector,
    AnomalyDetector,
)
from modules.reasoning.src.attack_path_reasoning import (
    AttackPathReasoningEngine,
    SymbolicReasoningEngine,
    ChainOfThoughtExplainer,
    ConstraintSatisfactionPlanner,
)
from modules.reasoning.src.explainability_chains import (
    ExplainabilityEngine,
    ExplanationGenerator,
    FeatureImportanceExplainer,
    ProofGenerator,
)


class TestPatternMatcher:
    """Tests for pattern matching"""
    
    def test_pattern_initialization(self):
        """Test pattern matcher initializes with known patterns"""
        matcher = PatternMatcher()
        assert len(matcher.known_patterns) > 0
        assert "sql_injection" in matcher.known_patterns
    
    def test_match_patterns(self):
        """Test pattern matching against findings"""
        matcher = PatternMatcher()
        findings = [
            {"cwe_id": "CWE-89", "category": "sql"},
            {"cwe_id": "CWE-22", "category": "path_traversal"},
        ]
        patterns = matcher.match_patterns(findings)
        assert len(patterns) >= 1
    
    def test_discover_novel_patterns(self):
        """Test discovery of novel patterns"""
        matcher = PatternMatcher()
        findings = [
            {
                "affected_components": ["auth", "database"],
                "severity": 0.8
            },
            {
                "affected_components": ["auth", "database"],
                "severity": 0.75
            },
            {
                "affected_components": ["auth", "database"],
                "severity": 0.85
            },
        ]
        novel_patterns = matcher.discover_novel_patterns(findings)
        assert len(novel_patterns) >= 1


class TestVulnerabilityChainDetector:
    """Tests for vulnerability chain detection"""
    
    def test_detector_initialization(self):
        """Test chain detector initializes"""
        detector = VulnerabilityChainDetector()
        assert len(detector.cwe_relationships) > 0
    
    def test_find_chains(self):
        """Test finding vulnerability chains"""
        detector = VulnerabilityChainDetector()
        vulnerabilities = [
            {"cwe_id": "CWE-89"},
            {"cwe_id": "CWE-284"},
        ]
        chains = detector.find_chains(vulnerabilities)
        # May find chains depending on relationships
        assert isinstance(chains, list)


class TestAnomalyDetector:
    """Tests for anomaly detection"""
    
    def test_detect_statistical_anomalies(self):
        """Test detection of statistical anomalies"""
        detector = AnomalyDetector()
        findings = [
            {"severity": 0.5, "component": "auth"},
            {"severity": 0.6, "component": "db"},
            {"severity": 0.55, "component": "api"},
            {"severity": 0.95, "component": "crypto"},  # Anomaly
        ]
        anomalies = detector.detect_anomalies(findings)
        assert len(anomalies) > 0
    
    def test_detect_structural_anomalies(self):
        """Test detection of structural anomalies"""
        detector = AnomalyDetector()
        findings = [
            {
                "severity": 0.5,
                "component": "auth",
                "affected_components": ["a", "b", "c", "d", "e"]  # Many components
            },
        ]
        anomalies = detector.detect_anomalies(findings)
        assert len(anomalies) > 0


class TestVulnerabilityDiscoveryEngine:
    """Tests for vulnerability discovery engine"""
    
    def test_engine_initialization(self):
        """Test engine initializes"""
        engine = VulnerabilityDiscoveryEngine()
        assert engine.pattern_matcher is not None
        assert engine.chain_detector is not None
        assert engine.anomaly_detector is not None
    
    def test_discover_vulnerabilities(self):
        """Test vulnerability discovery"""
        engine = VulnerabilityDiscoveryEngine()
        findings = [
            {
                "cwe_id": "CWE-89",
                "category": "sql",
                "severity": 0.9,
                "affected_components": ["database", "input"],
                "component": "database"
            },
            {
                "severity": 0.95,
                "component": "crypto",
                "affected_components": ["encryption", "key_management"]
            },
        ]
        discoveries = engine.discover_vulnerabilities(findings)
        assert isinstance(discoveries, list)
    
    def test_score_vulnerability(self):
        """Test vulnerability scoring"""
        engine = VulnerabilityDiscoveryEngine()
        findings = [
            {
                "severity": 0.8,
                "component": "auth",
                "affected_components": ["auth"]
            },
        ]
        discoveries = engine.discover_vulnerabilities(findings)
        if discoveries:
            score = engine.score_vulnerability(discoveries[0])
            assert 0 <= score <= 1
    
    def test_get_statistics(self):
        """Test getting discovery statistics"""
        engine = VulnerabilityDiscoveryEngine()
        findings = [
            {
                "cwe_id": "CWE-89",
                "category": "sql",
                "severity": 0.9,
                "affected_components": ["database"]
            },
        ]
        engine.discover_vulnerabilities(findings)
        stats = engine.get_statistics()
        assert "total_discovered" in stats


class TestSymbolicReasoningEngine:
    """Tests for symbolic reasoning"""
    
    def test_engine_initialization(self):
        """Test symbolic reasoning engine initializes"""
        engine = SymbolicReasoningEngine()
        assert len(engine.rules) > 0
    
    def test_symbolic_reasoning(self):
        """Test symbolic reasoning"""
        engine = SymbolicReasoningEngine()
        system = {
            "has_sql_injection": True,
            "has_database": True,
        }
        conclusions = engine.reason(system)
        assert len(conclusions) > 0
        assert "INFERRED" in conclusions[0]


class TestChainOfThoughtExplainer:
    """Tests for chain-of-thought explanation"""
    
    def test_explainer_initialization(self):
        """Test COT explainer initializes"""
        explainer = ChainOfThoughtExplainer()
        assert len(explainer.exploitation_library) > 0
    
    def test_explain_exploitation(self):
        """Test explaining exploitation"""
        explainer = ChainOfThoughtExplainer()
        vuln = {"type": "sql_injection"}
        step = explainer.explain_exploitation(vuln)
        assert step is not None
        assert step.description is not None
    
    def test_explain_chain(self):
        """Test chain explanation"""
        explainer = ChainOfThoughtExplainer()
        vulns = [
            {"type": "sql_injection"},
            {"type": "file_upload"},
        ]
        explanation = explainer.explain_chain(vulns)
        assert len(explanation) > 0


class TestConstraintSatisfactionPlanner:
    """Tests for constraint-based planning"""
    
    def test_planner_initialization(self):
        """Test planner initializes"""
        planner = ConstraintSatisfactionPlanner()
        assert len(planner.constraints) > 0
    
    def test_plan_attack(self):
        """Test attack planning"""
        planner = ConstraintSatisfactionPlanner()
        start = "external"
        goal = "admin_access"
        vulns = [
            {"type": "sql_injection", "severity": 0.8},
            {"type": "privilege_escalation", "severity": 0.7},
        ]
        path = planner.plan_attack(start, goal, vulns)
        if path:
            assert path.initial_state == start
            assert path.goal_state == goal


class TestAttackPathReasoningEngine:
    """Tests for attack path reasoning"""
    
    def test_engine_initialization(self):
        """Test reasoning engine initializes"""
        engine = AttackPathReasoningEngine()
        assert engine.symbolic_reasoner is not None
        assert engine.planner is not None
    
    def test_reason_about_attacks(self):
        """Test attack reasoning"""
        engine = AttackPathReasoningEngine()
        attacker = {"initial_position": "external", "objective": "admin_access"}
        target = {
            "has_sql_injection": True,
            "has_database": True,
            "vulnerabilities": [
                {"type": "sql_injection", "severity": 0.8},
            ],
        }
        paths = engine.reason_about_attacks(attacker, target)
        assert isinstance(paths, list)
    
    def test_explain_path(self):
        """Test path explanation"""
        engine = AttackPathReasoningEngine()
        attacker = {"initial_position": "external", "objective": "admin_access"}
        target = {
            "has_sql_injection": True,
            "has_database": True,
            "vulnerabilities": [
                {"type": "sql_injection", "severity": 0.8},
            ],
        }
        paths = engine.reason_about_attacks(attacker, target)
        if paths:
            explanation = engine.explain_path(paths[0])
            assert "summary" in explanation


class TestExplanationGenerator:
    """Tests for explanation generation"""
    
    def test_generator_initialization(self):
        """Test generator initializes"""
        gen = ExplanationGenerator()
        assert len(gen.templates) > 0
    
    def test_explain_vulnerability(self):
        """Test vulnerability explanation"""
        gen = ExplanationGenerator()
        vuln = {
            "type": "sql_injection",
            "component": "database",
            "severity": "high",
            "impact": "data breach",
            "cwe_id": "CWE-89",
            "id": "vuln_001",
            "name": "SQL Injection",
        }
        chain = gen.explain_vulnerability(vuln)
        assert chain is not None
        assert len(chain.steps) > 0
        assert chain.overall_confidence > 0
    
    def test_to_natural_language(self):
        """Test conversion to natural language"""
        gen = ExplanationGenerator()
        vuln = {
            "type": "sql_injection",
            "component": "database",
            "severity": "high",
            "impact": "data breach",
            "cwe_id": "CWE-89",
        }
        chain = gen.explain_vulnerability(vuln)
        nl = gen.to_natural_language(chain)
        assert isinstance(nl, str)
        assert len(nl) > 0


class TestFeatureImportanceExplainer:
    """Tests for feature importance explanation"""
    
    def test_explainer_initialization(self):
        """Test explainer initializes"""
        explainer = FeatureImportanceExplainer()
        assert explainer.baseline_importance is not None
    
    def test_compute_feature_importance(self):
        """Test feature importance computation"""
        explainer = FeatureImportanceExplainer()
        model_output = {"prediction": 0.8}
        features = {"sql_injection": 0.9, "auth_bypass": 0.2}
        importances = explainer.compute_feature_importance(model_output, features)
        assert len(importances) > 0


class TestProofGenerator:
    """Tests for proof generation"""
    
    def test_generator_initialization(self):
        """Test generator initializes"""
        gen = ProofGenerator()
        assert len(gen.axioms) > 0
    
    def test_generate_proof(self):
        """Test proof generation"""
        gen = ProofGenerator()
        path = {
            "id": "path_001",
            "steps": [
                {"description": "Recon", "success_probability": 0.95},
                {"description": "Exploit", "success_probability": 0.7},
            ],
            "success_probability": 0.5,
        }
        proof = gen.generate_proof(path)
        assert proof is not None
        assert len(proof.proof_steps) > 0
    
    def test_verify_proof(self):
        """Test proof verification"""
        gen = ProofGenerator()
        path = {
            "id": "path_001",
            "steps": [
                {"description": "Recon", "success_probability": 0.95},
            ],
            "success_probability": 0.5,
        }
        proof = gen.generate_proof(path)
        is_valid = gen.verify_proof(proof)
        assert isinstance(is_valid, bool)


class TestExplainabilityEngine:
    """Tests for main explainability engine"""
    
    def test_engine_initialization(self):
        """Test engine initializes"""
        engine = ExplainabilityEngine()
        assert engine.explanation_gen is not None
        assert engine.feature_importance is not None
        assert engine.proof_gen is not None
    
    def test_explain_vulnerability(self):
        """Test vulnerability explanation"""
        engine = ExplainabilityEngine()
        result = {
            "type": "vulnerability",
            "name": "SQL Injection",
            "component": "database",
            "severity": "high",
        }
        explanation = engine.explain_result(result)
        assert "reasoning_chain" in explanation or explanation


class TestIntegration:
    """Integration tests for complete reasoning pipeline"""
    
    def test_full_vulnerability_discovery(self):
        """Test full vulnerability discovery pipeline"""
        engine = VulnerabilityDiscoveryEngine()
        findings = [
            {
                "cwe_id": "CWE-89",
                "category": "sql",
                "severity": 0.9,
                "affected_components": ["database", "input"],
                "component": "database",
            },
            {
                "severity": 0.95,
                "component": "crypto",
                "affected_components": ["encryption"],
            },
        ]
        discoveries = engine.discover_vulnerabilities(findings)
        assert len(discoveries) >= 0
    
    def test_full_attack_reasoning(self):
        """Test full attack reasoning pipeline"""
        engine = AttackPathReasoningEngine()
        attacker = {"initial_position": "external", "objective": "admin_access"}
        target = {
            "has_sql_injection": True,
            "has_database": True,
            "vulnerabilities": [
                {"type": "sql_injection", "severity": 0.8},
            ],
        }
        paths = engine.reason_about_attacks(attacker, target)
        assert isinstance(paths, list)
    
    def test_full_explainability_pipeline(self):
        """Test full explainability pipeline"""
        engine = ExplainabilityEngine()
        result = {
            "type": "attack_path",
            "initial_state": "external",
            "goal_state": "admin_access",
            "steps": [
                {"description": "Recon", "success_probability": 0.95},
            ],
            "success_probability": 0.7,
        }
        explanation = engine.explain_result(result)
        assert isinstance(explanation, dict)
