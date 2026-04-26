"""
MOD-04: Attack Path Reasoning Engine

Generates step-by-step attack reasoning through:
- Symbolic reasoning (logic-based)
- Chain-of-thought exploitation
- Constraint satisfaction planning
- Multi-step attack discovery
"""

from dataclasses import dataclass
from typing import List, Set, Dict, Optional, Tuple
from enum import Enum


class ExploitationType(Enum):
    """Types of exploitation techniques"""
    DIRECT = "direct"  # Direct exploitation
    CHAINED = "chained"  # Requires prior exploitation
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"


class PreconditionType(Enum):
    """Types of preconditions for exploitation"""
    CAPABILITY = "capability"  # Attacker capability required
    ACCESS = "access"  # System access required
    KNOWLEDGE = "knowledge"  # Knowledge required
    TIMING = "timing"  # Timing condition


@dataclass
class Precondition:
    """Precondition for exploitation"""
    precond_id: str
    precond_type: PreconditionType
    description: str
    satisfied: bool = False


@dataclass
class ExploitationStep:
    """Single step in exploitation chain"""
    step_id: str
    description: str
    exploitation_type: ExploitationType
    required_preconditions: List[Precondition]
    result: str  # What state this achieves
    risk_level: float  # 0-1, detection risk
    success_probability: float  # 0-1
    required_tools: List[str]
    estimated_time: float  # seconds


@dataclass
class AttackPath:
    """Complete attack path from initial access to goal"""
    path_id: str
    initial_state: str  # Attacker's starting position
    goal_state: str  # Target objective
    steps: List[ExploitationStep]
    total_risk: float  # Cumulative risk
    success_probability: float
    estimated_duration: float
    required_capabilities: Set[str]
    feasibility_score: float  # 0-1
    reasoning_chain: List[str]  # Step-by-step explanation


class SymbolicReasoningEngine:
    """
    Logic-based reasoning about exploitation.
    Uses symbolic rules and deductive reasoning.
    """
    
    def __init__(self):
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> Dict[str, callable]:
        """Initialize reasoning rules"""
        return {
            "sql_injection_to_data_access": self._rule_sql_to_data,
            "file_access_to_rce": self._rule_file_to_rce,
            "auth_bypass_to_admin": self._rule_auth_to_admin,
            "info_disclosure_enables_targeted": self._rule_info_to_targeted,
        }
    
    def _rule_sql_to_data(self, system: Dict) -> bool:
        """Rule: If SQL injection exists, can read sensitive data"""
        return system.get("has_sql_injection") and system.get("has_database")
    
    def _rule_file_to_rce(self, system: Dict) -> bool:
        """Rule: If file upload exists, can achieve RCE"""
        return system.get("has_file_upload") and not system.get("file_validation")
    
    def _rule_auth_to_admin(self, system: Dict) -> bool:
        """Rule: If auth bypass exists, can become admin"""
        return system.get("has_auth_bypass") and system.get("has_privilege_system")
    
    def _rule_info_to_targeted(self, system: Dict) -> bool:
        """Rule: If info disclosure, can mount targeted attacks"""
        return system.get("has_info_disclosure")
    
    def reason(self, system: Dict) -> List[str]:
        """
        Perform symbolic reasoning about exploitation.
        
        Args:
            system: Dict describing system state and vulnerabilities
        
        Returns:
            List of reasoning conclusions
        """
        conclusions = []
        
        # Apply rules
        for rule_name, rule_func in self.rules.items():
            if rule_func(system):
                conclusions.append(f"INFERRED: {rule_name}")
        
        return conclusions


class ChainOfThoughtExplainer:
    """
    Generates step-by-step exploitation explanations.
    Chain-of-thought reasoning for attack paths.
    """
    
    def __init__(self):
        self.exploitation_library = self._build_exploitation_library()
    
    def _build_exploitation_library(self) -> Dict[str, ExploitationStep]:
        """Build library of known exploitation techniques"""
        return {
            "reconnaissance": ExploitationStep(
                step_id="step_001",
                description="Perform reconnaissance to map system",
                exploitation_type=ExploitationType.DIRECT,
                required_preconditions=[],
                result="system_map",
                risk_level=0.1,
                success_probability=0.95,
                required_tools=["nmap", "curl", "browser"],
                estimated_time=300
            ),
            "find_vulnerable_endpoint": ExploitationStep(
                step_id="step_002",
                description="Identify vulnerable web endpoint",
                exploitation_type=ExploitationType.DIRECT,
                required_preconditions=[
                    Precondition("pre_001", PreconditionType.KNOWLEDGE, "Know system topology")
                ],
                result="vulnerable_endpoint_found",
                risk_level=0.2,
                success_probability=0.85,
                required_tools=["burp", "scanner"],
                estimated_time=600
            ),
            "sql_injection_attack": ExploitationStep(
                step_id="step_003",
                description="Exploit SQL injection vulnerability",
                exploitation_type=ExploitationType.DIRECT,
                required_preconditions=[
                    Precondition("pre_002", PreconditionType.KNOWLEDGE, "Know SQL syntax")
                ],
                result="database_access",
                risk_level=0.4,
                success_probability=0.7,
                required_tools=["sqlmap"],
                estimated_time=120
            ),
            "extract_credentials": ExploitationStep(
                step_id="step_004",
                description="Extract credentials from database",
                exploitation_type=ExploitationType.DIRECT,
                required_preconditions=[
                    Precondition("pre_003", PreconditionType.ACCESS, "Have database access")
                ],
                result="admin_credentials",
                risk_level=0.3,
                success_probability=0.9,
                required_tools=["hashcat"],
                estimated_time=1800
            ),
            "privilege_escalation": ExploitationStep(
                step_id="step_005",
                description="Use credentials to escalate privileges",
                exploitation_type=ExploitationType.CHAINED,
                required_preconditions=[
                    Precondition("pre_004", PreconditionType.CAPABILITY, "Have valid credentials")
                ],
                result="admin_access",
                risk_level=0.5,
                success_probability=0.8,
                required_tools=["sudo", "exploit_kit"],
                estimated_time=300
            ),
        }
    
    def explain_exploitation(self, vulnerability: Dict) -> ExploitationStep:
        """
        Generate exploitation explanation for a vulnerability.
        
        Args:
            vulnerability: Vulnerability to explain
        
        Returns:
            ExploitationStep describing how to exploit it
        """
        vuln_type = vulnerability.get("type", "unknown")
        
        # Map vulnerability types to exploitation steps
        if vuln_type == "sql_injection":
            return self.exploitation_library["sql_injection_attack"]
        elif vuln_type == "auth_bypass":
            return self.exploitation_library["privilege_escalation"]
        else:
            return ExploitationStep(
                step_id="step_unknown",
                description=f"Exploit {vuln_type}",
                exploitation_type=ExploitationType.DIRECT,
                required_preconditions=[],
                result="unknown_outcome",
                risk_level=0.5,
                success_probability=0.5,
                required_tools=[],
                estimated_time=600
            )
    
    def explain_chain(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate chain-of-thought explanation for vulnerability chain"""
        chain_explanation = []
        
        chain_explanation.append("=== Attack Chain Explanation ===")
        for i, vuln in enumerate(vulnerabilities, 1):
            step = self.explain_exploitation(vuln)
            chain_explanation.append(f"\nStep {i}: {step.description}")
            chain_explanation.append(f"  Risk: {step.risk_level}")
            chain_explanation.append(f"  Success Probability: {step.success_probability}")
            chain_explanation.append(f"  Result: {step.result}")
        
        return chain_explanation


class ConstraintSatisfactionPlanner:
    """
    Plans attack paths subject to constraints.
    Uses constraint satisfaction to ensure feasibility.
    """
    
    def __init__(self):
        self.constraints = self._define_constraints()
    
    def _define_constraints(self) -> Dict[str, callable]:
        """Define planning constraints"""
        return {
            "precondition_satisfaction": self._check_preconditions,
            "temporal_ordering": self._check_temporal_order,
            "resource_availability": self._check_resources,
        }
    
    def _check_preconditions(self, path: List[ExploitationStep]) -> bool:
        """Check that all preconditions are satisfied in order"""
        satisfied_states = set()
        
        for step in path:
            # Check preconditions
            for precond in step.required_preconditions:
                if precond.precond_id not in satisfied_states:
                    return False
            
            # Add result to satisfied states
            satisfied_states.add(step.result)
        
        return True
    
    def _check_temporal_order(self, path: List[ExploitationStep]) -> bool:
        """Check that steps are in valid temporal order"""
        # Direct exploitations can come first
        # Chained exploitations require prior steps
        has_initial = any(s.exploitation_type == ExploitationType.DIRECT 
                         for s in path[:len(path)//2])
        return has_initial
    
    def _check_resources(self, path: List[ExploitationStep]) -> bool:
        """Check that required resources are available"""
        # For now, assume attacker has all tools
        return True
    
    def plan_attack(self, start_state: str, goal_state: str,
                   available_vulns: List[Dict]) -> Optional[AttackPath]:
        """
        Plan attack path from start to goal.
        
        Args:
            start_state: Attacker's initial position
            goal_state: Objective (e.g., "admin_access")
            available_vulns: Vulnerabilities to exploit
        
        Returns:
            AttackPath if feasible, None otherwise
        """
        # Build exploitation library from available vulnerabilities
        steps = []
        current_state = start_state
        
        # Add reconnaissance
        recon_step = ExploitationStep(
            step_id="recon",
            description="Initial reconnaissance",
            exploitation_type=ExploitationType.DIRECT,
            required_preconditions=[],
            result="system_knowledge",
            risk_level=0.1,
            success_probability=0.95,
            required_tools=[],
            estimated_time=300
        )
        steps.append(recon_step)
        current_state = "system_knowledge"
        
        # Add vulnerability exploitation steps
        for vuln in available_vulns:
            step = self._create_step_for_vuln(vuln)
            steps.append(step)
        
        # Check constraints
        if not self._check_preconditions(steps):
            return None
        if not self._check_temporal_order(steps):
            return None
        
        # Calculate metrics
        total_risk = sum(s.risk_level for s in steps) / len(steps)
        success_prob = 1.0
        for s in steps:
            success_prob *= s.success_probability
        
        total_time = sum(s.estimated_time for s in steps)
        required_caps = set()
        for s in steps:
            required_caps.update(s.required_tools)
        
        reasoning_chain = [f"Step {i+1}: {s.description}" 
                          for i, s in enumerate(steps)]
        
        return AttackPath(
            path_id=f"path_{len(steps)}_steps",
            initial_state=start_state,
            goal_state=goal_state,
            steps=steps,
            total_risk=total_risk,
            success_probability=success_prob,
            estimated_duration=total_time,
            required_capabilities=required_caps,
            feasibility_score=success_prob * (1 - total_risk),
            reasoning_chain=reasoning_chain
        )
    
    def _create_step_for_vuln(self, vuln: Dict) -> ExploitationStep:
        """Create exploitation step for vulnerability"""
        vuln_type = vuln.get("type", "unknown")
        
        return ExploitationStep(
            step_id=f"step_{vuln_type}",
            description=f"Exploit {vuln_type}: {vuln.get('description', '')}",
            exploitation_type=ExploitationType.DIRECT,
            required_preconditions=[],
            result=f"{vuln_type}_success",
            risk_level=vuln.get("severity", 0.5),
            success_probability=0.7,
            required_tools=[vuln_type],
            estimated_time=600
        )


class AttackPathReasoningEngine:
    """
    Main attack path reasoning engine.
    Combines symbolic reasoning, chain-of-thought, and constraint planning.
    """
    
    def __init__(self):
        self.symbolic_reasoner = SymbolicReasoningEngine()
        self.cot_explainer = ChainOfThoughtExplainer()
        self.planner = ConstraintSatisfactionPlanner()
        self.generated_paths: List[AttackPath] = []
    
    def reason_about_attacks(self, attacker_profile: Dict,
                           target_system: Dict) -> List[AttackPath]:
        """
        Generate attack paths for given attacker and target.
        
        Args:
            attacker_profile: Attacker capabilities and constraints
            target_system: Target system vulnerabilities and architecture
        
        Returns:
            List of feasible attack paths
        """
        paths = []
        
        # Step 1: Symbolic reasoning about what's possible
        conclusions = self.symbolic_reasoner.reason(target_system)
        
        # Step 2: Get vulnerabilities from target system
        vulnerabilities = target_system.get("vulnerabilities", [])
        
        # Step 3: Plan attack paths using constraint satisfaction
        start_state = attacker_profile.get("initial_position", "external")
        goal_state = attacker_profile.get("objective", "admin_access")
        
        attack_path = self.planner.plan_attack(start_state, goal_state, 
                                              vulnerabilities)
        
        if attack_path:
            paths.append(attack_path)
        
        self.generated_paths = paths
        return paths
    
    def explain_path(self, path: AttackPath) -> Dict:
        """Generate natural language explanation for attack path"""
        return {
            "summary": f"Attack path from {path.initial_state} to {path.goal_state}",
            "steps": path.reasoning_chain,
            "success_probability": path.success_probability,
            "risk": path.total_risk,
            "duration": f"{path.estimated_duration} seconds",
            "required_capabilities": list(path.required_capabilities),
        }
    
    def get_statistics(self) -> Dict:
        """Get reasoning statistics"""
        if not self.generated_paths:
            return {}
        
        return {
            "total_paths": len(self.generated_paths),
            "avg_steps": sum(len(p.steps) for p in self.generated_paths) / len(self.generated_paths),
            "avg_success_prob": sum(p.success_probability for p in self.generated_paths) / len(self.generated_paths),
            "avg_risk": sum(p.total_risk for p in self.generated_paths) / len(self.generated_paths),
        }
