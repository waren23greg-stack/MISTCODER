"""
MISTCODER MOD-07 — Threat Knowledge Graph Builder
Version 0.1.0 — Automatic graph construction from MOD-02 findings
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import json


class ThreatKGBuilder:
    """
    Builds a threat knowledge graph from security analysis findings.
    
    Input: MOD-02 analysis results (findings + control flow graphs)
    Output: Neo4j-ready threat graph with nodes and relationships
    """

    def __init__(self, backend):
        """
        backend: GraphBackend instance (Neo4j or In-Memory)
        """
        self.backend = backend
        self._node_counter = 0
        self._edge_counter = 0

    def _next_node_id(self, prefix: str = "N") -> str:
        self._node_counter += 1
        return f"{prefix}{self._node_counter:04d}"

    def _next_edge_id(self, prefix: str = "E") -> str:
        self._edge_counter += 1
        return f"{prefix}{self._edge_counter:04d}"

    def ingest_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Process MOD-02 findings and create weakness nodes in the graph.
        
        Expected finding structure:
        {
            "id": "FD0001",
            "call_name": "eval",
            "severity": "CRITICAL",
            "cvss_score": 9.1,
            "cwe_id": "CWE-95",
            "file": "app.py",
            "line": 42,
            "taint_path": ["user_input", "eval"]
        }
        """
        ingested = 0
        failed = 0

        for finding in findings:
            try:
                # Create weakness node
                vuln_id = self._next_node_id("VUL")
                severity = finding.get("severity", "MEDIUM")
                cvss = self._severity_to_cvss(severity)

                props = {
                    "cvss_score": cvss,
                    "cwe_id": finding.get("cwe_id", "CWE-0"),
                    "call_name": finding.get("call_name", "unknown"),
                    "file": finding.get("file", "unknown"),
                    "line": finding.get("line", 0),
                    "type": "ConfirmedVuln",
                    "severity": severity
                }

                self.backend.add_node(
                    vuln_id,
                    "Weakness",
                    f"{finding.get('call_name', 'unknown')}_L{finding.get('line', 0)}",
                    props
                )

                ingested += 1

            except Exception as e:
                print(f"[TKG] Error ingesting finding {finding.get('id', '?')}: {e}")
                failed += 1

        return {
            "ingested": ingested,
            "failed": failed,
            "total": len(findings)
        }

    def ingest_control_flow(self, cfg: Dict) -> Dict[str, Any]:
        """
        Process control flow graph from MOD-02 and create function/call nodes.
        
        Expected CFG structure:
        {
            "functions": [
                {
                    "id": "main",
                    "name": "main",
                    "calls": ["process", "validate"],
                    "callees": ["process"]
                }
            ]
        }
        """
        ingested = 0

        functions = cfg.get("functions", [])
        for func in functions:
            try:
                func_id = self._next_node_id("FN")
                self.backend.add_node(
                    func_id,
                    "Function",
                    func.get("name", "unknown"),
                    {"file": cfg.get("file", "unknown")}
                )

                # Create call edges
                for callee in func.get("callees", []):
                    self.backend.add_edge(
                        func_id,
                        callee,
                        "Calls",
                        {}
                    )

                ingested += 1

            except Exception as e:
                print(f"[TKG] Error ingesting function {func.get('name', '?')}: {e}")

        return {"ingested": ingested}

    def ingest_data_flow(self, taint_flows: List[Dict]) -> Dict[str, Any]:
        """
        Process taint flow analysis and create source -> sink edges.
        
        Expected taint structure:
        {
            "source": "user_input",
            "sink": "eval",
            "path": ["user_input", "process", "eval"],
            "sanitized": false
        }
        """
        ingested = 0

        for flow in taint_flows:
            try:
                source = flow.get("source", "unknown")
                sink = flow.get("sink", "unknown")
                sanitized = flow.get("sanitized", False)

                # Create taint flow edge
                edge_type = "TaintFlow_Sanitized" if sanitized else "TaintFlow"
                self.backend.add_edge(
                    source,
                    sink,
                    edge_type,
                    {"path_length": len(flow.get("path", []))}
                )

                ingested += 1

            except Exception as e:
                print(f"[TKG] Error ingesting taint flow: {e}")

        return {"ingested": ingested}

    def create_attacker_positions(self) -> Dict[str, Any]:
        """
        Create standard attacker positions for threat modeling.
        """
        positions = [
            {
                "id": "ATK-EXTERNAL",
                "name": "External",
                "description": "Unauthenticated internet attacker"
            },
            {
                "id": "ATK-AUTH-USER",
                "name": "AuthenticatedUser",
                "description": "Legitimate user with valid credentials"
            },
            {
                "id": "ATK-INTERNAL",
                "name": "InternalNetwork",
                "description": "Attacker on internal network (VPN/LAN)"
            },
            {
                "id": "ATK-CODE-EXEC",
                "name": "CodeExecution",
                "description": "Attacker with arbitrary code execution"
            }
        ]

        created = 0
        for pos in positions:
            try:
                self.backend.add_node(
                    pos["id"],
                    "AttackerPosition",
                    pos["name"],
                    {"description": pos["description"]}
                )
                created += 1
            except Exception as e:
                print(f"[TKG] Error creating attacker position {pos['name']}: {e}")

        return {"created": created}

    def create_mitigations_from_controls(self, controls: List[Dict]) -> Dict[str, Any]:
        """
        Create mitigation nodes from security controls.
        
        Expected control structure:
        {
            "id": "AUTH-001",
            "type": "Authentication",
            "name": "Multi-factor authentication",
            "effectiveness": 0.95
        }
        """
        created = 0

        for control in controls:
            try:
                mit_id = self._next_node_id("MIT")
                self.backend.add_node(
                    mit_id,
                    "Mitigation",
                    control.get("name", "unknown"),
                    {
                        "control_type": control.get("type", "Unknown"),
                        "effectiveness": control.get("effectiveness", 0.8)
                    }
                )
                created += 1
            except Exception as e:
                print(f"[TKG] Error creating mitigation {control.get('name', '?')}: {e}")

        return {"created": created}

    def create_assets(self, asset_list: List[Dict]) -> Dict[str, Any]:
        """
        Create asset nodes representing data stores and capabilities.
        
        Expected asset structure:
        {
            "id": "AST-001",
            "name": "customer_database",
            "type": "DataStore",
            "sensitivity": "CRITICAL"
        }
        """
        created = 0

        for asset in asset_list:
            try:
                self.backend.add_node(
                    asset.get("id", self._next_node_id("AST")),
                    "Asset",
                    asset.get("name", "unknown"),
                    {
                        "asset_type": asset.get("type", "DataStore"),
                        "sensitivity": asset.get("sensitivity", "MEDIUM")
                    }
                )
                created += 1
            except Exception as e:
                print(f"[TKG] Error creating asset {asset.get('name', '?')}: {e}")

        return {"created": created}

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity label to CVSS score"""
        mapping = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 3.0,
            "INFO": 1.0
        }
        return mapping.get(severity, 5.0)

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get current graph statistics"""
        stats = self.backend.get_stats()
        return {
            **stats,
            "builder_nodes_created": self._node_counter,
            "builder_edges_created": self._edge_counter,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


class ThreatModelingPipeline:
    """
    End-to-end pipeline for building threat knowledge graphs.
    Orchestrates TKG builder with analysis inputs.
    """

    def __init__(self, backend):
        self.backend = backend
        self.builder = ThreatKGBuilder(backend)
        self.stages = []

    def run(self, analysis_result: Dict) -> Dict[str, Any]:
        """
        Execute full threat modeling pipeline.
        
        Input: Complete MOD-02 analysis result
        Output: Populated threat knowledge graph
        """
        result = {
            "pipeline_version": "0.1.0",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stages": {}
        }

        try:
            # Stage 1: Create attacker positions
            print("[TKG] Stage 1: Creating attacker positions...")
            stage1 = self.builder.create_attacker_positions()
            result["stages"]["attacker_positions"] = stage1

            # Stage 2: Create assets
            print("[TKG] Stage 2: Creating asset nodes...")
            assets = analysis_result.get("assets", [])
            stage2 = self.builder.create_assets(assets)
            result["stages"]["assets"] = stage2

            # Stage 3: Ingest findings (vulnerabilities)
            print("[TKG] Stage 3: Ingesting security findings...")
            findings = analysis_result.get("findings", [])
            stage3 = self.builder.ingest_findings(findings)
            result["stages"]["findings"] = stage3

            # Stage 4: Ingest control flow
            print("[TKG] Stage 4: Ingesting control flow graph...")
            cfg = analysis_result.get("control_flow", {})
            stage4 = self.builder.ingest_control_flow(cfg)
            result["stages"]["control_flow"] = stage4

            # Stage 5: Ingest taint flows
            print("[TKG] Stage 5: Ingesting taint flows...")
            taint_flows = analysis_result.get("taint_flows", [])
            stage5 = self.builder.ingest_data_flow(taint_flows)
            result["stages"]["taint_flows"] = stage5

            # Stage 6: Create mitigations
            print("[TKG] Stage 6: Creating mitigation nodes...")
            controls = analysis_result.get("controls", [])
            stage6 = self.builder.create_mitigations_from_controls(controls)
            result["stages"]["mitigations"] = stage6

            # Final: Get stats
            result["final_stats"] = self.builder.get_graph_stats()
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            result["success"] = True

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            print(f"[TKG] Pipeline error: {e}")

        return result


if __name__ == "__main__":
    print("[MOD-07] Threat KG Builder Examples\n")

    # Mock example
    example_finding = {
        "id": "FD0001",
        "call_name": "eval",
        "severity": "CRITICAL",
        "cwe_id": "CWE-95",
        "file": "app.py",
        "line": 42
    }

    example_asset = {
        "id": "AST-001",
        "name": "customer_db",
        "type": "DataStore",
        "sensitivity": "CRITICAL"
    }

    print("Example finding:")
    print(json.dumps(example_finding, indent=2))
    print()

    print("Example asset:")
    print(json.dumps(example_asset, indent=2))