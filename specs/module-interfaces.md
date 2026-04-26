# Module Interface Specifications

## MOD-01 --> MOD-02
Output : Normalized IR (JSON)
Fields : ast_tree, dependency_graph, file_metadata, language_detected

## MOD-02 --> MOD-03
Output : Analysis Report (JSON)
Fields : taint_flows[], cfg_nodes[], dynamic_anomalies[], cve_matches[]

## MOD-03 --> MOD-04
Output : Attack Path Graph (JSON)
Fields : attack_paths[], confidence_scores[], novelty_flags[], chain_descriptions[]

## MOD-04 --> MOD-05
Output : Simulation Results (JSON)
Fields : executed_paths[], outcomes[], audit_log_hash, risk_rating
