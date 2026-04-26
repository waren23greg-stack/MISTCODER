# Sandbox

Test targets and demo scan outputs for MISTCODER.

## Contents

    vulnerable_app/   -- deliberately vulnerable Flask app (demo target)
    run_demo.py       -- end-to-end pipeline demo script
    environments/     -- reserved for isolated simulation environments
    logs/             -- reserved for sandbox execution logs

## Running the demo

From the repo root:

    python sandbox/run_demo.py

Requirements: Python 3.11+ only (no external packages needed for core pipeline).
Flask is not required to scan the app -- MISTCODER reads source code, not HTTP.

## Output

    reports/MISTCODER_VulnFlask_demo.html   -- professional HTML report
    reports/demo/ir.json                    -- MOD-01 intermediate representation
    reports/demo/analysis.json              -- MOD-02 findings + taint flows
    reports/demo/reasoning.json             -- MOD-03 threat model
    reports/demo/scores.json                -- CVSS 3.1 risk scores
