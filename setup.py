# setup.py
from setuptools import setup, find_packages

setup(
    name             = "mistcoder",
    version          = "1.0.0",
    description      = "Threat-Native Blockchain Security Scanner",
    packages         = find_packages(),
    python_requires  = ">=3.10",
    entry_points     = {
        "console_scripts": [
            "mistcoder=blockchain.mistcoder_cli:main",
        ]
    },
)