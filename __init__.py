"""
MISTCODER — Multi-layer Intelligent Static/Dynamic Code Reasoning Engine
Version: 0.5.0  |  Phase: 4 (Reasoning Engine)

Quick start:
    from mistcoder import scan, covenant, phantom
    results = scan("src/")
"""
__version__ = "0.5.0"
__author__  = "MISTCODER Contributors"
__license__ = "MIT"

# Lazy imports — only load what's available
def scan(target: str, **kwargs):
    """Run a full MISTCODER scan on a target path or URL."""
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from mistcoder import run_scan
    return run_scan(target, **kwargs)


def get_version() -> str:
    return __version__


def status() -> dict:
    """Return availability status of all engines."""
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from mistcoder import get_module_status
    layers, statuses = get_module_status()
    return statuses
