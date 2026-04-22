"""
MISTCODER — Multi-layer Intelligent Static/Dynamic Code Reasoning Engine
Version: 0.5.0  |  Phase: 4 (Reasoning Engine)

Quick start:
    from mistcoder import scan, covenant, phantom
    results = scan("src/")
"""
from threading import Lock

__version__ = "0.5.0"
__author__  = "MISTCODER Contributors"
__license__ = "MIT"
_PATH_SETUP_LOCK = Lock()
_PATH_CONFIGURED = False

def _ensure_repo_root_on_path() -> None:
    """Ensure local module imports resolve when used as a source checkout."""
    global _PATH_CONFIGURED
    if _PATH_CONFIGURED:
        return

    with _PATH_SETUP_LOCK:
        if _PATH_CONFIGURED:
            return

        import sys
        from pathlib import Path

        repo_root = str(Path(__file__).resolve().parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)

        _PATH_CONFIGURED = True


# Lazy imports — only load what's available
# TODO: Replace path mutation with proper package entry points when a stable
# distribution layout is introduced in a future iteration.
def scan(target: str, **kwargs):
    """Run a full MISTCODER scan on a target path or URL."""
    _ensure_repo_root_on_path()
    from mistcoder import run_scan
    return run_scan(target, **kwargs)


def get_version() -> str:
    return __version__


def status() -> dict:
    """Return availability status of all engines."""
    _ensure_repo_root_on_path()
    from mistcoder import get_module_status
    layers, statuses = get_module_status()
    return statuses
