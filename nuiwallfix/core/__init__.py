"""Compatibility facade for the scanner core and public API."""

import importlib.util
import sys
from pathlib import Path


_implementation_path = Path(__file__).resolve().parent.parent / "core.py"
_spec = importlib.util.spec_from_file_location("nuiwallfix._scanner_core", str(_implementation_path))
_implementation = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _implementation
_spec.loader.exec_module(_implementation)

for _name in dir(_implementation):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_implementation, _name)


def apply_target(target, **options):
    from ..api import apply
    return apply(target, **options)


def restore_run(target, run_id, **options):
    from ..api import restore
    return restore(target, run_id, **options)
