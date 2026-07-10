"""Stable CLI shim.

The implementation is versioned so the toolbox can keep importing this module
while the command implementation evolves.
"""

import importlib
import re
from pathlib import Path


def _load_runtime():
    package_dir = Path(__file__).resolve().parent
    candidates = []
    for path in package_dir.glob("runtime_v*.py"):
        match = re.match(r"runtime_v(\d+)\.py$", path.name)
        if match:
            candidates.append((int(match.group(1)), path.stem))
    if not candidates:
        raise RuntimeError("nui-wallfix runtime is missing")
    module_name = max(candidates)[1]
    return importlib.import_module("{}.{}".format(__package__, module_name))


def main(argv=None):
    return _load_runtime().main(argv)
