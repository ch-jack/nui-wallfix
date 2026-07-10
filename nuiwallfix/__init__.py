"""FiveM NUI external asset scanner and rewriter."""

__version__ = "0.1.0"


def _runtime():
    from .cli import _load_runtime
    return _load_runtime()


def scan_target(target):
    return _runtime().core.scan_target(target)


def apply_target(target, **options):
    return _runtime().api_apply(target, **options)


def restore_run(target, run_id, **options):
    return _runtime().api_restore(target, run_id, **options)


__all__ = ["apply_target", "restore_run", "scan_target", "__version__"]
