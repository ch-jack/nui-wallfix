"""Import-safe API for the future toolbox integration."""

from .cli import _load_runtime


def scan(target, **options):
    return _load_runtime().api_scan(target, **options)


def apply(target, **options):
    return _load_runtime().api_apply(target, **options)


def restore(target, run_id, **options):
    return _load_runtime().api_restore(target, run_id, **options)
