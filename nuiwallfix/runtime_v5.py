"""Runtime v5: loaded-file scope and idempotent domestic targets."""

from . import core
from . import runtime_v1 as _v1
from .runtime_v4 import *  # noqa: F401,F403


_scan_target_base = core.scan_target


def _scan_loaded_files(target):
    result = _scan_target_base(target)
    resources = {str(item.root).lower(): item for item in result.resources}
    kept = []
    skipped_counts = {}
    for reference in result.references:
        resource = resources.get(str(reference.resource_root).lower())
        if not resource:
            kept.append(reference)
            continue
        relative = core._posix(reference.file_path.relative_to(resource.root))
        covered = reference.file_path == resource.ui_file
        if not covered and not resource.file_patterns:
            covered = True
        if not covered:
            covered = any(_v1._manifest_pattern_covers(pattern, relative) for pattern in resource.file_patterns)
        if covered:
            kept.append(reference)
        else:
            key = str(resource.root)
            skipped_counts[key] = skipped_counts.get(key, 0) + 1
    result.references = kept
    for resource_name, count in sorted(skipped_counts.items()):
        result.diagnostics.append({
            "level": "info",
            "resource": resource_name,
            "message": "skipped {} external reference(s) in files not covered by manifest files".format(count),
        })
    return result


core.scan_target = _scan_loaded_files

_resolve_mirror_base = _v1._resolve_mirror


def _resolve_mirror_idempotent(reference, fetcher, rules, allow_unverified):
    normalised = core._normalise_url(reference.url)
    for rule in rules:
        target = core._normalise_url(rule.get("target", ""))
        if target and normalised.startswith(target):
            return normalised, "already-provider-target"
    return _resolve_mirror_base(reference, fetcher, rules, allow_unverified)


_v1._resolve_mirror = _resolve_mirror_idempotent
