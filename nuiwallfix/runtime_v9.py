"""Runtime v9: exact CSP fallback chains and resource-wide policy gating."""

import urllib.parse
from pathlib import Path

from . import core
from . import runtime_v1 as _v1
from . import runtime_v8 as _v8
from .runtime_v8 import *  # noqa: F401,F403


def _directive_for_v9(reference, kind):
    if reference.context in ("js-worker", "js-sharedworker"):
        return "worker-src"
    if kind == "script":
        if reference.syntax == "html" and reference.context in ("html-script", "html-module-script"):
            return "script-src-elem"
        return "script-src"
    if kind == "style":
        if reference.syntax == "html" and reference.context == "html-stylesheet":
            return "style-src-elem"
        return "style-src"
    return {
        "font": "font-src",
        "image": "img-src",
        "media": "media-src",
    }.get(kind, "default-src")


def _directive_tokens(policy, directive):
    chains = {
        "script-src-elem": ("script-src-elem", "script-src", "default-src"),
        "script-src": ("script-src", "default-src"),
        "style-src-elem": ("style-src-elem", "style-src", "default-src"),
        "style-src": ("style-src", "default-src"),
        "worker-src": ("worker-src", "child-src", "script-src", "default-src"),
        "child-src": ("child-src", "default-src"),
        "font-src": ("font-src", "default-src"),
        "img-src": ("img-src", "default-src"),
        "media-src": ("media-src", "default-src"),
        "default-src": ("default-src",),
    }
    for name in chains.get(directive, (directive, "default-src")):
        if name in policy:
            return policy[name]
    return None


def _source_matches_remote_v9(token, url):
    lowered = token.lower()
    parsed = urllib.parse.urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if lowered == "*" or lowered == parsed.scheme.lower() + ":":
        return True
    if lowered.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")):
        return False
    if lowered.startswith("*."):
        host = lowered[2:].split(":", 1)[0]
        return bool(hostname and hostname != host and hostname.endswith("." + host))
    if "://*." in lowered:
        scheme, remainder = lowered.split("://*.", 1)
        host = remainder.split("/", 1)[0].split(":", 1)[0]
        return bool(parsed.scheme.lower() == scheme and hostname and hostname != host and hostname.endswith("." + host))
    if not lowered.startswith(("http://", "https://")):
        return False
    try:
        source = urllib.parse.urlsplit(lowered)
    except ValueError:
        return False
    if source.scheme != parsed.scheme or source.netloc != parsed.netloc.lower():
        return False
    source_path = source.path or ""
    request_path = parsed.path or "/"
    if source_path in ("", "/"):
        return True
    if source_path.endswith("/"):
        return request_path.startswith(source_path)
    return request_path == source_path


def _policy_allows_v9(policy, reference, kind, replacement, local):
    directive = _directive_for_v9(reference, kind)
    tokens = _directive_tokens(policy, directive)
    if tokens is None:
        return True, directive
    lowered = [token.lower() for token in tokens]
    if directive.startswith("script-src") and "'strict-dynamic'" in lowered:
        return False, directive
    if local:
        return any(token in ("'self'", "*", "https:") for token in lowered), directive
    return any(_source_matches_remote_v9(token, replacement) for token in tokens), directive


def _loaded_html_policies(scan, resource):
    policies = []
    for file_name, document in scan.documents.items():
        path = Path(file_name)
        if path.suffix.lower() not in (".html", ".htm") or not core._is_within(path, resource.root):
            continue
        relative = core._posix(path.relative_to(resource.root))
        covered = path == resource.ui_file or not resource.file_patterns
        if not covered:
            covered = any(_v1._manifest_pattern_covers(pattern, relative) for pattern in resource.file_patterns)
        if covered:
            policies.extend(_v8._csp_policies(document))
    return policies


_resolve_before_csp = _v8._resolve_scan_v7


def _resolve_scan_v9(scan, mode, fetcher, rules, allow_unverified):
    resolved, _assets = _resolve_before_csp(scan, mode, fetcher, rules, allow_unverified)
    resource_policies = {
        str(resource.root).lower(): _loaded_html_policies(scan, resource)
        for resource in scan.resources
    }
    document_policies = {}
    for item in resolved:
        if item.action not in ("local", "remote"):
            continue
        if item.action == "remote" and item.replacement == item.reference.url:
            continue
        if item.reference.file_path.suffix.lower() in (".html", ".htm"):
            file_name = str(item.reference.file_path)
            if file_name not in document_policies:
                document_policies[file_name] = _v8._csp_policies(scan.documents[file_name])
            policies = document_policies[file_name]
        else:
            policies = resource_policies.get(str(item.reference.resource_root).lower(), [])
        if not policies:
            continue
        kinds = _v8._asset_kinds(item.asset) if item.action == "local" and item.asset else [item.reference.kind]
        denied = ""
        for policy in policies:
            for kind in kinds:
                allowed, directive = _policy_allows_v9(
                    policy,
                    item.reference,
                    kind,
                    item.replacement,
                    item.action == "local",
                )
                if not allowed:
                    denied = directive
                    break
            if denied:
                break
        if denied:
            item.action = "unresolved"
            item.replacement = ""
            item.verification = ""
            item.reason = "Content-Security-Policy {} does not allow the planned asset source".format(denied)
            item.asset = None
    roots = [item.asset for item in resolved if item.action == "local" and item.asset is not None]
    return resolved, _v1._collect_assets(roots)


_v1._resolve_scan = _resolve_scan_v9


try:
    import nuiwallfix as _public_package
    _public_package.scan_target = core.scan_target
except ImportError:
    pass
