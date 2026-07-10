"""Runtime v11: protect CSP-hash-authorized inline script/style bytes."""

from . import core
from . import runtime_v1 as _v1
from . import runtime_v8 as _v8
from . import runtime_v9 as _v9
from .runtime_v10 import *  # noqa: F401,F403


def _contains_csp_hash(tokens):
    if not tokens:
        return False
    for token in tokens:
        value = token.strip().strip("'").lower()
        if value.startswith(("sha256-", "sha384-", "sha512-")):
            return True
    return False


def _first_policy_tokens(policy, names):
    for name in names:
        if name in policy:
            return policy[name]
    return None


def _inline_css_is_attribute(reference, document):
    opening = document.text.rfind("<", 0, reference.start)
    closing = document.text.rfind(">", 0, reference.start)
    return opening > closing


def _inline_hash_guarded(reference, document, policies):
    if reference.syntax == "js":
        chains = ("script-src-elem", "script-src", "default-src")
    elif reference.syntax == "css":
        if _inline_css_is_attribute(reference, document):
            chains = ("style-src-attr", "style-src", "default-src")
        else:
            chains = ("style-src-elem", "style-src", "default-src")
    else:
        return False
    for policy in policies:
        if _contains_csp_hash(_first_policy_tokens(policy, chains)):
            return True
    return False


_resolve_scan_v10 = _v1._resolve_scan


def _resolve_scan_v11(scan, mode, fetcher, rules, allow_unverified):
    resolved, _assets = _resolve_scan_v10(scan, mode, fetcher, rules, allow_unverified)
    policies = {}
    for item in resolved:
        reference = item.reference
        if item.action not in ("local", "remote"):
            continue
        if reference.file_path.suffix.lower() not in (".html", ".htm") or reference.syntax not in ("js", "css"):
            continue
        file_name = str(reference.file_path)
        if file_name not in policies:
            policies[file_name] = _v8._csp_policies(scan.documents[file_name])
        if _inline_hash_guarded(reference, scan.documents[file_name], policies[file_name]):
            item.action = "unresolved"
            item.replacement = ""
            item.verification = ""
            item.reason = "rewriting this inline block would invalidate its Content-Security-Policy hash"
            item.asset = None
    roots = [item.asset for item in resolved if item.action == "local" and item.asset is not None]
    return resolved, _v1._collect_assets(roots)


_v1._resolve_scan = _resolve_scan_v11


try:
    import nuiwallfix as _public_package
    _public_package.scan_target = core.scan_target
except ImportError:
    pass
