"""Runtime v8: bare crossorigin recognition and conservative CSP gating."""

import re
import urllib.parse

from . import core
from . import runtime_v1 as _v1
from . import runtime_v7 as _v7
from .runtime_v7 import *  # noqa: F401,F403


_scan_v7 = core.scan_target


def _tag_text(reference, document):
    opening = document.text.rfind("<", 0, reference.start)
    if opening < 0:
        return ""
    end = core._find_html_tag_end(document.text, opening + 1)
    if end <= reference.end:
        return ""
    return document.text[opening:end]


def _scan_crossorigin(target):
    result = _scan_v7(target)
    for reference in result.references:
        if reference.syntax != "html" or reference.context in ("html-module-script", "html-modulepreload"):
            continue
        document = result.documents.get(str(reference.file_path))
        if not document:
            continue
        tag = _tag_text(reference, document)
        if re.search(r"\bcrossorigin(?:\s*=|\s|/?>)", tag, re.IGNORECASE):
            reference.context = "html-crossorigin-asset"
    return result


core.scan_target = _scan_crossorigin


def _csp_policies(document):
    text = re.sub(r"<!--.*?-->", "", document.text, flags=re.DOTALL)
    policies = []
    offset = 0
    while True:
        match = re.search(r"<\s*meta\b", text[offset:], re.IGNORECASE)
        if not match:
            break
        opening = offset + match.start()
        end = core._find_html_tag_end(text, opening + 1)
        tag = text[opening:end]
        name_match = re.match(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9:-]*)", tag)
        if name_match:
            attributes = core._html_attributes(tag, opening, name_match.end())
            http_equiv = attributes.get("http-equiv", [])
            content = attributes.get("content", [])
            if http_equiv and content and http_equiv[0].value.strip().lower() == "content-security-policy":
                directives = {}
                for section in content[0].value.split(";"):
                    tokens = section.strip().split()
                    if tokens:
                        directives[tokens[0].lower()] = tokens[1:]
                policies.append(directives)
        offset = max(end, opening + 1)
    return policies


def _directive_for(reference, kind):
    if reference.context in ("js-worker", "js-sharedworker"):
        return "worker-src"
    return {
        "script": "script-src",
        "style": "style-src",
        "font": "font-src",
        "image": "img-src",
        "media": "media-src",
    }.get(kind, "default-src")


def _source_matches_remote(token, url):
    lowered = token.lower()
    parsed = urllib.parse.urlsplit(url)
    origin = "{}://{}".format(parsed.scheme.lower(), parsed.netloc.lower())
    if lowered == "*" or lowered == parsed.scheme.lower() + ":":
        return True
    if lowered.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")):
        return False
    if lowered.startswith("*."):
        host = lowered[2:].split(":", 1)[0]
        return parsed.hostname and (parsed.hostname.lower() == host or parsed.hostname.lower().endswith("." + host))
    if "://*." in lowered:
        scheme, host = lowered.split("://*.", 1)
        host = host.split("/", 1)[0].split(":", 1)[0]
        return parsed.scheme.lower() == scheme and parsed.hostname and parsed.hostname.lower().endswith("." + host)
    if lowered.startswith(("http://", "https://")):
        return origin == lowered.rstrip("/") or url.lower().startswith(lowered.rstrip("/") + "/")
    return False


def _policy_allows(policy, reference, kind, replacement, local):
    directive = _directive_for(reference, kind)
    tokens = policy.get(directive)
    if tokens is None and directive == "worker-src":
        tokens = policy.get("child-src")
    if tokens is None and directive not in ("script-src", "default-src"):
        tokens = policy.get("default-src")
    if tokens is None:
        return True, directive
    lowered = [token.lower() for token in tokens]
    if local:
        return any(token in ("'self'", "*", "https:") for token in lowered), directive
    return any(_source_matches_remote(token, replacement) for token in tokens), directive


def _asset_kinds(asset):
    values = []
    seen = set()

    def visit(item):
        key = str(item.path).lower()
        if key in seen:
            return
        seen.add(key)
        values.append(item.kind)
        for child in item.dependencies:
            visit(child)

    visit(asset)
    return values


_resolve_scan_v7 = _v1._resolve_scan


def _resolve_scan_with_csp(scan, mode, fetcher, rules, allow_unverified):
    resolved, _assets = _resolve_scan_v7(scan, mode, fetcher, rules, allow_unverified)
    policy_cache = {}
    for item in resolved:
        if item.action not in ("local", "remote") or item.reference.file_path.suffix.lower() not in (".html", ".htm"):
            continue
        if item.action == "remote" and item.replacement == item.reference.url:
            continue
        file_name = str(item.reference.file_path)
        if file_name not in policy_cache:
            policy_cache[file_name] = _csp_policies(scan.documents[file_name])
        policies = policy_cache[file_name]
        if not policies:
            continue
        kinds = _asset_kinds(item.asset) if item.action == "local" and item.asset else [item.reference.kind]
        denied = ""
        for policy in policies:
            for kind in kinds:
                allowed, directive = _policy_allows(
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


_v1._resolve_scan = _resolve_scan_with_csp


try:
    import nuiwallfix as _public_package
    _public_package.scan_target = core.scan_target
except ImportError:
    pass
