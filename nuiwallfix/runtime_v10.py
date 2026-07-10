"""Runtime v10: CSP duplicate/source matching parity and quiet JSON stderr."""

import contextlib
import io
import json
import re
import sys
from pathlib import Path

from . import core
from . import runtime_v1 as _v1
from . import runtime_v8 as _v8
from . import runtime_v9 as _v9
from .runtime_v9 import *  # noqa: F401,F403


def _csp_policies_first_directive(document):
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
                    if tokens and tokens[0].lower() not in directives:
                        directives[tokens[0].lower()] = tokens[1:]
                policies.append(directives)
        offset = max(end, opening + 1)
    return policies


_v8._csp_policies = _csp_policies_first_directive


_CSP_HOST_SOURCE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://)?"
    r"(?P<host>\*|\*\.[^/:]+|[^/:]+)"
    r"(?::(?P<port>\*|[0-9]+))?"
    r"(?P<path>/.*)?$"
)


def _source_matches_remote_v10(token, url):
    value = token.strip()
    lowered = value.lower()
    try:
        parsed = _v1.urllib.parse.urlsplit(url)
        request_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return False
    if lowered == "*" or lowered == parsed.scheme.lower() + ":":
        return True
    if lowered.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")):
        return False
    match = _CSP_HOST_SOURCE.match(value)
    if not match:
        return False
    source_scheme = (match.group("scheme") or "").lower()
    if source_scheme:
        if source_scheme != parsed.scheme.lower():
            return False
    elif parsed.scheme.lower() != "https":
        return False
    source_host = match.group("host").lower()
    request_host = (parsed.hostname or "").lower()
    if source_host == "*":
        host_matches = bool(request_host)
    elif source_host.startswith("*."):
        bare = source_host[2:]
        host_matches = bool(request_host and request_host != bare and request_host.endswith("." + bare))
    else:
        host_matches = request_host == source_host
    if not host_matches:
        return False
    source_port = match.group("port")
    if source_port and source_port != "*":
        if request_port != int(source_port):
            return False
    elif source_port is None:
        expected_default = 443 if parsed.scheme.lower() == "https" else 80
        if request_port != expected_default:
            return False
    source_path = match.group("path") or ""
    request_path = parsed.path or "/"
    if source_path in ("", "/"):
        return True
    if source_path.endswith("/"):
        return request_path.startswith(source_path)
    return request_path == source_path


_v9._source_matches_remote_v9 = _source_matches_remote_v10


def main(argv=None):
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if "--json" not in raw_arguments:
        return _v9.main(raw_arguments)
    captured_stderr = io.StringIO()
    with contextlib.redirect_stderr(captured_stderr):
        return _v9.main(raw_arguments)


try:
    import nuiwallfix as _public_package
    _public_package.scan_target = core.scan_target
except ImportError:
    pass
