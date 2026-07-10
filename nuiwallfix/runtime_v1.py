"""Command runtime for nui-wallfix.

This module intentionally uses only the Python 3.7 standard library.
"""

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import mimetypes
import os
import posixpath
import re
import socket
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import __version__
from . import core


EXIT_OK = 0
EXIT_REVIEW = 10
EXIT_INPUT = 20
EXIT_WRITE = 40
EXIT_CONFLICT = 50


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    data: bytes
    content_type: str
    charset: str

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, validator):
        urllib.request.HTTPRedirectHandler.__init__(self)
        self.validator = validator

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.validator(newurl)
        return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(self, timeout=15.0, max_bytes=20 * 1024 * 1024, allow_private=False):
        self.timeout = float(timeout)
        self.max_bytes = int(max_bytes)
        self.allow_private = bool(allow_private)
        self._cache = {}
        self._errors = {}
        self._opener = urllib.request.build_opener(_SafeRedirectHandler(self._validate_url))

    def _validate_url(self, url):
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError as exc:
            raise core.ResolveError("invalid URL: {} ({})".format(url, exc))
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise core.ResolveError("only HTTP(S) assets are supported: {}".format(url))
        if parsed.username or parsed.password:
            raise core.ResolveError("URLs containing credentials are refused")
        if self.allow_private:
            return
        try:
            addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise core.ResolveError("DNS lookup failed for {}: {}".format(parsed.hostname, exc))
        for item in addresses:
            address = item[4][0].split("%", 1)[0]
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                raise core.ResolveError("private or non-public network address is blocked: {}".format(address))

    def fetch(self, url):
        parsed = urllib.parse.urlsplit(url)
        request_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if request_url in self._cache:
            return self._cache[request_url]
        if request_url in self._errors:
            raise core.ResolveError(self._errors[request_url])
        try:
            self._validate_url(request_url)
            request = urllib.request.Request(
                request_url,
                headers={
                    "User-Agent": "nui-wallfix/{0}".format(__version__),
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                },
            )
            with self._opener.open(request, timeout=self.timeout) as response:
                final_url = response.geturl()
                self._validate_url(final_url)
                length = response.headers.get("Content-Length")
                if length:
                    try:
                        if int(length) > self.max_bytes:
                            raise core.ResolveError("asset exceeds the {} byte limit".format(self.max_bytes))
                    except ValueError:
                        pass
                data = response.read(self.max_bytes + 1)
                if len(data) > self.max_bytes:
                    raise core.ResolveError("asset exceeds the {} byte limit".format(self.max_bytes))
                content_type = response.headers.get_content_type() or ""
                charset = response.headers.get_content_charset() or ""
            result = FetchResult(request_url, final_url, data, content_type.lower(), charset)
            self._cache[request_url] = result
            return result
        except core.ResolveError as exc:
            message = "{}: {}".format(request_url, exc)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            message = "{}: {}".format(request_url, exc)
        self._errors[request_url] = message
        raise core.ResolveError(message)


def _validate_content(result, kind):
    if not result.data:
        raise core.ResolveError("empty response from {}".format(result.requested_url))
    prefix = result.data[:512].lstrip(b"\xef\xbb\xbf\x00\t\r\n ").lower()
    if kind not in ("remote-page", "network") and (prefix.startswith(b"<!doctype html") or prefix.startswith(b"<html")):
        raise core.ResolveError("asset URL returned an HTML page: {}".format(result.requested_url))
    content_type = result.content_type
    if kind == "style" and content_type and content_type not in ("text/css", "text/plain", "application/octet-stream"):
        raise core.ResolveError("unexpected CSS content type {}".format(content_type))
    if kind == "script" and content_type:
        allowed = (
            "javascript" in content_type
            or "ecmascript" in content_type
            or content_type in ("text/plain", "application/octet-stream")
        )
        if not allowed:
            raise core.ResolveError("unexpected JavaScript content type {}".format(content_type))
    if kind in ("font", "image", "media", "asset") and content_type in ("text/html", "application/json"):
        raise core.ResolveError("unexpected asset content type {}".format(content_type))


def _sri_algorithms(integrity):
    algorithms = []
    for token in integrity.split():
        token = token.split("?", 1)[0]
        if "-" not in token:
            continue
        algorithm = token.split("-", 1)[0].lower()
        if algorithm in ("sha256", "sha384", "sha512") and algorithm not in algorithms:
            algorithms.append(algorithm)
    return algorithms


def _sri_matches(data, integrity):
    matched_supported = False
    for token in integrity.split():
        token = token.split("?", 1)[0]
        if "-" not in token:
            continue
        algorithm, expected = token.split("-", 1)
        algorithm = algorithm.lower()
        if algorithm not in ("sha256", "sha384", "sha512"):
            continue
        matched_supported = True
        actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
        if actual.rstrip("=") == expected.rstrip("="):
            return True
    return False if matched_supported else False


def _new_sri(data, previous=""):
    algorithms = _sri_algorithms(previous) or ["sha384"]
    return " ".join(
        "{}-{}".format(name, base64.b64encode(hashlib.new(name, data).digest()).decode("ascii"))
        for name in algorithms
    )


def _default_provider_path():
    return Path(__file__).resolve().parent.parent / "providers.json"


def _load_rules(path=None):
    selected = Path(path).expanduser().resolve() if path else _default_provider_path()
    try:
        payload = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise core.WallfixError("cannot read provider config {}: {}".format(selected, exc))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("rules"), list):
        raise core.WallfixError("unsupported provider config schema: {}".format(selected))
    rules = []
    for item in payload["rules"]:
        if not isinstance(item, dict) or item.get("type") not in ("prefix", "npm_file"):
            raise core.WallfixError("invalid provider rule in {}".format(selected))
        if not item.get("source") or not item.get("target"):
            raise core.WallfixError("provider rules require source and target")
        rules.append(dict(item))
    return rules


def _npm_file_candidate(url, rule):
    source = rule["source"]
    if not url.startswith(source):
        return None
    remainder = url[len(source):]
    parsed = urllib.parse.urlsplit("https://placeholder/" + remainder)
    path = parsed.path.lstrip("/")
    if path.startswith("@"):
        scope_end = path.find("/")
        version_at = path.find("@", scope_end + 1) if scope_end >= 0 else -1
    else:
        version_at = path.find("@")
    if version_at <= 0:
        return None
    slash = path.find("/", version_at + 1)
    if slash < 0:
        return None
    package = path[:version_at]
    version = path[version_at + 1:slash]
    asset_path = path[slash + 1:]
    if not package or not version or not asset_path or version.lower() in ("latest", "next", "beta"):
        return None
    target = rule["target"].rstrip("/")
    candidate_path = "{}/{}/files/{}".format(package, version, asset_path)
    return urllib.parse.urlunsplit((
        urllib.parse.urlsplit(target).scheme or "https",
        urllib.parse.urlsplit(target).netloc,
        urllib.parse.urlsplit(target).path.rstrip("/") + "/" + candidate_path,
        parsed.query,
        parsed.fragment,
    ))


def _provider_candidates(url, rules):
    normalised = core._normalise_url(url)
    candidates = []
    for rule in rules:
        candidate = None
        if rule["type"] == "prefix" and normalised.startswith(rule["source"]):
            candidate = rule["target"] + normalised[len(rule["source"]):]
        elif rule["type"] == "npm_file":
            candidate = _npm_file_candidate(normalised, rule)
        if candidate and candidate != normalised:
            candidates.append((rule.get("name") or rule["type"], candidate))
    return candidates


def _safe_segment(value):
    value = urllib.parse.unquote(value)
    value = re.sub(r"[<>:\"/\\|?*\x00-\x1f]", "_", value).strip(" .")
    if not value:
        value = "_"
    if value.upper().split(".", 1)[0] in {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }:
        value = "_" + value
    if len(value) > 80:
        suffix = hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()[:8]
        value = value[:68] + "__" + suffix
    return value


def _asset_relative_path(resource, url, kind):
    parsed = urllib.parse.urlsplit(url)
    host = _safe_segment(parsed.netloc or "remote")
    raw_segments = [part for part in parsed.path.split("/") if part not in ("", ".", "..")]
    segments = [_safe_segment(part) for part in raw_segments]
    if not segments or parsed.path.endswith("/"):
        segments.append("index")
    filename = segments[-1]
    suffix = PurePosixPath(filename).suffix
    if not suffix:
        extension = {
            "script": ".js",
            "style": ".css",
            "font": ".bin",
            "image": ".img",
            "media": ".bin",
        }.get(kind, ".bin")
        filename += extension
        suffix = extension
    stem = filename[:-len(suffix)] if suffix else filename
    url_hash = hashlib.sha1(url.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    segments[-1] = "{}__{}{}".format(stem, url_hash, suffix)
    ui_relative = resource.ui_root.relative_to(resource.root)
    relative = Path(ui_relative) / "_vendor" / host
    for segment in segments:
        relative /= segment
    if len(str(resource.root / relative)) > 235:
        relative = Path(ui_relative) / "_vendor" / host / (url_hash + suffix)
    return relative


def _decode_remote_text(result):
    data = result.data
    bom = b""
    if data.startswith(b"\xef\xbb\xbf"):
        bom, data = b"\xef\xbb\xbf", data[3:]
    encodings = []
    if result.charset:
        encodings.append(result.charset)
    encodings.extend(["utf-8", "gb18030", "latin-1"])
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding, bom
        except (LookupError, UnicodeDecodeError):
            continue
    raise core.ResolveError("cannot decode text asset {}".format(result.requested_url))


def _css_escape(value, quote=""):
    value = value.replace("\\", "\\\\")
    if quote:
        value = value.replace(quote, "\\" + quote)
    else:
        value = value.replace(" ", "\\ ").replace("(", "\\(").replace(")", "\\)")
    return value


def _js_escape(value, quote):
    value = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
    if quote:
        value = value.replace(quote, "\\" + quote)
    return value


def _apply_spans(text, replacements):
    previous = len(text) + 1
    for start, end, value in sorted(replacements, key=lambda item: (item[0], item[1]), reverse=True):
        if start < 0 or end < start or end > len(text) or end > previous:
            raise core.WallfixError("overlapping or invalid rewrite span")
        text = text[:start] + value + text[end:]
        previous = start
    return text


def _relative_asset_url(from_path, to_path, original_url=""):
    relative = posixpath.relpath(core._posix(to_path), posixpath.dirname(core._posix(from_path)))
    if not relative.startswith((".", "/")):
        relative = "./" + relative
    parsed = urllib.parse.urlsplit(original_url)
    if parsed.query:
        relative += "?" + parsed.query
    if parsed.fragment:
        relative += "#" + parsed.fragment
    return relative


@dataclass
class LocalAsset:
    origin_url: str
    fetch_url: str
    path: Path
    data: bytes
    kind: str
    verification: str
    dependencies: list = field(default_factory=list)
    complete: bool = False

    def to_dict(self, target):
        return {
            "origin_url": self.origin_url,
            "fetch_url": self.fetch_url,
            "file": core._posix(self.path.relative_to(target)),
            "kind": self.kind,
            "bytes": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "verification": self.verification,
        }


class Localizer:
    def __init__(self, resource, fetcher, rules, allow_unverified=False, max_depth=20):
        self.resource = resource
        self.fetcher = fetcher
        self.rules = rules
        self.allow_unverified = allow_unverified
        self.max_depth = max_depth
        self.assets = {}

    def _fetch_source(self, url, kind, integrity=""):
        errors = []
        try:
            result = self.fetcher.fetch(url)
            _validate_content(result, kind)
            if integrity and not _sri_matches(result.data, integrity):
                raise core.ResolveError("source content does not match SRI")
            return result, "source" + ("+sri" if integrity else "")
        except core.ResolveError as exc:
            errors.append(str(exc))
        for rule_name, candidate in _provider_candidates(url, self.rules):
            try:
                result = self.fetcher.fetch(candidate)
                _validate_content(result, kind)
                if integrity:
                    if not _sri_matches(result.data, integrity):
                        raise core.ResolveError("mirror content does not match SRI")
                    return result, "mirror:{}+sri".format(rule_name)
                if self.allow_unverified:
                    return result, "mirror:{}+explicit-trust".format(rule_name)
                raise core.ResolveError("original is unavailable and mirror has no SRI proof")
            except core.ResolveError as exc:
                errors.append(str(exc))
        raise core.ResolveError("; ".join(errors) if errors else "no downloadable source")

    def localize(self, url, kind, integrity="", depth=0):
        if depth > self.max_depth:
            raise core.ResolveError("dependency depth exceeds {}".format(self.max_depth))
        normalised = core._normalise_url(url)
        parsed = urllib.parse.urlsplit(normalised)
        key = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if key in self.assets:
            return self.assets[key]
        result, verification = self._fetch_source(key, kind, integrity)
        relative_path = _asset_relative_path(self.resource, key, kind)
        absolute_path = (self.resource.root / relative_path).resolve()
        if not core._is_within(absolute_path, self.resource.root):
            raise core.ResolveError("generated vendor path escapes the resource")
        asset = LocalAsset(key, result.requested_url, absolute_path, result.data, kind, verification)
        self.assets[key] = asset
        try:
            if kind == "style":
                self._rewrite_css(asset, result, depth)
            elif kind == "script":
                self._rewrite_js(asset, result, depth)
            asset.complete = True
            return asset
        except Exception:
            self.assets.pop(key, None)
            raise

    def _rewrite_css(self, asset, result, depth):
        text, encoding, bom = _decode_remote_text(result)
        replacements = []
        for start, end, raw_url, context, quote in core._find_css_urls(text):
            value = html.unescape(raw_url).strip()
            lowered = value.lower()
            if not value or lowered.startswith(("data:", "blob:", "#", "about:")):
                continue
            absolute = urllib.parse.urljoin(result.final_url, value)
            if urllib.parse.urlsplit(absolute).scheme not in ("http", "https"):
                continue
            child_kind = "style" if context == "css-import" else core._classify_url(absolute, "asset")
            child = self.localize(absolute, child_kind, depth=depth + 1)
            asset.dependencies.append(child)
            replacement = _relative_asset_url(asset.path, child.path, absolute)
            replacements.append((start, end, _css_escape(replacement, quote)))
        if replacements:
            text = _apply_spans(text, replacements)
            asset.data = bom + text.encode(encoding)

    def _rewrite_js(self, asset, result, depth):
        text, encoding, bom = _decode_remote_text(result)
        replacements = []
        for start, end, raw_url, context, kind, quote, auto, _reason in core._js_candidate_tokens(text):
            if not auto or context == "js-network":
                continue
            value = raw_url.strip()
            if not value or value.startswith(("data:", "blob:", "#")):
                continue
            if not value.startswith(("http://", "https://", "//", "./", "../", "/")):
                continue
            absolute = urllib.parse.urljoin(result.final_url, value)
            if urllib.parse.urlsplit(absolute).scheme not in ("http", "https"):
                continue
            child = self.localize(absolute, kind or "script", depth=depth + 1)
            asset.dependencies.append(child)
            replacement = _relative_asset_url(asset.path, child.path, absolute)
            replacements.append((start, end, _js_escape(replacement, quote)))
        if replacements:
            text = _apply_spans(text, replacements)
            asset.data = bom + text.encode(encoding)


@dataclass
class ResolvedReference:
    reference: core.Reference
    action: str
    replacement: str = ""
    verification: str = ""
    reason: str = ""
    asset: LocalAsset = None

    def to_dict(self, target):
        payload = self.reference.to_dict(target)
        payload.update({
            "action": self.action,
            "replacement": self.replacement,
            "verification": self.verification,
            "resolution_reason": self.reason,
        })
        if self.asset:
            payload["local_file"] = core._posix(self.asset.path.relative_to(target))
        return payload


def _resolve_mirror(reference, fetcher, rules, allow_unverified):
    candidates = _provider_candidates(reference.url, rules)
    if not candidates:
        raise core.ResolveError("no domestic CDN mapping")
    source = None
    source_error = ""
    try:
        source = fetcher.fetch(reference.url)
        _validate_content(source, reference.kind)
        if reference.integrity and not _sri_matches(source.data, reference.integrity):
            raise core.ResolveError("source content does not match SRI")
    except core.ResolveError as exc:
        source_error = str(exc)
        source = None
    errors = []
    for rule_name, candidate in candidates:
        try:
            mirrored = fetcher.fetch(candidate)
            _validate_content(mirrored, reference.kind)
            if reference.integrity:
                if not _sri_matches(mirrored.data, reference.integrity):
                    raise core.ResolveError("mirror content does not match SRI")
                return candidate, "{}+sri".format(rule_name)
            if source and source.data == mirrored.data:
                return candidate, "{}+sha256".format(rule_name)
            if allow_unverified:
                return candidate, "{}+explicit-trust".format(rule_name)
            if source:
                raise core.ResolveError("source and mirror bytes differ")
            raise core.ResolveError("source unavailable; mirror equivalence cannot be proven")
        except core.ResolveError as exc:
            errors.append("{}: {}".format(rule_name, exc))
    if source_error:
        errors.append("source: {}".format(source_error))
    raise core.ResolveError("; ".join(errors))


def _collect_assets(roots):
    result = {}

    def visit(asset):
        key = str(asset.path).lower()
        if key in result:
            return
        if not asset.complete:
            raise core.WallfixError("incomplete local asset: {}".format(asset.origin_url))
        result[key] = asset
        for child in asset.dependencies:
            visit(child)

    for root in roots:
        visit(root)
    return sorted(result.values(), key=lambda item: str(item.path).lower())


def _format_reference_replacement(reference, replacement):
    if reference.syntax == "html":
        return html.escape(replacement, quote=False)
    if reference.syntax == "js":
        return _js_escape(replacement, reference.quote)
    if reference.syntax == "css":
        return _css_escape(replacement, reference.quote)
    return replacement


def _locate_integrity_span(reference, document):
    if reference.syntax != "html" or not reference.integrity:
        return None
    opening = document.text.rfind("<", 0, reference.start)
    if opening < 0:
        return None
    tag_end = core._find_html_tag_end(document.text, opening + 1)
    if tag_end <= reference.end:
        return None
    tag_text = document.text[opening:tag_end]
    name_match = re.match(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9:-]*)", tag_text)
    if not name_match:
        return None
    attributes = core._html_attributes(tag_text, opening, name_match.end())
    values = attributes.get("integrity", [])
    if not values:
        return None
    return values[0].start, values[0].end


def _manifest_pattern_covers(pattern, relative_file):
    pattern = pattern.strip().replace("\\", "/").lstrip("./")
    relative_file = relative_file.replace("\\", "/").lstrip("./")
    if not pattern or "$" in pattern or "{" in pattern:
        return False
    return fnmatch_case(relative_file, pattern)


def fnmatch_case(path, pattern):
    import fnmatch
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if pattern.endswith("/**/*") and path.startswith(pattern[:-4].rstrip("*")):
        return True
    if pattern.endswith("/**") and path.startswith(pattern[:-3].rstrip("/")):
        return True
    return False


def _vendor_glob(resource):
    ui_relative = resource.ui_root.relative_to(resource.root)
    prefix = core._posix(ui_relative)
    return "_vendor/**/*" if prefix == "." else prefix.rstrip("/") + "/_vendor/**/*"


def _append_manifest_files(document, glob_pattern):
    newline = "\r\n" if "\r\n" in document.text else "\n"
    prefix = "" if not document.text or document.text.endswith(("\n", "\r")) else newline
    block = (
        prefix
        + newline
        + "-- nui-wallfix managed local assets"
        + newline
        + "files {"
        + newline
        + "    '" + glob_pattern.replace("'", "\\'") + "'"
        + newline
        + "}"
        + newline
    )
    return document.text + block


def _resolve_scan(scan, mode, fetcher, rules, allow_unverified):
    localizers = {}
    resolved = []
    root_assets = []
    for reference in scan.references:
        if not reference.auto_allowed:
            resolved.append(ResolvedReference(reference, "report-only", reason=reference.reason or "not safe to rewrite automatically"))
            continue
        try:
            if mode in ("cn-cdn", "auto"):
                try:
                    replacement, verification = _resolve_mirror(reference, fetcher, rules, allow_unverified)
                    resolved.append(ResolvedReference(reference, "remote", replacement, verification))
                    continue
                except core.ResolveError:
                    if mode == "cn-cdn":
                        raise
            resource_key = str(reference.resource_root).lower()
            if resource_key not in localizers:
                resource = next(item for item in scan.resources if item.root == reference.resource_root)
                localizers[resource_key] = Localizer(resource, fetcher, rules, allow_unverified)
            localizer = localizers[resource_key]
            asset = localizer.localize(reference.url, reference.kind, reference.integrity)
            replacement = _relative_asset_url(reference.file_path, asset.path, reference.url)
            resolved.append(ResolvedReference(reference, "local", replacement, asset.verification, asset=asset))
            root_assets.append(asset)
        except core.ResolveError as exc:
            resolved.append(ResolvedReference(reference, "unresolved", reason=str(exc)))
    return resolved, _collect_assets(root_assets)


def _build_output_files(scan, resolved, assets):
    replacements = {}
    integrity_values = {}
    for item in resolved:
        if item.action not in ("remote", "local"):
            continue
        reference = item.reference
        replacements.setdefault(str(reference.file_path), []).append((
            reference.start,
            reference.end,
            _format_reference_replacement(reference, item.replacement),
        ))
        if item.action == "local" and reference.integrity and not _sri_matches(item.asset.data, reference.integrity):
            document = scan.documents[str(reference.file_path)]
            span = _locate_integrity_span(reference, document)
            if not span:
                raise core.WallfixError("cannot safely update SRI in {}:{}".format(reference.file_path, reference.line))
            new_value = _new_sri(item.asset.data, reference.integrity)
            existing = integrity_values.get((str(reference.file_path), span))
            if existing and existing != new_value:
                raise core.WallfixError("conflicting SRI updates in {}".format(reference.file_path))
            integrity_values[(str(reference.file_path), span)] = new_value
    for (file_name, span), value in integrity_values.items():
        replacements.setdefault(file_name, []).append((span[0], span[1], value))

    outputs = {}
    expected = {}
    for file_name, spans in replacements.items():
        document = scan.documents[file_name]
        outputs[Path(file_name)] = document.encode(_apply_spans(document.text, spans))
        expected[Path(file_name)] = document.original

    for asset in assets:
        outputs[asset.path] = asset.data

    for resource in scan.resources:
        resource_assets = [item for item in assets if core._is_within(item.path, resource.root)]
        if not resource_assets:
            continue
        missing = []
        for asset in resource_assets:
            relative = core._posix(asset.path.relative_to(resource.root))
            if not any(_manifest_pattern_covers(pattern, relative) for pattern in resource.file_patterns):
                missing.append(relative)
        if missing:
            manifest_document = scan.documents[str(resource.manifest)]
            glob_pattern = _vendor_glob(resource)
            if not any(_manifest_pattern_covers(pattern, missing[0]) for pattern in resource.file_patterns):
                outputs[resource.manifest] = manifest_document.encode(_append_manifest_files(manifest_document, glob_pattern))
                expected[resource.manifest] = manifest_document.original
    return outputs, expected


def _default_state_dir(target):
    return target.parent / ".nui-wallfix-backups"


def _atomic_write(path, data, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".nui-wallfix-", dir=str(path.parent))
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, str(path))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _write_json(path, payload):
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(path, data)


class _TargetLock:
    def __init__(self, state_dir, target):
        digest = hashlib.sha1(str(target).lower().encode("utf-8")).hexdigest()[:16]
        self.path = state_dir / ("target-" + digest + ".lock")
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(self.handle, str(os.getpid()).encode("ascii"))
        except FileExistsError:
            raise core.WallfixError("another apply/restore is active: {}".format(self.path))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.handle is not None:
            os.close(self.handle)
        try:
            self.path.unlink()
        except OSError:
            pass


def _assert_safe_output(path, target):
    path = Path(path)
    if not core._is_within(path, target):
        raise core.WallfixError("output escapes target: {}".format(path))
    cursor = path.parent
    while core._is_within(cursor, target):
        if cursor.exists() and cursor.is_symlink():
            raise core.WallfixError("refusing to write through symlink: {}".format(cursor))
        if cursor == target:
            break
        cursor = cursor.parent
    if path.exists() and path.is_symlink():
        raise core.WallfixError("refusing to overwrite symlink: {}".format(path))


def _apply_outputs(target, state_dir, mode, outputs, expected, result_payload):
    state_dir = Path(state_dir).expanduser().resolve()
    if core._is_within(state_dir, target):
        raise core.WallfixError("state directory must be outside the target resource tree")
    run_id = _datetime_run_id()
    run_dir = state_dir / "runs" / run_id
    backup_root = run_dir / "files"
    records = []
    changed = {}
    with _TargetLock(state_dir, target):
        for path, data in sorted(outputs.items(), key=lambda item: str(item[0]).lower()):
            path = Path(path).resolve()
            _assert_safe_output(path, target)
            before = path.read_bytes() if path.exists() else None
            if path in expected and before != expected[path]:
                raise core.WallfixError("file changed after scan; refusing to overwrite: {}".format(path))
            if before == data:
                continue
            relative = path.relative_to(target)
            record = {
                "path": core._posix(relative),
                "existed_before": before is not None,
                "before_sha256": hashlib.sha256(before).hexdigest() if before is not None else "",
                "after_sha256": hashlib.sha256(data).hexdigest(),
                "backup": core._posix(Path("files") / relative) if before is not None else "",
            }
            if before is not None:
                backup_path = backup_root / relative
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                backup_path.write_bytes(before)
            records.append(record)
            changed[path] = (before, data)

        run_payload = {
            "schema_version": 1,
            "run_id": run_id,
            "target": str(target),
            "mode": mode,
            "status": "preparing",
            "created_at": core._utc_now(),
            "files": records,
            "result_summary": result_payload.get("summary", {}),
        }
        run_dir.mkdir(parents=True, exist_ok=False)
        _write_json(run_dir / "run.json", run_payload)
        written = []
        try:
            for path, (before, after) in changed.items():
                mode_bits = path.stat().st_mode if before is not None else None
                _atomic_write(path, after, mode_bits)
                written.append(path)
        except Exception:
            for path in reversed(written):
                before = changed[path][0]
                try:
                    if before is None:
                        path.unlink()
                    else:
                        _atomic_write(path, before)
                except OSError:
                    pass
            run_payload["status"] = "failed-and-rolled-back"
            run_payload["finished_at"] = core._utc_now()
            _write_json(run_dir / "run.json", run_payload)
            raise
        run_payload["status"] = "applied"
        run_payload["finished_at"] = core._utc_now()
        _write_json(run_dir / "run.json", run_payload)
    return run_id, records


def _datetime_run_id():
    import datetime
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid_hex(6)


def uuid_hex(length):
    import uuid
    return uuid.uuid4().hex[:length]


def _restore(target, run_id, state_dir=None, force=False):
    if not re.match(r"^[A-Za-z0-9._-]+$", run_id):
        raise core.WallfixError("invalid run id")
    state = Path(state_dir).expanduser().resolve() if state_dir else _default_state_dir(target).resolve()
    run_dir = state / "runs" / run_id
    record_path = run_dir / "run.json"
    try:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise core.WallfixError("cannot read run {}: {}".format(run_id, exc))
    if Path(payload.get("target", "")).resolve() != target:
        raise core.WallfixError("run target does not match: {}".format(run_id))
    if payload.get("status") == "restored":
        return {
            "schema_version": 1,
            "command": "restore",
            "status": "already-restored",
            "target": str(target),
            "run_id": run_id,
            "summary": {"files": 0},
        }
    if payload.get("status") != "applied":
        raise core.WallfixError("run is not restorable (status: {})".format(payload.get("status")))
    records = payload.get("files", [])
    with _TargetLock(state, target):
        conflicts = []
        current = {}
        for item in records:
            path = (target / item["path"]).resolve()
            _assert_safe_output(path, target)
            data = path.read_bytes() if path.exists() else None
            current[path] = data
            actual = hashlib.sha256(data).hexdigest() if data is not None else ""
            if actual != item.get("after_sha256", ""):
                conflicts.append(item["path"])
        if conflicts and not force:
            raise core.RestoreConflict("files changed after apply: {}".format(", ".join(conflicts)))
        restored = []
        try:
            for item in records:
                path = (target / item["path"]).resolve()
                if item.get("existed_before"):
                    backup = run_dir / item["backup"]
                    data = backup.read_bytes()
                    if hashlib.sha256(data).hexdigest() != item.get("before_sha256"):
                        raise core.WallfixError("backup hash mismatch: {}".format(backup))
                    _atomic_write(path, data)
                elif path.exists():
                    path.unlink()
                restored.append(path)
        except Exception:
            for path in reversed(restored):
                data = current[path]
                try:
                    if data is None:
                        if path.exists():
                            path.unlink()
                    else:
                        _atomic_write(path, data)
                except OSError:
                    pass
            raise
        payload["status"] = "restored"
        payload["restored_at"] = core._utc_now()
        payload["restore_forced"] = bool(force)
        _write_json(record_path, payload)
    return {
        "schema_version": 1,
        "command": "restore",
        "status": "restored",
        "target": str(target),
        "run_id": run_id,
        "summary": {"files": len(records), "forced_conflicts": len(conflicts)},
    }


def api_scan(target):
    return core.scan_target(target).to_dict()


def api_apply(
    target,
    mode="auto",
    write=False,
    providers=None,
    state_dir=None,
    timeout=15.0,
    max_bytes=20 * 1024 * 1024,
    allow_unverified_mirror=False,
    allow_private_network=False,
):
    if mode not in ("auto", "local", "cn-cdn"):
        raise core.WallfixError("invalid mode: {}".format(mode))
    scan = core.scan_target(target)
    rules = _load_rules(providers)
    fetcher = Fetcher(timeout, max_bytes, allow_private_network)
    resolved, assets = _resolve_scan(scan, mode, fetcher, rules, allow_unverified_mirror)
    summary = {
        "resources": len(scan.resources),
        "references": len(resolved),
        "remote": sum(1 for item in resolved if item.action == "remote"),
        "local": sum(1 for item in resolved if item.action == "local"),
        "report_only": sum(1 for item in resolved if item.action == "report-only"),
        "unresolved": sum(1 for item in resolved if item.action == "unresolved"),
        "vendor_files": len(assets),
        "written_files": 0,
    }
    result = {
        "schema_version": 1,
        "command": "apply",
        "status": "preview" if not write else "resolved",
        "target": str(scan.target),
        "mode": mode,
        "write_requested": bool(write),
        "summary": summary,
        "references": [item.to_dict(scan.target) for item in resolved],
        "assets": [item.to_dict(scan.target) for item in assets],
        "diagnostics": list(scan.diagnostics),
    }
    outputs, expected = _build_output_files(scan, resolved, assets)
    result["summary"]["planned_files"] = len(outputs)
    if write:
        selected_state = Path(state_dir).expanduser().resolve() if state_dir else _default_state_dir(scan.target).resolve()
        run_id, records = _apply_outputs(scan.target, selected_state, mode, outputs, expected, result)
        result["status"] = "applied"
        result["run_id"] = run_id
        result["state_dir"] = str(selected_state)
        result["summary"]["written_files"] = len(records)
    return result


def api_restore(target, run_id, state_dir=None, force=False):
    target = Path(target).expanduser().resolve()
    if not target.is_dir():
        raise core.WallfixError("target is not a directory: {}".format(target))
    return _restore(target, run_id, state_dir, force)


def _add_output_options(parser):
    parser.add_argument("--json", action="store_true", help="print a stable JSON result to stdout")
    parser.add_argument("--json-output", help="also write the JSON result to this file")


def _parser():
    parser = argparse.ArgumentParser(
        prog="nui-wallfix",
        description="Scan and safely rewrite external assets used by FiveM NUI resources.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    scan = subparsers.add_parser("scan", help="scan only; never writes files or uses the network")
    scan.add_argument("target", help="a resource directory or a directory containing resources")
    _add_output_options(scan)

    apply_parser = subparsers.add_parser("apply", help="resolve references; writes only with --write")
    apply_parser.add_argument("target")
    apply_parser.add_argument("--mode", choices=("auto", "local", "cn-cdn"), default="auto")
    apply_parser.add_argument("--write", action="store_true", help="perform the planned changes")
    apply_parser.add_argument("--providers", help="custom provider JSON file")
    apply_parser.add_argument("--state-dir", help="backup directory outside the target tree")
    apply_parser.add_argument("--timeout", type=float, default=15.0, help="network timeout in seconds")
    apply_parser.add_argument("--max-bytes", type=int, default=20 * 1024 * 1024, help="maximum bytes per asset")
    apply_parser.add_argument("--allow-unverified-mirror", action="store_true", help="trust an exact provider mapping when byte equivalence cannot be proven")
    apply_parser.add_argument("--allow-private-network", action="store_true", help="allow fetching loopback/private-network URLs")
    _add_output_options(apply_parser)

    restore = subparsers.add_parser("restore", help="restore an applied run")
    restore.add_argument("target")
    restore.add_argument("--run-id", required=True)
    restore.add_argument("--state-dir")
    restore.add_argument("--force", action="store_true", help="overwrite files changed after apply")
    _add_output_options(restore)
    return parser


def _write_result_file(path, payload):
    selected = Path(path).expanduser().resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _human_scan(payload):
    summary = payload["summary"]
    print("Resources: {resources}  External references: {references}  Report-only: {report_only}".format(**summary))
    for item in payload["references"]:
        marker = " [report-only]" if not item["auto_allowed"] else ""
        print("{file}:{line}:{column}  {kind:<8} {url}{marker}".format(marker=marker, **item))
    for item in payload["diagnostics"]:
        print("{level}: {message}".format(**item), file=sys.stderr)


def _human_apply(payload):
    summary = payload["summary"]
    print(
        "Status: {status}  Mode: {mode}  Remote: {remote}  Local: {local}  "
        "Unresolved: {unresolved}  Report-only: {report_only}".format(
            status=payload["status"], mode=payload["mode"], **summary
        )
    )
    for item in payload["references"]:
        detail = item["replacement"] if item["replacement"] else item["resolution_reason"]
        print("{file}:{line}  {action:<11} {url} -> {detail}".format(detail=detail, **item))
    if payload.get("run_id"):
        print("Run ID: {}".format(payload["run_id"]))
        print("Backup: {}".format(payload["state_dir"]))


def _human_restore(payload):
    print("Status: {status}  Run ID: {run_id}  Files: {summary[files]}".format(**payload))


def main(argv=None):
    parser = _parser()
    arguments = parser.parse_args(argv)
    use_json = bool(arguments.json)
    try:
        if arguments.command == "scan":
            payload = api_scan(arguments.target)
        elif arguments.command == "apply":
            payload = api_apply(
                arguments.target,
                mode=arguments.mode,
                write=arguments.write,
                providers=arguments.providers,
                state_dir=arguments.state_dir,
                timeout=arguments.timeout,
                max_bytes=arguments.max_bytes,
                allow_unverified_mirror=arguments.allow_unverified_mirror,
                allow_private_network=arguments.allow_private_network,
            )
        else:
            payload = api_restore(arguments.target, arguments.run_id, arguments.state_dir, arguments.force)
        if arguments.json_output:
            _write_result_file(arguments.json_output, payload)
        if use_json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        elif arguments.command == "scan":
            _human_scan(payload)
        elif arguments.command == "apply":
            _human_apply(payload)
        else:
            _human_restore(payload)
        if arguments.command == "apply":
            summary = payload["summary"]
            if summary["unresolved"] or summary["report_only"]:
                return EXIT_REVIEW
        return EXIT_OK
    except core.RestoreConflict as exc:
        payload = {"schema_version": 1, "command": arguments.command, "status": "conflict", "error": str(exc)}
        if use_json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print("error: {}".format(exc), file=sys.stderr)
        return EXIT_CONFLICT
    except core.WallfixError as exc:
        payload = {"schema_version": 1, "command": arguments.command, "status": "error", "error": str(exc)}
        if use_json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print("error: {}".format(exc), file=sys.stderr)
        return EXIT_INPUT
    except OSError as exc:
        payload = {"schema_version": 1, "command": arguments.command, "status": "write-error", "error": str(exc)}
        if use_json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print("error: {}".format(exc), file=sys.stderr)
        return EXIT_WRITE
