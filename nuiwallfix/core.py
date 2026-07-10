import base64
import codecs
import datetime as _datetime
import fnmatch
import hashlib
import html
import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


MANIFEST_NAMES = ("fxmanifest.lua", "__resource.lua")
SCAN_EXTENSIONS = {".html", ".htm", ".css", ".js", ".mjs", ".cjs"}
SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".nui-wallfix",
    ".nui-wallfix-backups",
    "node_modules",
    "__pycache__",
}
STATIC_EXTENSIONS = {
    ".js": "script",
    ".mjs": "script",
    ".cjs": "script",
    ".css": "style",
    ".woff": "font",
    ".woff2": "font",
    ".ttf": "font",
    ".otf": "font",
    ".eot": "font",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
    ".svg": "image",
    ".ico": "image",
    ".avif": "image",
    ".mp3": "media",
    ".ogg": "media",
    ".wav": "media",
    ".mp4": "media",
    ".webm": "media",
}
REMOTE_SCHEMES = ("http://", "https://", "//")
NUI_CALLBACK_MARKERS = (
    "getparentresourcename",
    "nui://",
    "cfx-nui-",
    "https://${",
    "http://${",
)


class WallfixError(Exception):
    """Base error raised for an input or operation failure."""


class ResolveError(WallfixError):
    """A remote reference could not be resolved safely."""


class RestoreConflict(WallfixError):
    """A file changed after apply and cannot be restored blindly."""


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _utc_now():
    return _datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _posix(path):
    return str(path).replace("\\", "/")


def _is_within(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def _line_column(text, offset):
    line = text.count("\n", 0, offset) + 1
    last = text.rfind("\n", 0, offset)
    column = offset + 1 if last < 0 else offset - last
    return line, column


def _decode_js_string(value):
    def replace_escape(match):
        token = match.group(1)
        simple = {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
            "v": "\v",
            "0": "\0",
            "/": "/",
            "\\": "\\",
            "\"": "\"",
            "'": "'",
        }
        if token in simple:
            return simple[token]
        if token.startswith("x") and len(token) == 3:
            try:
                return chr(int(token[1:], 16))
            except ValueError:
                return "\\" + token
        if token.startswith("u") and len(token) == 5:
            try:
                return chr(int(token[1:], 16))
            except ValueError:
                return "\\" + token
        return token

    return re.sub(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", replace_escape, value)


def _normalise_url(raw_url, base_url=None):
    value = html.unescape(raw_url).strip()
    value = _decode_js_string(value)
    if value.startswith("//"):
        value = "https:" + value
    if base_url:
        value = urllib.parse.urljoin(base_url, value)
    return value


def _is_external(raw_url):
    value = html.unescape(raw_url).strip().lower()
    return value.startswith(REMOTE_SCHEMES)


def _is_callback_or_internal(url):
    lowered = url.lower()
    return any(marker in lowered for marker in NUI_CALLBACK_MARKERS)


def _classify_url(url, fallback="asset"):
    try:
        suffix = PurePosixPath(urllib.parse.urlsplit(url).path).suffix.lower()
    except ValueError:
        return fallback
    return STATIC_EXTENSIONS.get(suffix, fallback)


@dataclass
class Document:
    path: Path
    text: str
    encoding: str
    bom: bytes
    original: bytes

    @property
    def sha256(self):
        return _sha256(self.original)

    def encode(self, text):
        return self.bom + text.encode(self.encoding)


def _read_document(path):
    data = Path(path).read_bytes()
    if data.startswith(codecs.BOM_UTF8):
        return Document(Path(path), data[len(codecs.BOM_UTF8):].decode("utf-8"), "utf-8", codecs.BOM_UTF8, data)
    if data.startswith(codecs.BOM_UTF16_LE):
        return Document(Path(path), data[2:].decode("utf-16-le"), "utf-16-le", codecs.BOM_UTF16_LE, data)
    if data.startswith(codecs.BOM_UTF16_BE):
        return Document(Path(path), data[2:].decode("utf-16-be"), "utf-16-be", codecs.BOM_UTF16_BE, data)
    try:
        return Document(Path(path), data.decode("utf-8"), "utf-8", b"", data)
    except UnicodeDecodeError:
        try:
            return Document(Path(path), data.decode("gb18030"), "gb18030", b"", data)
        except UnicodeDecodeError as exc:
            raise WallfixError("unsupported text encoding: {} ({})".format(path, exc))


@dataclass
class ResourceInfo:
    root: Path
    manifest: Path
    ui_page: str
    ui_file: Path
    ui_root: Path
    file_patterns: list = field(default_factory=list)

    def to_dict(self, target):
        return {
            "root": _posix(self.root.relative_to(target)) if self.root != target else ".",
            "manifest": _posix(self.manifest.relative_to(target)),
            "ui_page": self.ui_page,
            "ui_root": _posix(self.ui_root.relative_to(self.root)) if self.ui_root != self.root else ".",
            "file_patterns": list(self.file_patterns),
        }


@dataclass
class Reference:
    resource_root: Path
    file_path: Path
    start: int
    end: int
    raw_url: str
    url: str
    kind: str
    context: str
    line: int
    column: int
    syntax: str
    quote: str = ""
    integrity: str = ""
    auto_allowed: bool = True
    reason: str = ""

    @property
    def reference_id(self):
        payload = "{}|{}|{}|{}|{}".format(
            self.resource_root,
            self.file_path,
            self.start,
            self.end,
            self.url,
        ).encode("utf-8", "surrogatepass")
        return hashlib.sha1(payload).hexdigest()[:16]

    def to_dict(self, target):
        return {
            "id": self.reference_id,
            "resource": _posix(self.resource_root.relative_to(target)) if self.resource_root != target else ".",
            "file": _posix(self.file_path.relative_to(target)),
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            "context": self.context,
            "url": self.url,
            "raw_url": self.raw_url,
            "auto_allowed": self.auto_allowed,
            "reason": self.reason,
            "has_integrity": bool(self.integrity),
        }


@dataclass
class ScanResult:
    target: Path
    resources: list
    references: list
    diagnostics: list
    documents: dict = field(repr=False)

    def to_dict(self):
        automatic = sum(1 for ref in self.references if ref.auto_allowed)
        skipped = len(self.references) - automatic
        return {
            "schema_version": 1,
            "command": "scan",
            "target": str(self.target),
            "summary": {
                "resources": len(self.resources),
                "references": len(self.references),
                "automatic": automatic,
                "report_only": skipped,
                "diagnostics": len(self.diagnostics),
            },
            "resources": [item.to_dict(self.target) for item in self.resources],
            "references": [item.to_dict(self.target) for item in self.references],
            "diagnostics": list(self.diagnostics),
        }


def _mask_lua_comments(text):
    chars = list(text)
    i = 0
    quote = None
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
            i += 1
            continue
        if text.startswith("--[[", i):
            end = text.find("]]", i + 4)
            end = len(text) if end < 0 else end + 2
            for pos in range(i, end):
                if chars[pos] not in "\r\n":
                    chars[pos] = " "
            i = end
            continue
        if text.startswith("--", i):
            end = text.find("\n", i + 2)
            end = len(text) if end < 0 else end
            for pos in range(i, end):
                if chars[pos] != "\r":
                    chars[pos] = " "
            i = end
            continue
        i += 1
    return "".join(chars)


def _find_matching_brace(text, opening):
    depth = 0
    quote = None
    i = opening
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _parse_manifest(path):
    document = _read_document(path)
    masked = _mask_lua_comments(document.text)
    ui_match = re.search(r"\bui_page\s*(?:\(\s*)?(['\"])(.*?)\1", masked, re.IGNORECASE | re.DOTALL)
    if not ui_match:
        return document, None, []
    ui_page = document.text[ui_match.start(2):ui_match.end(2)].strip()
    patterns = []
    block_pattern = re.compile(r"\bfiles\s*(?:\(\s*)?\{", re.IGNORECASE)
    for match in block_pattern.finditer(masked):
        opening = masked.find("{", match.start(), match.end())
        closing = _find_matching_brace(masked, opening)
        if closing < 0:
            continue
        block = document.text[opening + 1:closing]
        for item in re.finditer(r"(['\"])(.*?)\1", block, re.DOTALL):
            patterns.append(item.group(2).strip().replace("\\", "/"))
    return document, ui_page, patterns


def _discover_manifest_paths(target):
    target = Path(target).resolve()
    direct = [target / name for name in MANIFEST_NAMES if (target / name).is_file()]
    if direct:
        return [direct[0]]
    manifests = []
    for root, dirs, files in os.walk(str(target), followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in SKIP_DIRECTORIES and not name.lower().endswith(".backup")
            and not (Path(root) / name).is_symlink()
        )
        selected = None
        for name in MANIFEST_NAMES:
            if name in files:
                selected = Path(root) / name
                break
        if selected:
            manifests.append(selected)
            dirs[:] = []
    return sorted(manifests, key=lambda item: str(item).lower())


def _discover_resources(target, diagnostics, documents):
    resources = []
    for manifest in _discover_manifest_paths(target):
        try:
            document, ui_page, patterns = _parse_manifest(manifest)
            documents[str(manifest)] = document
        except (OSError, WallfixError) as exc:
            diagnostics.append({"level": "error", "file": str(manifest), "message": str(exc)})
            continue
        if not ui_page:
            continue
        root = manifest.parent.resolve()
        if _is_external(ui_page):
            diagnostics.append({
                "level": "warning",
                "resource": str(root),
                "file": str(manifest),
                "message": "remote ui_page is report-only: {}".format(ui_page),
            })
            continue
        ui_file = (root / ui_page.replace("/", os.sep)).resolve()
        if not _is_within(ui_file, root):
            diagnostics.append({
                "level": "error",
                "resource": str(root),
                "file": str(manifest),
                "message": "ui_page escapes the resource root: {}".format(ui_page),
            })
            continue
        if not ui_file.is_file():
            diagnostics.append({
                "level": "error",
                "resource": str(root),
                "file": str(manifest),
                "message": "ui_page does not exist: {}".format(ui_page),
            })
            continue
        resources.append(ResourceInfo(root, manifest.resolve(), ui_page, ui_file, ui_file.parent, patterns))
    return resources


def _make_reference(document, resource, start, end, raw_url, kind, context, syntax, quote="", integrity="", auto_allowed=True, reason=""):
    url = _normalise_url(raw_url)
    if not _is_external(url):
        return None
    if _is_callback_or_internal(url):
        auto_allowed = False
        reason = reason or "FiveM/NUI internal callback"
    line, column = _line_column(document.text, start)
    return Reference(
        resource.root,
        document.path,
        start,
        end,
        raw_url,
        url,
        kind,
        context,
        line,
        column,
        syntax,
        quote,
        integrity,
        auto_allowed,
        reason,
    )


@dataclass
class _HtmlAttribute:
    name: str
    value: str
    start: int
    end: int
    quote: str


_HTML_ATTRIBUTE = re.compile(
    r"(?P<name>[^\s=/>]+)(?:\s*=\s*(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<uq>[^\s\"'=<>`]+)))?",
    re.DOTALL,
)


def _html_attributes(tag_text, absolute_start, name_end):
    result = {}
    for match in _HTML_ATTRIBUTE.finditer(tag_text, name_end):
        name = match.group("name").lower()
        if match.group("dq") is not None:
            group, quote = "dq", '"'
        elif match.group("sq") is not None:
            group, quote = "sq", "'"
        elif match.group("uq") is not None:
            group, quote = "uq", ""
        else:
            continue
        item = _HtmlAttribute(
            name,
            match.group(group),
            absolute_start + match.start(group),
            absolute_start + match.end(group),
            quote,
        )
        result.setdefault(name, []).append(item)
    return result


def _find_html_tag_end(text, start):
    quote = None
    i = start
    while i < len(text):
        char = text[i]
        if quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == ">":
            return i + 1
        i += 1
    return len(text)


def _srcset_items(attribute):
    for match in re.finditer(r"(?:^|,)\s*([^\s,]+)", attribute.value):
        value = match.group(1)
        start = attribute.start + match.start(1)
        yield value, start, start + len(value)


def _find_css_urls(text):
    results = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = length if end < 0 else end + 2
            continue
        char = text[i]
        if char in ("'", '"'):
            quote = char
            i += 1
            while i < length:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if text[i:i + 7].lower() == "@import" and (i + 7 == length or not (text[i + 7].isalnum() or text[i + 7] in "_-$")):
            j = i + 7
            while j < length and text[j].isspace():
                j += 1
            if j < length and text[j] in ("'", '"'):
                quote = text[j]
                start = j + 1
                j = start
                while j < length:
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == quote:
                        results.append((start, j, text[start:j], "css-import", quote))
                        j += 1
                        break
                    j += 1
                i = j
                continue
        if text[i:i + 3].lower() == "url" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_-$")):
            j = i + 3
            while j < length and text[j].isspace():
                j += 1
            if j < length and text[j] == "(":
                j += 1
                while j < length and text[j].isspace():
                    j += 1
                quote = text[j] if j < length and text[j] in ("'", '"') else ""
                if quote:
                    start = j + 1
                    j = start
                    while j < length:
                        if text[j] == "\\":
                            j += 2
                            continue
                        if text[j] == quote:
                            end = j
                            break
                        j += 1
                    else:
                        i += 3
                        continue
                else:
                    start = j
                    while j < length and text[j] != ")":
                        j += 1
                    end = j
                    while end > start and text[end - 1].isspace():
                        end -= 1
                prefix = text[max(0, i - 24):i].lower()
                context = "css-import" if "@import" in prefix else "css-url"
                results.append((start, end, text[start:end], context, quote))
                i = max(j + 1, i + 3)
                continue
        i += 1
    unique = {}
    for item in results:
        unique[(item[0], item[1])] = item
    return [unique[key] for key in sorted(unique)]


@dataclass
class _JsToken:
    kind: str
    value: str
    start: int
    end: int
    quote: str = ""


def _lex_js(text):
    tokens = []
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char.isspace():
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = length if end < 0 else end + 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = length if end < 0 else end + 2
            continue
        if char in ("'", '"'):
            quote = char
            start = i + 1
            i = start
            while i < length:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
            tokens.append(_JsToken("string", _decode_js_string(text[start:i]), start, i, quote))
            i = min(i + 1, length)
            continue
        if char == "`":
            start = i + 1
            i = start
            dynamic = False
            while i < length:
                if text[i] == "\\":
                    i += 2
                    continue
                if text.startswith("${", i):
                    dynamic = True
                if text[i] == "`":
                    break
                i += 1
            kind = "template-dynamic" if dynamic else "string"
            tokens.append(_JsToken(kind, _decode_js_string(text[start:i]), start, i, "`"))
            i = min(i + 1, length)
            continue
        identifier = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", text[i:])
        if identifier:
            value = identifier.group(0)
            tokens.append(_JsToken("identifier", value, i, i + len(value)))
            i += len(value)
            continue
        tokens.append(_JsToken("punct", char, i, i + 1))
        i += 1
    return tokens


def _js_candidate_tokens(text):
    tokens = _lex_js(text)
    results = []

    def add(token, context, kind, auto=True, reason=""):
        if token.kind != "string":
            return
        results.append((token.start, token.end, token.value, context, kind, token.quote, auto, reason))

    for index, token in enumerate(tokens):
        if token.kind != "identifier":
            continue
        next_one = tokens[index + 1] if index + 1 < len(tokens) else None
        next_two = tokens[index + 2] if index + 2 < len(tokens) else None
        if token.value == "import":
            if next_one and next_one.value == "(" and next_two:
                add(next_two, "js-dynamic-import", "script")
            elif next_one and next_one.kind == "string":
                add(next_one, "js-import", "script")
            else:
                for cursor in range(index + 1, min(index + 24, len(tokens))):
                    if tokens[cursor].value in (";", "}"):
                        break
                    if tokens[cursor].value == "from" and cursor + 1 < len(tokens):
                        add(tokens[cursor + 1], "js-import", "script")
                        break
        elif token.value == "export":
            for cursor in range(index + 1, min(index + 24, len(tokens))):
                if tokens[cursor].value in (";", "}"):
                    break
                if tokens[cursor].value == "from" and cursor + 1 < len(tokens):
                    add(tokens[cursor + 1], "js-export", "script")
                    break
        elif token.value == "new" and next_one and next_one.value in ("Worker", "SharedWorker", "URL"):
            if next_two and next_two.value == "(" and index + 3 < len(tokens):
                candidate = tokens[index + 3]
                if next_one.value != "URL" or _classify_url(candidate.value, "") in ("script", "style", "font", "image", "media"):
                    add(candidate, "js-{}".format(next_one.value.lower()), _classify_url(candidate.value, "script"))
        elif token.value == "importScripts" and next_one and next_one.value == "(":
            cursor = index + 2
            while cursor < len(tokens) and tokens[cursor].value != ")":
                if tokens[cursor].kind == "string":
                    add(tokens[cursor], "js-import-scripts", "script")
                cursor += 1
        elif token.value in ("fetch", "WebSocket", "EventSource") and next_one and next_one.value == "(" and next_two:
            add(next_two, "js-network", "network", False, "business network request; report only")
    unique = {}
    for item in results:
        unique[(item[0], item[1])] = item
    return [unique[key] for key in sorted(unique)]


def _scan_css_document(document, resource, offset=0, text=None):
    source = document.text if text is None else text
    references = []
    for start, end, raw_url, context, quote in _find_css_urls(source):
        if not _is_external(raw_url):
            continue
        kind = "style" if context == "css-import" else _classify_url(raw_url, "asset")
        ref = _make_reference(document, resource, offset + start, offset + end, raw_url, kind, context, "css", quote)
        if ref:
            references.append(ref)
    return references


def _scan_js_document(document, resource, offset=0, text=None):
    source = document.text if text is None else text
    references = []
    for start, end, raw_url, context, kind, quote, auto, reason in _js_candidate_tokens(source):
        if not _is_external(raw_url):
            continue
        ref = _make_reference(document, resource, offset + start, offset + end, raw_url, kind, context, "js", quote, auto_allowed=auto, reason=reason)
        if ref:
            references.append(ref)
    return references


def _scan_html_document(document, resource, diagnostics):
    text = document.text
    references = []
    i = 0
    while i < len(text):
        opening = text.find("<", i)
        if opening < 0:
            break
        if text.startswith("<!--", opening):
            closing = text.find("-->", opening + 4)
            i = len(text) if closing < 0 else closing + 3
            continue
        tag_end = _find_html_tag_end(text, opening + 1)
        tag_text = text[opening:tag_end]
        name_match = re.match(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9:-]*)", tag_text)
        if not name_match:
            i = tag_end
            continue
        if name_match.group(1):
            i = tag_end
            continue
        tag = name_match.group(2).lower()
        attributes = _html_attributes(tag_text, opening, name_match.end())

        def first(name):
            values = attributes.get(name, [])
            return values[0] if values else None

        integrity = first("integrity").value if first("integrity") else ""

        def add_attribute(attribute, kind, context, auto=True, reason=""):
            if not attribute or not _is_external(attribute.value):
                return
            ref = _make_reference(
                document,
                resource,
                attribute.start,
                attribute.end,
                attribute.value,
                kind,
                context,
                "html",
                attribute.quote,
                integrity,
                auto,
                reason,
            )
            if ref:
                references.append(ref)

        if tag == "script":
            add_attribute(first("src"), "script", "html-script")
        elif tag == "link":
            rel = (first("rel").value.lower() if first("rel") else "")
            as_type = (first("as").value.lower() if first("as") else "")
            href = first("href")
            if "stylesheet" in rel:
                add_attribute(href, "style", "html-stylesheet")
            elif "modulepreload" in rel or as_type == "script":
                add_attribute(href, "script", "html-link")
            elif as_type == "style":
                add_attribute(href, "style", "html-link")
            elif as_type == "font":
                add_attribute(href, "font", "html-link")
            elif "icon" in rel or as_type == "image":
                add_attribute(href, "image", "html-link")
            elif href and _classify_url(href.value, "") in ("script", "style", "font", "image"):
                add_attribute(href, _classify_url(href.value), "html-link")
        elif tag in ("img", "source"):
            add_attribute(first("src"), "image", "html-asset")
            for srcset in attributes.get("srcset", []):
                for value, start, end in _srcset_items(srcset):
                    if _is_external(value):
                        ref = _make_reference(document, resource, start, end, value, "image", "html-srcset", "html", srcset.quote)
                        if ref:
                            references.append(ref)
        elif tag in ("video", "audio"):
            add_attribute(first("src"), "media", "html-media")
            add_attribute(first("poster"), "image", "html-poster")
        elif tag == "base":
            href = first("href")
            if href and _is_external(href.value):
                line, column = _line_column(text, href.start)
                diagnostics.append({
                    "level": "warning",
                    "file": str(document.path),
                    "line": line,
                    "column": column,
                    "message": "external <base> changes relative URL resolution and requires manual review",
                })
        elif tag == "iframe":
            add_attribute(first("src"), "remote-page", "html-iframe", False, "remote page; report only")

        for style_attr in attributes.get("style", []):
            references.extend(_scan_css_document(document, resource, style_attr.start, style_attr.value))

        if tag in ("script", "style"):
            close_match = re.search(r"</\s*{}\s*>".format(tag), text[tag_end:], re.IGNORECASE)
            if close_match:
                content_start = tag_end
                content_end = tag_end + close_match.start()
                content = text[content_start:content_end]
                if tag == "style":
                    references.extend(_scan_css_document(document, resource, content_start, content))
                elif not first("src"):
                    references.extend(_scan_js_document(document, resource, content_start, content))
                i = tag_end + close_match.end()
                continue
        i = tag_end
    return references


def _resource_scan_files(resource):
    paths = []
    for root, dirs, files in os.walk(str(resource.ui_root), followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in SKIP_DIRECTORIES and not name.lower().endswith(".backup")
            and not (Path(root) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(root) / name
            if path.suffix.lower() in SCAN_EXTENSIONS and not path.is_symlink():
                paths.append(path.resolve())
    return paths


def scan_target(target):
    target = Path(target).expanduser().resolve()
    if not target.is_dir():
        raise WallfixError("target is not a directory: {}".format(target))
    diagnostics = []
    documents = {}
    resources = _discover_resources(target, diagnostics, documents)
    references = []
    for resource in resources:
        for path in _resource_scan_files(resource):
            try:
                document = documents.get(str(path)) or _read_document(path)
                documents[str(path)] = document
                suffix = path.suffix.lower()
                if suffix in (".html", ".htm"):
                    references.extend(_scan_html_document(document, resource, diagnostics))
                elif suffix == ".css":
                    references.extend(_scan_css_document(document, resource))
                else:
                    references.extend(_scan_js_document(document, resource))
            except (OSError, WallfixError) as exc:
                diagnostics.append({"level": "error", "file": str(path), "message": str(exc)})
    unique = {}
    for ref in references:
        unique[(str(ref.file_path).lower(), ref.start, ref.end)] = ref
    references = sorted(unique.values(), key=lambda item: (str(item.file_path).lower(), item.start, item.end))
    return ScanResult(target, resources, references, diagnostics, documents)
