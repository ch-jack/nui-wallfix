"""Runtime v6: hardened networking, transactions, scope, and CLI errors."""

import ctypes
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import urllib.parse
from pathlib import Path

from . import core
from . import runtime_v1 as _v1
from . import runtime_v5 as _v5
from .runtime_v5 import *  # noqa: F401,F403


def _scan_manifest_scope(target):
    result = _v5._scan_target_base(target)
    for resource in result.resources:
        for root, dirs, files in os.walk(str(resource.root), followlinks=False):
            dirs[:] = sorted(
                name for name in dirs
                if name not in core.SKIP_DIRECTORIES
                and not name.lower().endswith(".backup")
                and not (Path(root) / name).is_symlink()
            )
            for name in sorted(files):
                path = (Path(root) / name).resolve()
                if path.suffix.lower() not in core.SCAN_EXTENSIONS or path.is_symlink():
                    continue
                if core._is_within(path, resource.ui_root):
                    continue
                relative = core._posix(path.relative_to(resource.root))
                if not any(_v1._manifest_pattern_covers(pattern, relative) for pattern in resource.file_patterns):
                    continue
                try:
                    document = result.documents.get(str(path)) or core._read_document(path)
                    result.documents[str(path)] = document
                    if path.suffix.lower() in (".html", ".htm"):
                        result.references.extend(core._scan_html_document(document, resource, result.diagnostics))
                    elif path.suffix.lower() == ".css":
                        result.references.extend(core._scan_css_document(document, resource))
                    else:
                        result.references.extend(core._scan_js_document(document, resource))
                except (OSError, core.WallfixError) as exc:
                    result.diagnostics.append({"level": "error", "file": str(path), "message": str(exc)})

    resources = {str(item.root).lower(): item for item in result.resources}
    kept = []
    skipped = {}
    for reference in result.references:
        resource = resources.get(str(reference.resource_root).lower())
        if not resource:
            kept.append(reference)
            continue
        relative = core._posix(reference.file_path.relative_to(resource.root))
        covered = reference.file_path == resource.ui_file
        if not covered and not resource.file_patterns:
            covered = core._is_within(reference.file_path, resource.ui_root)
        if not covered:
            covered = any(_v1._manifest_pattern_covers(pattern, relative) for pattern in resource.file_patterns)
        if covered:
            kept.append(reference)
        else:
            skipped[str(resource.root)] = skipped.get(str(resource.root), 0) + 1
    unique = {}
    for reference in kept:
        unique[(str(reference.file_path).lower(), reference.start, reference.end)] = reference
    result.references = sorted(unique.values(), key=lambda item: (str(item.file_path).lower(), item.start, item.end))
    for resource_name, count in sorted(skipped.items()):
        result.diagnostics.append({
            "level": "info",
            "resource": resource_name,
            "message": "skipped {} external reference(s) in files not covered by manifest files".format(count),
        })
    return result


core.scan_target = _scan_manifest_scope


def _has_html_base(document):
    masked = re.sub(r"<!--.*?-->", "", document.text, flags=re.DOTALL)
    return bool(re.search(r"<\s*base\b[^>]*\bhref\s*=", masked, re.IGNORECASE | re.DOTALL))


_resolve_scan_base = _v1._resolve_scan


def _resolve_scan_base_safe(scan, mode, fetcher, rules, allow_unverified):
    resolved, _assets = _resolve_scan_base(scan, mode, fetcher, rules, allow_unverified)
    base_files = {}
    for item in resolved:
        if item.action != "local" or item.reference.file_path.suffix.lower() not in (".html", ".htm"):
            continue
        file_name = str(item.reference.file_path)
        if file_name not in base_files:
            base_files[file_name] = _has_html_base(scan.documents[file_name])
        if base_files[file_name]:
            item.action = "unresolved"
            item.replacement = ""
            item.verification = ""
            item.reason = "HTML <base href> would change the generated local asset URL; manual review required"
            item.asset = None
    roots = [item.asset for item in resolved if item.action == "local" and item.asset is not None]
    return resolved, _v1._collect_assets(roots)


_v1._resolve_scan = _resolve_scan_base_safe


class PinnedFetcher:
    """HTTP client that connects to the same validated IP address it resolved."""

    def __init__(self, timeout=15.0, max_bytes=20 * 1024 * 1024, allow_private=False):
        self.timeout = float(timeout)
        self.max_bytes = int(max_bytes)
        self.allow_private = bool(allow_private)
        self._cache = {}
        self._errors = {}

    def _parse(self, url):
        if any(char in url for char in ("\r", "\n", "\x00")):
            raise core.ResolveError("control characters are not allowed in URLs")
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise core.ResolveError("invalid URL {}: {}".format(url, exc))
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise core.ResolveError("only HTTP(S) assets are supported: {}".format(url))
        if parsed.username or parsed.password:
            raise core.ResolveError("URLs containing credentials are refused")
        return parsed, port

    def _addresses(self, host, port):
        try:
            values = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise core.ResolveError("DNS lookup failed for {}: {}".format(host, exc))
        addresses = []
        seen = set()
        for family, socktype, protocol, _canonname, sockaddr in values:
            key = (family, socktype, protocol, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            address = sockaddr[0].split("%", 1)[0]
            try:
                ip = _v1.ipaddress.ip_address(address)
            except ValueError:
                continue
            if not self.allow_private and (
                ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified
            ):
                raise core.ResolveError("private or non-public network address is blocked: {}".format(address))
            addresses.append((family, socktype, protocol, sockaddr))
        if not addresses:
            raise core.ResolveError("DNS lookup returned no usable address for {}".format(host))
        return addresses

    def _connect(self, addresses):
        errors = []
        for family, socktype, protocol, sockaddr in addresses:
            stream = socket.socket(family, socktype, protocol)
            stream.settimeout(self.timeout)
            try:
                stream.connect(sockaddr)
                return stream
            except OSError as exc:
                errors.append(str(exc))
                stream.close()
        raise core.ResolveError("connection failed: {}".format("; ".join(errors)))

    def _request_once(self, url):
        parsed, port = self._parse(url)
        host = parsed.hostname.encode("idna").decode("ascii")
        addresses = self._addresses(host, port)
        stream = self._connect(addresses)
        try:
            if parsed.scheme == "https":
                context = ssl.create_default_context()
                stream = context.wrap_socket(stream, server_hostname=host)
            connection = http.client.HTTPConnection(host, port, timeout=self.timeout)
            connection.sock = stream
            path = parsed.path or "/"
            path = urllib.parse.quote(path, safe="/%:@!$&'()*+,;=-._~")
            if parsed.query:
                path += "?" + urllib.parse.quote(parsed.query, safe="=&;%:@!$'()*+,/?-._~")
            default_port = 443 if parsed.scheme == "https" else 80
            display_host = "[{}]".format(host) if ":" in host else host
            host_header = display_host if port == default_port else "{}:{}".format(display_host, port)
            connection.request("GET", path, headers={
                "Host": host_header,
                "User-Agent": "nui-wallfix/{}".format(_v1.__version__),
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = connection.getresponse()
            return connection, response
        except BaseException:
            try:
                stream.close()
            except OSError:
                pass
            raise

    def fetch(self, url):
        parsed, _port = self._parse(url)
        current = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if current in self._cache:
            return self._cache[current]
        if current in self._errors:
            raise core.ResolveError(self._errors[current])
        original = current
        try:
            for _redirect in range(9):
                connection, response = self._request_once(current)
                try:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.getheader("Location")
                        if not location:
                            raise core.ResolveError("redirect has no Location header")
                        next_url = urllib.parse.urljoin(current, location)
                        old_scheme = urllib.parse.urlsplit(current).scheme
                        new_scheme = urllib.parse.urlsplit(next_url).scheme
                        if old_scheme == "https" and new_scheme != "https":
                            raise core.ResolveError("HTTPS-to-HTTP redirect is refused")
                        current = next_url
                        continue
                    if response.status < 200 or response.status >= 300:
                        raise core.ResolveError("HTTP {} {}".format(response.status, response.reason))
                    length = response.getheader("Content-Length")
                    if length:
                        try:
                            if int(length) > self.max_bytes:
                                raise core.ResolveError("asset exceeds the {} byte limit".format(self.max_bytes))
                        except ValueError:
                            pass
                    encoding = (response.getheader("Content-Encoding") or "identity").lower()
                    if encoding not in ("", "identity"):
                        raise core.ResolveError("unexpected content encoding {}".format(encoding))
                    data = response.read(self.max_bytes + 1)
                    if len(data) > self.max_bytes:
                        raise core.ResolveError("asset exceeds the {} byte limit".format(self.max_bytes))
                    content_type = response.headers.get_content_type() or ""
                    charset = response.headers.get_content_charset() or ""
                    result = _v1.FetchResult(original, current, data, content_type.lower(), charset)
                    result.headers = {key.lower(): value for key, value in response.getheaders()}
                    self._cache[original] = result
                    self._cache[current] = result
                    return result
                finally:
                    connection.close()
            raise core.ResolveError("too many redirects")
        except core.ResolveError as exc:
            message = "{}: {}".format(original, exc)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            message = "{}: {}".format(original, exc)
        self._errors[original] = message
        raise core.ResolveError(message)


_v1.Fetcher = PinnedFetcher

_resolve_mirror_cors_base = _v1._resolve_mirror


def _resolve_mirror_with_cors(reference, fetcher, rules, allow_unverified):
    replacement, verification = _resolve_mirror_cors_base(reference, fetcher, rules, allow_unverified)
    if verification == "already-provider-target":
        return replacement, verification
    cors_required = reference.integrity or reference.context in {
        "js-import", "js-export", "js-dynamic-import", "js-worker", "js-sharedworker", "html-module-script",
    }
    if cors_required:
        result = fetcher.fetch(replacement)
        allowed_origin = getattr(result, "headers", {}).get("access-control-allow-origin", "")
        if allowed_origin.strip() != "*":
            raise core.ResolveError("domestic CDN lacks Access-Control-Allow-Origin: * for a CORS-required asset")
    return replacement, verification


_v1._resolve_mirror = _resolve_mirror_with_cors


def _atomic_write_safe(path, data, mode=None):
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
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


_v1._atomic_write = _atomic_write_safe


def _pid_is_running(pid):
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return ctypes.windll.kernel32.GetLastError() == 5
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class TargetLockV6:
    def __init__(self, state_dir, target):
        digest = hashlib.sha1(str(target).lower().encode("utf-8")).hexdigest()[:16]
        self.path = state_dir / ("target-" + digest + ".lock")
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _attempt in range(3):
            try:
                self.handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.handle, str(os.getpid()).encode("ascii"))
                return self
            except FileExistsError:
                try:
                    owner = int(self.path.read_text(encoding="ascii").strip())
                except (OSError, ValueError):
                    raise core.WallfixError("invalid or unreadable operation lock: {}".format(self.path))
                if _pid_is_running(owner):
                    raise core.WallfixError("another apply/restore is active (pid {}): {}".format(owner, self.path))
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    continue
        raise core.WallfixError("could not acquire operation lock: {}".format(self.path))

    def __exit__(self, exc_type, exc_value, traceback):
        if self.handle is not None:
            os.close(self.handle)
        try:
            self.path.unlink()
        except OSError:
            pass


_v1._TargetLock = TargetLockV6


def _apply_outputs_v6(target, state_dir, mode, outputs, expected, result_payload):
    state_dir = Path(state_dir).expanduser().resolve()
    if core._is_within(state_dir, target):
        raise core.WallfixError("state directory must be outside the target resource tree")
    run_id = _v1._datetime_run_id()
    run_dir = state_dir / "runs" / run_id
    records = []
    changed = {}
    with TargetLockV6(state_dir, target):
        for path, data in sorted(outputs.items(), key=lambda item: str(item[0]).lower()):
            path = Path(path).resolve()
            _v1._assert_safe_output(path, target)
            before = path.read_bytes() if path.exists() else None
            if path in expected and before != expected[path]:
                raise core.WallfixError("file changed after scan; refusing to overwrite: {}".format(path))
            if before == data:
                continue
            relative = path.relative_to(target)
            records.append({
                "path": core._posix(relative),
                "existed_before": before is not None,
                "before_sha256": hashlib.sha256(before).hexdigest() if before is not None else "",
                "after_sha256": hashlib.sha256(data).hexdigest(),
                "backup": core._posix(Path("files") / relative) if before is not None else "",
            })
            changed[path] = (before, data)

        run_dir.mkdir(parents=True, exist_ok=False)
        for item in records:
            if item["existed_before"]:
                backup = run_dir / item["backup"]
                backup.parent.mkdir(parents=True, exist_ok=True)
                backup.write_bytes(changed[(target / item["path"]).resolve()][0])
        journal = {
            "schema_version": 1,
            "run_id": run_id,
            "target": str(target),
            "mode": mode,
            "status": "preparing",
            "created_at": core._utc_now(),
            "files": records,
            "result_summary": result_payload.get("summary", {}),
        }
        _v1._write_json(run_dir / "run.json", journal)
        written = []
        try:
            for path, (before, after) in changed.items():
                mode_bits = path.stat().st_mode if before is not None else None
                _atomic_write_safe(path, after, mode_bits)
                written.append(path)
            journal["status"] = "applied"
            journal["finished_at"] = core._utc_now()
            _v1._write_json(run_dir / "run.json", journal)
        except BaseException:
            rollback_errors = []
            for path in reversed(written):
                before = changed[path][0]
                try:
                    if before is None:
                        path.unlink()
                    else:
                        _atomic_write_safe(path, before)
                except OSError as exc:
                    rollback_errors.append("{}: {}".format(path, exc))
            journal["status"] = "rollback-incomplete" if rollback_errors else "failed-and-rolled-back"
            journal["finished_at"] = core._utc_now()
            if rollback_errors:
                journal["rollback_errors"] = rollback_errors
            try:
                _v1._write_json(run_dir / "run.json", journal)
            except OSError:
                pass
            if rollback_errors:
                raise core.WallfixError("apply failed and rollback was incomplete: {}".format("; ".join(rollback_errors)))
            raise
    return run_id, records


_v1._apply_outputs = _apply_outputs_v6


def _restore_v6(target, run_id, state_dir=None, force=False):
    if not re.match(r"^[A-Za-z0-9._-]+$", run_id):
        raise core.WallfixError("invalid run id")
    state = Path(state_dir).expanduser().resolve() if state_dir else _v1._default_state_dir(target).resolve()
    run_dir = state / "runs" / run_id
    record_path = run_dir / "run.json"
    try:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise core.WallfixError("cannot read run {}: {}".format(run_id, exc))
    if Path(payload.get("target", "")).resolve() != target:
        raise core.WallfixError("run target does not match: {}".format(run_id))
    status = payload.get("status")
    if status in ("restored", "recovered"):
        return {"schema_version": 1, "command": "restore", "status": "already-restored", "target": str(target), "run_id": run_id, "summary": {"files": 0}}
    if status not in ("applied", "preparing"):
        raise core.WallfixError("run is not restorable (status: {})".format(status))
    records = payload.get("files", [])
    with TargetLockV6(state, target):
        conflicts = []
        current = {}
        for item in records:
            path = (target / item["path"]).resolve()
            _v1._assert_safe_output(path, target)
            data = path.read_bytes() if path.exists() else None
            current[path] = data
            actual = hashlib.sha256(data).hexdigest() if data is not None else ""
            allowed = {item.get("after_sha256", "")}
            if status == "preparing":
                allowed.add(item.get("before_sha256", ""))
            if actual not in allowed:
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
                    _atomic_write_safe(path, data)
                elif path.exists():
                    path.unlink()
                restored.append(path)
            payload["status"] = "recovered" if status == "preparing" else "restored"
            payload["restored_at"] = core._utc_now()
            payload["restore_forced"] = bool(force)
            _v1._write_json(record_path, payload)
        except BaseException:
            for path in reversed(restored):
                data = current[path]
                try:
                    if data is None:
                        if path.exists():
                            path.unlink()
                    else:
                        _atomic_write_safe(path, data)
                except OSError:
                    pass
            raise
    return {
        "schema_version": 1,
        "command": "restore",
        "status": payload["status"],
        "target": str(target),
        "run_id": run_id,
        "summary": {"files": len(records), "forced_conflicts": len(conflicts)},
    }


_v1._restore = _restore_v6


def _emit_error(command, status, message, use_json):
    payload = {"schema_version": 1, "command": command or "", "status": status, "error": str(message)}
    if use_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print("error: {}".format(message), file=sys.stderr)


def main(argv=None):
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    use_json_hint = "--json" in raw_arguments
    try:
        arguments = _v1._parser().parse_args(raw_arguments)
    except SystemExit as exc:
        return _v1.EXIT_OK if int(exc.code or 0) == 0 else _v1.EXIT_INPUT
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
    except core.RestoreConflict as exc:
        _emit_error(arguments.command, "conflict", exc, use_json)
        return _v1.EXIT_CONFLICT
    except core.WallfixError as exc:
        _emit_error(arguments.command, "error", exc, use_json)
        return _v1.EXIT_INPUT
    except OSError as exc:
        _emit_error(arguments.command, "write-error", exc, use_json)
        return _v1.EXIT_WRITE
    except KeyboardInterrupt:
        _emit_error(arguments.command, "interrupted", "operation interrupted", use_json_hint)
        return 130

    report_error = ""
    if arguments.json_output:
        try:
            _v1._write_result_file(arguments.json_output, payload)
        except OSError as exc:
            report_error = str(exc)
            payload["json_output_error"] = report_error
    if use_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif arguments.command == "scan":
        _v1._human_scan(payload)
    elif arguments.command == "apply":
        _v1._human_apply(payload)
    else:
        _v1._human_restore(payload)
    if report_error:
        print("error: JSON report could not be written: {}".format(report_error), file=sys.stderr)
        return _v1.EXIT_WRITE
    if arguments.command == "apply":
        summary = payload["summary"]
        if summary["unresolved"] or summary["report_only"]:
            return _v1.EXIT_REVIEW
    return _v1.EXIT_OK
