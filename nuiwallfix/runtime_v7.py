"""Runtime v7: crash-recoverable restore and stricter input/CORS guards."""

import json
import math
import os
import re
import sys
from pathlib import Path

from . import core
from . import runtime_v1 as _v1
from . import runtime_v6 as _v6
from .runtime_v6 import *  # noqa: F401,F403


_scan_v6 = core.scan_target


def _tag_attributes_for_reference(reference, document):
    opening = document.text.rfind("<", 0, reference.start)
    if opening < 0:
        return {}
    tag_end = core._find_html_tag_end(document.text, opening + 1)
    if tag_end <= reference.end:
        return {}
    tag_text = document.text[opening:tag_end]
    match = re.match(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9:-]*)", tag_text)
    if not match:
        return {}
    return core._html_attributes(tag_text, opening, match.end())


def _is_member_dynamic_import(reference, document):
    if reference.context != "js-dynamic-import":
        return False
    tokens = core._lex_js(document.text)
    for index, token in enumerate(tokens):
        if token.kind != "string" or token.start != reference.start or token.end != reference.end:
            continue
        if index < 2 or tokens[index - 1].value != "(" or tokens[index - 2].value != "import":
            return False
        return index >= 3 and tokens[index - 3].value == "."
    return False


def _scan_with_context_guards(target):
    result = _scan_v6(target)
    for reference in result.references:
        document = result.documents.get(str(reference.file_path))
        if not document:
            continue
        if _is_member_dynamic_import(reference, document):
            reference.context = "js-member-import"
            reference.auto_allowed = False
            reference.reason = "member method named import; report only"
            continue
        if reference.syntax != "html":
            continue
        attributes = _tag_attributes_for_reference(reference, document)
        type_values = attributes.get("type", [])
        rel_values = attributes.get("rel", [])
        has_crossorigin = bool(attributes.get("crossorigin"))
        type_value = type_values[0].value.strip().lower() if type_values else ""
        rel_value = rel_values[0].value.strip().lower() if rel_values else ""
        if reference.context == "html-script" and type_value == "module":
            reference.context = "html-module-script"
        elif reference.context == "html-link" and "modulepreload" in rel_value.split():
            reference.context = "html-modulepreload"
        elif has_crossorigin:
            reference.context = "html-crossorigin-asset"
    return result


core.scan_target = _scan_with_context_guards


_resolve_mirror_v6 = _v1._resolve_mirror


def _resolve_mirror_all_cors(reference, fetcher, rules, allow_unverified):
    replacement, verification = _resolve_mirror_v6(reference, fetcher, rules, allow_unverified)
    if verification == "already-provider-target":
        return replacement, verification
    cors_required = reference.kind == "font" or reference.context in {
        "html-modulepreload", "html-crossorigin-asset",
    }
    if cors_required:
        result = fetcher.fetch(replacement)
        allowed_origin = getattr(result, "headers", {}).get("access-control-allow-origin", "")
        if allowed_origin.strip() != "*":
            raise core.ResolveError("domestic CDN lacks Access-Control-Allow-Origin: * for a CORS-required asset")
    return replacement, verification


_v1._resolve_mirror = _resolve_mirror_all_cors


class ValidatedFetcher(_v6.PinnedFetcher):
    def __init__(self, timeout=15.0, max_bytes=20 * 1024 * 1024, allow_private=False):
        try:
            parsed_timeout = float(timeout)
            parsed_max_bytes = int(max_bytes)
        except (TypeError, ValueError, OverflowError):
            raise core.WallfixError("timeout and max-bytes must be numeric")
        if not math.isfinite(parsed_timeout) or parsed_timeout <= 0:
            raise core.WallfixError("timeout must be a finite number greater than zero")
        if parsed_max_bytes <= 0:
            raise core.WallfixError("max-bytes must be greater than zero")
        _v6.PinnedFetcher.__init__(self, parsed_timeout, parsed_max_bytes, allow_private)


_v1.Fetcher = ValidatedFetcher


def _strict_load_rules(path=None):
    selected = Path(path).expanduser().resolve() if path else _v1._default_provider_path()
    try:
        payload = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise core.WallfixError("cannot read provider config {}: {}".format(selected, exc))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("rules"), list):
        raise core.WallfixError("unsupported provider config schema: {}".format(selected))
    rules = []
    for index, item in enumerate(payload["rules"]):
        if not isinstance(item, dict):
            raise core.WallfixError("provider rule {} must be an object".format(index))
        rule_type = item.get("type")
        source = item.get("source")
        target = item.get("target")
        if rule_type not in ("prefix", "npm_file"):
            raise core.WallfixError("provider rule {} has an invalid type".format(index))
        if not isinstance(source, str) or not isinstance(target, str) or not source or not target:
            raise core.WallfixError("provider rule {} requires string source and target URLs".format(index))
        for label, value in (("source", source), ("target", target)):
            try:
                parsed = _v1.urllib.parse.urlsplit(value)
            except ValueError as exc:
                raise core.WallfixError("provider rule {} {} URL is invalid: {}".format(index, label, exc))
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise core.WallfixError("provider rule {} {} must be a credential-free HTTP(S) URL".format(index, label))
        name = item.get("name")
        if name is not None and not isinstance(name, str):
            raise core.WallfixError("provider rule {} name must be a string".format(index))
        rules.append(dict(item))
    return rules


_v1._load_rules = _strict_load_rules


def _validated_run_paths(target, run_id, state_dir):
    if not isinstance(run_id, str) or run_id in (".", "..") or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", run_id):
        raise core.WallfixError("invalid run id")
    state = Path(state_dir).expanduser().resolve() if state_dir else _v1._default_state_dir(target).resolve()
    runs_root = (state / "runs").resolve()
    run_dir = (runs_root / run_id).resolve()
    if run_dir.parent != runs_root:
        raise core.WallfixError("run id escapes the runs directory")
    return state, run_dir


def _restore_v7(target, run_id, state_dir=None, force=False):
    state, run_dir = _validated_run_paths(target, run_id, state_dir)
    record_path = run_dir / "run.json"
    try:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise core.WallfixError("cannot read run {}: {}".format(run_id, exc))
    if not isinstance(payload, dict) or Path(payload.get("target", "")).resolve() != target:
        raise core.WallfixError("run target does not match: {}".format(run_id))
    status = payload.get("status")
    if status in ("restored", "recovered"):
        return {"schema_version": 1, "command": "restore", "status": "already-restored", "target": str(target), "run_id": run_id, "summary": {"files": 0}}
    if status not in ("applied", "preparing", "restoring"):
        raise core.WallfixError("run is not restorable (status: {})".format(status))
    records = payload.get("files", [])
    if not isinstance(records, list):
        raise core.WallfixError("run file list is invalid")
    with _v6.TargetLockV6(state, target):
        conflicts = []
        current = {}
        effective_force = bool(force or payload.get("restore_force"))
        recoverable_mix = status in ("preparing", "restoring")
        for item in records:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise core.WallfixError("run contains an invalid file record")
            path = (target / item["path"]).resolve()
            _v1._assert_safe_output(path, target)
            data = path.read_bytes() if path.exists() else None
            current[path] = data
            actual = _v1.hashlib.sha256(data).hexdigest() if data is not None else ""
            allowed = {item.get("after_sha256", "")}
            if recoverable_mix:
                allowed.add(item.get("before_sha256", ""))
            if actual not in allowed:
                conflicts.append(item["path"])
        if conflicts and not effective_force:
            raise core.RestoreConflict("files changed after apply: {}".format(", ".join(conflicts)))

        restore_origin = payload.get("restore_from_status") or status
        if status != "restoring":
            payload["restore_from_status"] = status
            payload["restore_force"] = effective_force
            payload["restore_started_at"] = core._utc_now()
            payload["status"] = "restoring"
            _v1._write_json(record_path, payload)

        restored = []
        try:
            for item in records:
                path = (target / item["path"]).resolve()
                if item.get("existed_before"):
                    backup = run_dir / item.get("backup", "")
                    if not core._is_within(backup.resolve(), run_dir):
                        raise core.WallfixError("backup path escapes the run directory")
                    data = backup.read_bytes()
                    if _v1.hashlib.sha256(data).hexdigest() != item.get("before_sha256"):
                        raise core.WallfixError("backup hash mismatch: {}".format(backup))
                    _v6._atomic_write_safe(path, data)
                elif path.exists():
                    path.unlink()
                restored.append(path)
            payload["status"] = "recovered" if restore_origin == "preparing" else "restored"
            payload["restored_at"] = core._utc_now()
            payload["restore_forced"] = effective_force
            _v1._write_json(record_path, payload)
        except BaseException:
            rollback_errors = []
            for path in reversed(restored):
                data = current[path]
                try:
                    if data is None:
                        if path.exists():
                            path.unlink()
                    else:
                        _v6._atomic_write_safe(path, data)
                except OSError as exc:
                    rollback_errors.append("{}: {}".format(path, exc))
            if rollback_errors:
                payload["status"] = "rollback-incomplete"
                payload["restore_rollback_errors"] = rollback_errors
                try:
                    _v1._write_json(record_path, payload)
                except OSError:
                    pass
                raise core.WallfixError("restore failed and rollback was incomplete: {}".format("; ".join(rollback_errors)))
            raise
    return {
        "schema_version": 1,
        "command": "restore",
        "status": payload["status"],
        "target": str(target),
        "run_id": run_id,
        "summary": {"files": len(records), "forced_conflicts": len(conflicts)},
    }


_v1._restore = _restore_v7


def main(argv=None):
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _v1._parser().parse_args(raw_arguments)
    except SystemExit as exc:
        code = int(exc.code or 0)
        if code != 0 and "--json" in raw_arguments:
            command = raw_arguments[0] if raw_arguments and not raw_arguments[0].startswith("-") else ""
            print(json.dumps({
                "schema_version": 1,
                "command": command,
                "status": "error",
                "error": "invalid command line; see stderr for usage details",
            }, ensure_ascii=False, sort_keys=True))
        return _v1.EXIT_OK if code == 0 else _v1.EXIT_INPUT
    return _v6.main(raw_arguments)


try:
    import nuiwallfix as _public_package
    _public_package.scan_target = core.scan_target
except ImportError:
    pass
