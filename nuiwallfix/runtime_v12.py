"""Runtime v12: persistent operation-specific execution reports."""

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

from . import core
from . import reporting
from . import runtime_v1 as _v1
from . import runtime_v11 as _v11
from .runtime_v11 import *  # noqa: F401,F403


RUNTIME_MODULE = __name__


def _operation_name(command, request):
    if command == "apply":
        return "apply" if request.get("write_requested") else "preview"
    return reporting._safe_operation(command)


def _error_payload(command, target, status, message):
    return {
        "schema_version": 1,
        "command": command or "",
        "status": status,
        "target": str(Path(target).expanduser().resolve()),
        "error": str(message),
    }


def _attach_exception_payload(exc, payload):
    try:
        exc.wallfix_payload = payload
    except (AttributeError, TypeError):
        pass


def _run_with_report(command, target, request, report_dir, callback):
    operation = _operation_name(command, request)
    execution = reporting.begin_report(target, operation, report_dir)
    if command == "apply" and request.get("write_requested"):
        execution["preexisting_run_ids"] = reporting.snapshot_run_ids(target, request)
    try:
        payload = callback()
    except core.RestoreConflict as exc:
        payload = _error_payload(command, target, "conflict", exc)
        reporting.persist_report_safe(payload, target, request, execution, RUNTIME_MODULE)
        _attach_exception_payload(exc, payload)
        raise
    except core.WallfixError as exc:
        payload = _error_payload(command, target, "error", exc)
        reporting.persist_report_safe(payload, target, request, execution, RUNTIME_MODULE)
        _attach_exception_payload(exc, payload)
        raise
    except OSError as exc:
        payload = _error_payload(command, target, "write-error", exc)
        reporting.persist_report_safe(payload, target, request, execution, RUNTIME_MODULE)
        _attach_exception_payload(exc, payload)
        raise
    except KeyboardInterrupt as exc:
        payload = _error_payload(command, target, "interrupted", "operation interrupted")
        reporting.persist_report_safe(payload, target, request, execution, RUNTIME_MODULE)
        _attach_exception_payload(exc, payload)
        raise
    except Exception as exc:
        payload = _error_payload(command, target, "error", exc)
        reporting.persist_report_safe(payload, target, request, execution, RUNTIME_MODULE)
        _attach_exception_payload(exc, payload)
        raise

    try:
        reporting.persist_report(payload, target, request, execution, RUNTIME_MODULE)
    except Exception as exc:
        message = "execution report could not be written: {}".format(exc)
        payload["execution_report_error"] = message
        report_error = OSError(message)
        _attach_exception_payload(report_error, payload)
        raise report_error
    return payload


def api_scan(target, report_dir=None):
    request = {
        "write_requested": False,
        "report_dir": report_dir or "",
    }
    return _run_with_report(
        "scan",
        target,
        request,
        report_dir,
        lambda: _v11.api_scan(target),
    )


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
    report_dir=None,
):
    request = {
        "mode": mode,
        "write_requested": bool(write),
        "providers_path": providers or "",
        "state_dir": state_dir or "",
        "timeout_seconds": timeout,
        "max_bytes": max_bytes,
        "allow_unverified_mirror": bool(allow_unverified_mirror),
        "allow_private_network": bool(allow_private_network),
        "report_dir": report_dir or "",
    }

    def execute():
        return _v11.api_apply(
            target,
            mode=mode,
            write=write,
            providers=providers,
            state_dir=state_dir,
            timeout=timeout,
            max_bytes=max_bytes,
            allow_unverified_mirror=allow_unverified_mirror,
            allow_private_network=allow_private_network,
        )

    return _run_with_report("apply", target, request, report_dir, execute)


def _inspect_restore_conflicts(target, run_id, state_dir=None):
    target = Path(target).expanduser().resolve()
    if not reporting.RUN_ID_PATTERN.match(str(run_id or "")):
        return []
    state = (
        Path(state_dir).expanduser().resolve()
        if state_dir
        else _v1._default_state_dir(target).resolve()
    )
    runs_root = (state / "runs").resolve()
    journal_path = (runs_root / str(run_id) / "run.json").resolve()
    if not core._is_within(journal_path, runs_root):
        return []
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        if Path(journal.get("target", "")).resolve() != target:
            return []
        status = journal.get("status")
        if status in ("restored", "recovered"):
            return []
        if status not in ("applied", "preparing", "restoring"):
            return []
        conflicts = []
        for item in journal.get("files", []):
            path = (target / item["path"]).resolve()
            if not core._is_within(path, target):
                return []
            data = path.read_bytes() if path.exists() else None
            actual = _v1.hashlib.sha256(data).hexdigest() if data is not None else ""
            allowed = {item.get("after_sha256", "")}
            if status in ("preparing", "restoring"):
                allowed.add(item.get("before_sha256", ""))
            if actual not in allowed:
                conflicts.append(item["path"])
        return conflicts
    except (OSError, ValueError, KeyError, TypeError):
        return []


def api_restore(target, run_id, state_dir=None, force=False, report_dir=None):
    pre_restore_conflicts = _inspect_restore_conflicts(target, run_id, state_dir)
    request = {
        "requested_run_id": run_id,
        "state_dir": state_dir or "",
        "force": bool(force),
        "write_requested": True,
        "report_dir": report_dir or "",
        "pre_restore_conflicts": pre_restore_conflicts,
    }
    return _run_with_report(
        "restore",
        target,
        request,
        report_dir,
        lambda: _v11.api_restore(target, run_id, state_dir, force),
    )


def _parser():
    parser = _v1._parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for subparser in action.choices.values():
                subparser.add_argument(
                    "--report-dir",
                    help="execution report directory outside the target resource tree",
                )
            break
    return parser


def _option_value(raw_arguments, name):
    try:
        index = raw_arguments.index(name)
    except ValueError:
        return ""
    if index + 1 >= len(raw_arguments):
        return ""
    value = raw_arguments[index + 1]
    return "" if value.startswith("--") else value


def _parse_error_payload(raw_arguments):
    command = raw_arguments[0] if raw_arguments and not raw_arguments[0].startswith("-") else ""
    target = (
        raw_arguments[1]
        if len(raw_arguments) > 1 and not raw_arguments[1].startswith("-")
        else str(Path.cwd())
    )
    request = {
        "write_requested": "--write" in raw_arguments,
        "requested_run_id": _option_value(raw_arguments, "--run-id"),
        "state_dir": _option_value(raw_arguments, "--state-dir"),
        "providers_path": _option_value(raw_arguments, "--providers"),
        "report_dir": _option_value(raw_arguments, "--report-dir"),
        "invalid_command_line": True,
    }
    payload = _error_payload(
        command,
        target,
        "error",
        "invalid command line; see stderr for usage details",
    )
    try:
        execution = reporting.begin_report(
            target,
            _operation_name(command, request),
            request["report_dir"] or None,
        )
        reporting.persist_report_safe(payload, target, request, execution, RUNTIME_MODULE)
    except Exception as exc:
        payload["execution_report_error"] = str(exc)
    return payload


def _emit_payload(payload, use_json):
    if use_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return
    message = (
        payload.get("execution_report_error")
        or payload.get("json_output_error")
        or payload.get("error")
        or "operation failed"
    )
    print("error: {}".format(message), file=sys.stderr)


def _emit_success(payload, arguments):
    if arguments.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return
    if arguments.command == "scan":
        _v1._human_scan(payload)
    elif arguments.command == "apply":
        _v1._human_apply(payload)
    else:
        _v1._human_restore(payload)
    report = payload.get("execution_report", {})
    report_path = report.get("markdown", "")
    if report_path and Path(report_path).is_file():
        print("Execution report: {}".format(report_path))


def _main_impl(raw_arguments):
    use_json_hint = "--json" in raw_arguments
    try:
        arguments = _parser().parse_args(raw_arguments)
    except SystemExit as exc:
        code = int(exc.code or 0)
        if code == 0:
            return _v1.EXIT_OK
        payload = _parse_error_payload(raw_arguments)
        _emit_payload(payload, use_json_hint)
        return _v1.EXIT_INPUT

    try:
        if arguments.command == "scan":
            payload = api_scan(arguments.target, report_dir=arguments.report_dir)
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
                report_dir=arguments.report_dir,
            )
        else:
            payload = api_restore(
                arguments.target,
                arguments.run_id,
                state_dir=arguments.state_dir,
                force=arguments.force,
                report_dir=arguments.report_dir,
            )
    except core.RestoreConflict as exc:
        payload = getattr(exc, "wallfix_payload", None) or _error_payload(
            arguments.command, arguments.target, "conflict", exc
        )
        _emit_payload(payload, bool(arguments.json))
        return _v1.EXIT_CONFLICT
    except core.WallfixError as exc:
        payload = getattr(exc, "wallfix_payload", None) or _error_payload(
            arguments.command, arguments.target, "error", exc
        )
        _emit_payload(payload, bool(arguments.json))
        return _v1.EXIT_INPUT
    except OSError as exc:
        payload = getattr(exc, "wallfix_payload", None) or _error_payload(
            arguments.command, arguments.target, "write-error", exc
        )
        if payload.get("execution_report_error") and payload.get("command"):
            _emit_success(payload, arguments)
            if not arguments.json:
                print(
                    "error: {}".format(payload["execution_report_error"]),
                    file=sys.stderr,
                )
        else:
            _emit_payload(payload, bool(arguments.json))
        return _v1.EXIT_WRITE
    except KeyboardInterrupt as exc:
        payload = getattr(exc, "wallfix_payload", None) or _error_payload(
            arguments.command, arguments.target, "interrupted", "operation interrupted"
        )
        _emit_payload(payload, use_json_hint)
        return 130
    except Exception as exc:
        payload = getattr(exc, "wallfix_payload", None) or _error_payload(
            arguments.command, arguments.target, "error", exc
        )
        _emit_payload(payload, bool(arguments.json))
        return _v1.EXIT_INPUT

    json_output_error = ""
    if arguments.json_output:
        try:
            _v1._write_result_file(arguments.json_output, payload)
        except OSError as exc:
            json_output_error = str(exc)
            payload["json_output_error"] = json_output_error
            try:
                reporting.mark_output_failure(payload, json_output_error)
            except Exception as report_exc:
                payload["execution_report_update_error"] = str(report_exc)

    _emit_success(payload, arguments)
    if json_output_error:
        if not arguments.json:
            print(
                "error: JSON result could not be written: {}".format(json_output_error),
                file=sys.stderr,
            )
        return _v1.EXIT_WRITE
    if arguments.command == "apply":
        summary = payload["summary"]
        if summary["unresolved"] or summary["report_only"]:
            return _v1.EXIT_REVIEW
    return _v1.EXIT_OK


def main(argv=None):
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if "--json" not in raw_arguments:
        return _main_impl(raw_arguments)
    captured_stderr = io.StringIO()
    with contextlib.redirect_stderr(captured_stderr):
        return _main_impl(raw_arguments)


try:
    import nuiwallfix as _public_package
    _public_package.scan_target = core.scan_target
except ImportError:
    pass
