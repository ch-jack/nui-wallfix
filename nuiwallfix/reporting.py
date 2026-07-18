"""Persistent, operation-specific execution reports for nui-wallfix."""

import copy
import datetime
import hashlib
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

from . import __version__, core
from . import runtime_v1 as _v1


REPORT_SCHEMA = "nui-wallfix.execution/v1"
URL_FIELDS = {"url", "raw_url", "replacement", "origin_url", "fetch_url"}
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_OPERATIONS = {"scan", "preview", "apply", "restore", "unknown"}
URL_IN_TEXT_PATTERN = re.compile(r"(?:(?:https?):)?//[^\s<>\"']+", re.IGNORECASE)


def begin_execution():
    return {
        "started_at_utc": datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
        "started_clock": time.monotonic(),
        "started_timestamp": time.time(),
    }


def _safe_operation(operation):
    value = str(operation or "unknown")
    return value if value in SAFE_OPERATIONS else "unknown"


def begin_report(target, operation, report_dir=None):
    execution = begin_execution()
    execution["execution_id"] = _execution_id()
    execution["operation"] = _safe_operation(operation)
    execution["paths"] = _report_paths(
        target,
        execution["operation"],
        execution["started_at_utc"],
        execution["execution_id"],
        report_dir,
    )
    return execution


def _finished_at_utc():
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _execution_id():
    return _v1._datetime_run_id()


def _operation_name(command, request):
    if command == "apply":
        return "apply" if request.get("write_requested") else "preview"
    return _safe_operation(command)


def _report_paths(target, operation, started_at_utc, execution_id, report_dir=None):
    target = Path(target).expanduser().resolve()
    operation = _safe_operation(operation)
    root = (
        Path(report_dir).expanduser().resolve()
        if report_dir
        else (target.parent / ".nui-wallfix-reports").resolve()
    )
    if core._is_within(root, target):
        raise core.WallfixError("report directory must be outside the target resource tree")
    date_parts = started_at_utc[:10].split("-")
    if len(date_parts) != 3:
        date_parts = ["unknown", "unknown", "unknown"]
    execution_dir = root.joinpath(date_parts[0], date_parts[1], date_parts[2], execution_id)
    paths = {
        "root": root,
        "execution_dir": execution_dir,
        "history_json": execution_dir / "report.json",
        "history_markdown": execution_dir / "report.md",
        "latest_json": root / ("latest-" + operation + ".json"),
        "latest_markdown": root / ("latest-" + operation + ".md"),
    }
    for name, path in paths.items():
        if name != "root" and not core._is_within(path.resolve(), root):
            raise core.WallfixError("report path escapes the report directory")
    return paths


def _build_metadata():
    build_path = Path(__file__).resolve().parent.parent / "BUILD.txt"
    metadata = {}
    if not build_path.is_file():
        return metadata
    try:
        lines = build_path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return metadata
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            metadata[key.strip()] = value.strip()
    return metadata


def _sha256_file(path):
    if not path:
        return ""
    selected = Path(path).expanduser()
    if not selected.is_file():
        return ""
    digest = hashlib.sha256()
    try:
        with selected.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _redact_url(value):
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    looks_like_url = bool(re.match(r"^(?:(?:https?):)?//", candidate, re.IGNORECASE))
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return "<redacted-url>" if looks_like_url else value
    scheme = parsed.scheme.lower()
    if scheme not in ("", "http", "https") or not parsed.netloc:
        return value
    try:
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return "<redacted-url>" if looks_like_url else value
    if ":" in hostname and not hostname.startswith("["):
        hostname = "[" + hostname + "]"
    netloc = hostname + (":" + str(port) if port is not None else "")
    query = "<redacted>" if parsed.query else ""
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def _sanitize(value, field=""):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _sanitize(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, field) for item in value]
    if isinstance(value, str):
        if field in URL_FIELDS:
            return _redact_url(value)
        return URL_IN_TEXT_PATTERN.sub(lambda match: _redact_url(match.group(0)), value)
    return value


def _conflict_files(payload):
    error = str(payload.get("error", ""))
    marker = "files changed after apply:"
    if marker not in error:
        return []
    return [
        item.strip()
        for item in error.split(marker, 1)[1].split(",")
        if item.strip()
    ]


def snapshot_run_ids(target, request):
    target = Path(target).expanduser().resolve()
    state_value = request.get("state_dir")
    state_dir = (
        Path(state_value).expanduser().resolve()
        if state_value
        else _v1._default_state_dir(target).resolve()
    )
    runs_root = (state_dir / "runs").resolve()
    try:
        return {
            path.parent.name
            for path in runs_root.glob("*/run.json")
            if RUN_ID_PATTERN.match(path.parent.name)
        }
    except OSError:
        return set()


def _recent_apply_run_id(target, state_dir, execution):
    runs_root = (state_dir / "runs").resolve()
    if not runs_root.is_dir() or not execution:
        return ""
    threshold = float(execution.get("started_timestamp", time.time())) - 1.0
    candidates = []
    preexisting = set(execution.get("preexisting_run_ids", ()))
    try:
        journal_paths = list(runs_root.glob("*/run.json"))
    except OSError:
        return ""
    for journal_path in journal_paths:
        try:
            modified = journal_path.stat().st_mtime
            if modified < threshold:
                continue
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            run_id = str(journal.get("run_id", ""))
            if (
                isinstance(journal, dict)
                and run_id not in preexisting
                and RUN_ID_PATTERN.match(run_id)
                and Path(journal.get("target", "")).resolve() == target
            ):
                candidates.append((modified, run_id))
        except (OSError, ValueError, TypeError):
            continue
    return max(candidates)[1] if candidates else ""


def _journal_details(payload, target, request, execution=None):
    target = Path(target).expanduser().resolve()
    state_value = payload.get("state_dir") or request.get("state_dir")
    state_dir = (
        Path(state_value).expanduser().resolve()
        if state_value
        else _v1._default_state_dir(target).resolve()
    )
    run_id = str(payload.get("run_id") or request.get("requested_run_id") or "")
    if not run_id and request.get("write_requested"):
        run_id = _recent_apply_run_id(target, state_dir, execution)
    if not run_id or not RUN_ID_PATTERN.match(run_id):
        return {
            "run_id": run_id,
            "journal": {},
            "journal_path": "",
            "state_dir": str(state_dir),
        }
    runs_root = (state_dir / "runs").resolve()
    journal_path = (runs_root / run_id / "run.json").resolve()
    if not core._is_within(journal_path, runs_root):
        return {
            "run_id": run_id,
            "journal": {},
            "journal_path": "",
            "state_dir": str(state_dir),
            "journal_error": "journal path escapes the runs directory",
        }
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {
            "run_id": run_id,
            "journal": {},
            "journal_path": str(journal_path),
            "state_dir": str(state_dir),
            "journal_error": str(exc),
        }
    return {
        "run_id": run_id,
        "journal": journal if isinstance(journal, dict) else {},
        "journal_path": str(journal_path),
        "state_dir": str(state_dir),
    }


def _outcome(payload):
    status = str(payload.get("status", ""))
    if status == "conflict":
        return "conflict"
    if status == "interrupted":
        return "interrupted"
    if status in ("error", "write-error"):
        return "error"
    summary = payload.get("summary", {})
    if payload.get("command") == "apply" and (
        int(summary.get("unresolved", 0) or 0)
        or int(summary.get("report_only", 0) or 0)
    ):
        return "review-required"
    return "success"


def _exit_code(payload):
    outcome = _outcome(payload)
    if outcome == "conflict":
        return _v1.EXIT_CONFLICT
    if outcome == "interrupted":
        return 130
    if outcome == "error":
        return _v1.EXIT_WRITE if payload.get("status") == "write-error" else _v1.EXIT_INPUT
    if outcome == "review-required":
        return _v1.EXIT_REVIEW
    return _v1.EXIT_OK


def _report_notes(operation, payload, journal_details):
    summary = payload.get("summary", {})
    notes = [
        "\u62a5\u544a\u5199\u5728\u76ee\u6807\u76ee\u5f55\u4e4b\u5916\uff0c\u4e0d\u4f1a\u88ab FiveM resource \u7684 files \u89c4\u5219\u52a0\u8f7d\u3002",
        "\u6301\u4e45\u62a5\u544a\u5df2\u79fb\u9664 URL \u7528\u6237\u4fe1\u606f\u3001fragment\uff0c\u5e76\u8131\u654f\u6240\u6709 query \u503c\uff1bCLI \u539f\u751f JSON \u8fd4\u56de\u503c\u4fdd\u6301\u4e0d\u53d8\u3002",
    ]
    if operation == "scan":
        notes.extend([
            "\u672c\u6b21\u626b\u63cf\u4e0d\u8054\u7f51\uff0c\u4e5f\u6ca1\u6709\u6539\u5199\u76ee\u6807\u76ee\u5f55\u4e2d\u7684\u4efb\u4f55\u6587\u4ef6\u3002",
            "fetch\u3001WebSocket\u3001EventSource\u3001FiveM NUI callback\u3001\u8fdc\u7a0b iframe \u548c\u52a8\u6001 URL \u53ea\u62a5\u544a\uff0c\u4e0d\u81ea\u52a8\u66ff\u6362\u3002",
        ])
    elif operation == "preview":
        notes.extend([
            "\u672c\u6b21\u53ea\u5b8c\u6210\u89e3\u6790\u548c\u6539\u5199\u9884\u89c8\uff0c\u6ca1\u6709\u5199\u5165\u76ee\u6807\u6587\u4ef6\uff0c\u4e5f\u6ca1\u6709\u521b\u5efa\u53ef\u6062\u590d\u5907\u4efd\u3002",
            "unresolved \u548c report-only \u9879\u5fc5\u987b\u4eba\u5de5\u786e\u8ba4\uff1b\u56fd\u5185\u955c\u50cf\u53ef\u7528\u6027\u4ee5\u672c\u6b21\u6821\u9a8c\u7ed3\u679c\u4e3a\u51c6\u3002",
        ])
    elif operation == "apply":
        notes.extend([
            "\u4ec5 files \u6e05\u5355\u4e2d\u7684\u5b9e\u9645\u6539\u5199\u8bb0\u5f55\u4ee3\u8868\u672c\u6b21\u5199\u5165\uff1brun.json \u7684 result_summary \u53ef\u80fd\u65e9\u4e8e\u6700\u7ec8\u5199\u5165\u8ba1\u6570\u3002",
            "\u6062\u590d\u524d\u82e5\u7528\u6237\u7ee7\u7eed\u4fee\u6539\u5df2\u6539\u5199\u6587\u4ef6\uff0c\u9ed8\u8ba4 restore \u4f1a\u62a5\u544a\u51b2\u7a81\u5e76\u62d2\u7edd\u8986\u76d6\u3002",
        ])
        if journal_details.get("run_id"):
            notes.append(
                "\u8bf7\u4fdd\u7559\u5907\u4efd\u76ee\u5f55\u548c Run ID {}\uff1b\u5220\u9664\u62a5\u544a\u4e0d\u4f1a\u5220\u9664\u5907\u4efd\uff0c\u5220\u9664\u5907\u4efd\u5219\u4f1a\u5931\u53bb\u6062\u590d\u80fd\u529b\u3002".format(
                    journal_details["run_id"]
                )
            )
    elif operation == "restore":
        notes.append("\u5f3a\u5236\u6062\u590d\u4f1a\u8986\u76d6 apply \u4e4b\u540e\u7684\u7528\u6237\u6539\u52a8\uff1b\u53ea\u6709\u786e\u8ba4\u8fd9\u4e9b\u6539\u52a8\u53ef\u4ee5\u4e22\u5f03\u65f6\u624d\u5e94\u4f7f\u7528 --force\u3002")
        if payload.get("status") == "already-restored":
            notes.append("\u8be5 Run ID \u4e4b\u524d\u5df2\u7ecf\u6062\u590d\uff0c\u672c\u6b21\u6ca1\u6709\u518d\u6b21\u6539\u5199\u6587\u4ef6\u3002")
    if int(summary.get("unresolved", 0) or 0):
        notes.append("\u4ecd\u6709 {} \u6761\u5f15\u7528\u672a\u89e3\u51b3\uff0c\u6b63\u5f0f\u90e8\u7f72\u524d\u5fc5\u987b\u68c0\u67e5\u6d4f\u89c8\u5668\u63a7\u5236\u53f0\u3002".format(summary["unresolved"]))
    if int(summary.get("report_only", 0) or 0):
        notes.append("\u6709 {} \u6761\u4e1a\u52a1\u6216\u52a8\u6001\u5f15\u7528\u4ec5\u62a5\u544a\uff0c\u5de5\u5177\u4e0d\u4f1a\u731c\u6d4b\u5176\u66ff\u6362\u65b9\u5f0f\u3002".format(summary["report_only"]))
    journal_status = str(journal_details.get("journal", {}).get("status", ""))
    if journal_status == "rollback-incomplete":
        notes.append("CRITICAL: rollback was incomplete; the target may remain partially modified. Review rollback_errors before any retry.")
    elif journal_status == "failed-and-rolled-back":
        notes.append("The write failed, but every completed target change was rolled back.")
    return notes


def _build_report(payload, target, request, execution, paths, runtime_module):
    operation = _operation_name(payload.get("command"), request)
    finished_at = _finished_at_utc()
    duration_ms = max(0, int(round((time.monotonic() - execution["started_clock"]) * 1000)))
    journal_details = _journal_details(payload, target, request, execution)
    journal = journal_details.get("journal", {})
    files = journal.get("files", []) if isinstance(journal.get("files", []), list) else []
    request_copy = copy.deepcopy(request)
    providers_path = request_copy.get("providers_path")
    if providers_path:
        request_copy["providers_sha256"] = _sha256_file(providers_path)
    else:
        request_copy["providers_sha256"] = ""

    summary = payload.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    journal_summary = journal.get("result_summary", {})
    if not summary and isinstance(journal_summary, dict):
        summary = journal_summary
    journal_status = str(journal.get("status", ""))
    target_files_written = int(
        summary.get("target_files_written", summary.get("written_files", 0)) or 0
    )
    hazardous_failure = bool(
        payload.get("status") in ("error", "write-error", "interrupted")
        and journal_status in ("preparing", "restoring", "rollback-incomplete")
    )
    target_modified = bool(
        journal_status == "rollback-incomplete"
        or hazardous_failure
        or (operation == "apply" and target_files_written)
        or (
            operation == "restore"
            and payload.get("status") in ("restored", "recovered")
            and int(summary.get("files", 0) or 0)
        )
    )
    target_state = "possibly-partial" if hazardous_failure else ("modified" if target_modified else "unchanged")
    report = {
        "report_schema": REPORT_SCHEMA,
        "execution_id": payload["execution_report"]["execution_id"],
        "operation": operation,
        "command": payload.get("command", ""),
        "outcome": _outcome(payload),
        "exit_code": _exit_code(payload),
        "native_status": payload.get("status", ""),
        "target": str(Path(target).expanduser().resolve()),
        "timing": {
            "started_at_utc": execution["started_at_utc"],
            "finished_at_utc": finished_at,
            "duration_ms": duration_ms,
        },
        "tool": {
            "version": __version__,
            "runtime_module": runtime_module,
            "build": _build_metadata(),
            "python": sys.version.split()[0],
        },
        "request": _sanitize(request_copy),
        "summary": _sanitize(summary),
        "safety": {
            "target_modified": target_modified,
            "target_state": target_state,
            "network_resolution_enabled": operation in ("preview", "apply"),
            "backup_created": bool(journal_details.get("journal_path") and operation == "apply"),
            "restorable": journal_status in ("applied", "preparing", "restoring"),
            "forced_restore": bool(
                request.get("force")
                or journal.get("restore_forced")
                or journal.get("restore_force")
            ),
            "report_outside_target": True,
            "url_credentials_and_query_values_redacted": True,
        },
        "notes": _report_notes(operation, payload, journal_details),
        "report_files": {
            "history_json": str(paths["history_json"]),
            "history_markdown": str(paths["history_markdown"]),
            "latest_json": str(paths["latest_json"]),
            "latest_markdown": str(paths["latest_markdown"]),
        },
        "native_payload": _sanitize(copy.deepcopy(payload)),
    }

    references = _sanitize(copy.deepcopy(payload.get("references", [])))
    resources = _sanitize(copy.deepcopy(payload.get("resources", [])))
    assets = _sanitize(copy.deepcopy(payload.get("assets", [])))
    diagnostics = _sanitize(copy.deepcopy(payload.get("diagnostics", [])))
    journal_files = _sanitize(copy.deepcopy(files))
    if operation == "scan":
        report["scan_results"] = {
            "resources": resources,
            "external_references": references,
            "diagnostics": diagnostics,
            "automatic_candidates": int(summary.get("automatic", 0) or 0),
            "report_only": int(summary.get("report_only", 0) or 0),
        }
    elif operation == "preview":
        report["resolution_preview"] = {
            "reference_decisions": references,
            "planned_vendor_assets": assets,
            "diagnostics": diagnostics,
            "planned_files": int(summary.get("planned_files", 0) or 0),
            "target_files_written": 0,
            "backup_created": False,
        }
    elif operation == "apply":
        report["apply_results"] = {
            "reference_decisions": references,
            "downloaded_vendor_assets": assets,
            "diagnostics": diagnostics,
            "run_id": journal_details.get("run_id", ""),
            "state_dir": journal_details.get("state_dir", ""),
            "journal_path": journal_details.get("journal_path", ""),
            "journal_status": journal_status,
            "changed_files": journal_files,
            "journal_error": journal_details.get("journal_error", ""),
            "rollback_errors": _sanitize(copy.deepcopy(journal.get("rollback_errors", []))),
        }
    elif operation == "restore":
        restored_files = journal_files if payload.get("status") in ("restored", "recovered") else []
        request_conflicts = request.get("pre_restore_conflicts")
        conflict_files = (
            list(request_conflicts)
            if isinstance(request_conflicts, list)
            else _conflict_files(payload)
        )
        report["restore_results"] = {
            "run_id": journal_details.get("run_id", ""),
            "state_dir": journal_details.get("state_dir", ""),
            "journal_path": journal_details.get("journal_path", ""),
            "journal_status": journal_status,
            "restored_files": restored_files,
            "source_run_files": journal_files,
            "forced": bool(request.get("force") or journal.get("restore_forced")),
            "conflict_files": conflict_files,
            "journal_error": journal_details.get("journal_error", ""),
            "rollback_errors": _sanitize(copy.deepcopy(journal.get("rollback_errors", []))),
            "restore_rollback_errors": _sanitize(copy.deepcopy(journal.get("restore_rollback_errors", []))),
        }
    if payload.get("error"):
        report["failure"] = {
            "status": payload.get("status", ""),
            "message": _sanitize(str(payload.get("error", "")), "error"),
            "conflict_files": (
                report.get("restore_results", {}).get("conflict_files", [])
                if operation == "restore"
                else _conflict_files(payload)
            ),
        }
    return report


def _md_cell(value):
    return str(value if value is not None else "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _outcome_text(value):
    return {
        "success": "\u6210\u529f",
        "review-required": "\u5b8c\u6210\uff0c\u4f46\u9700\u8981\u4eba\u5de5\u68c0\u67e5",
        "conflict": "\u6062\u590d\u51b2\u7a81",
        "interrupted": "\u5df2\u4e2d\u65ad",
        "error": "\u5931\u8d25",
    }.get(value, value)


def _title(operation):
    return {
        "scan": "NUI \u5916\u94fe\u626b\u63cf\u6267\u884c\u62a5\u544a",
        "preview": "NUI \u53bb\u5899\u9884\u89c8\u6267\u884c\u62a5\u544a",
        "apply": "NUI \u53bb\u5899\u5199\u5165\u6267\u884c\u62a5\u544a",
        "restore": "NUI \u53bb\u5899\u6062\u590d\u6267\u884c\u62a5\u544a",
    }.get(operation, "NUI \u53bb\u5899\u6267\u884c\u62a5\u544a")


def _reference_action(item, operation):
    if operation == "scan":
        return "\u53ef\u81ea\u52a8\u5904\u7406" if item.get("auto_allowed") else "\u4ec5\u62a5\u544a"
    return item.get("action", "")


def _append_references(lines, references, operation):
    lines.extend([
        "",
        "## \u5f15\u7528\u660e\u7ec6",
        "",
        "| \u6587\u4ef6 | \u884c:\u5217 | \u7c7b\u578b | \u5904\u7406\u7ed3\u679c | \u539f\u5730\u5740 | \u66ff\u6362/\u539f\u56e0 |",
        "| --- | ---: | --- | --- | --- | --- |",
    ])
    if not references:
        lines.append("| - | - | - | \u672a\u53d1\u73b0\u5916\u94fe | - | - |")
        return
    for item in references:
        detail = (
            item.get("replacement")
            or item.get("resolution_reason")
            or item.get("reason")
            or ""
        )
        lines.append(
            "| {file} | {line}:{column} | {kind} | {action} | {url} | {detail} |".format(
                file=_md_cell(item.get("file", "")),
                line=_md_cell(item.get("line", "")),
                column=_md_cell(item.get("column", "")),
                kind=_md_cell(item.get("kind", "")),
                action=_md_cell(_reference_action(item, operation)),
                url=_md_cell(item.get("url", "")),
                detail=_md_cell(detail),
            )
        )


def _append_diagnostics(lines, diagnostics):
    lines.extend(["", "## \u626b\u63cf\u8bca\u65ad", ""])
    if not diagnostics:
        lines.append("- \u6ca1\u6709\u8bca\u65ad\u9879\u3002")
        return
    for item in diagnostics:
        location = item.get("file", "")
        lines.append(
            "- [{level}] {location}{message}".format(
                level=item.get("level", "info"),
                location=(str(location) + ": ") if location else "",
                message=item.get("message", ""),
            )
        )


def _append_assets(lines, assets):
    lines.extend([
        "",
        "## \u672c\u5730\u5316\u8d44\u4ea7",
        "",
        "| \u8f93\u51fa\u6587\u4ef6 | \u7c7b\u578b | \u5b57\u8282\u6570 | SHA-256 | \u9a8c\u8bc1\u65b9\u5f0f | \u6765\u6e90 |",
        "| --- | --- | ---: | --- | --- | --- |",
    ])
    if not assets:
        lines.append("| - | - | 0 | - | - | \u672c\u6b21\u6ca1\u6709\u672c\u5730\u5316\u8d44\u4ea7 |")
        return
    for item in assets:
        lines.append(
            "| {file} | {kind} | {bytes} | {sha} | {verification} | {origin} |".format(
                file=_md_cell(item.get("file", "")),
                kind=_md_cell(item.get("kind", "")),
                bytes=_md_cell(item.get("bytes", 0)),
                sha=_md_cell(item.get("sha256", "")),
                verification=_md_cell(item.get("verification", "")),
                origin=_md_cell(item.get("origin_url", "")),
            )
        )


def _append_files(lines, files, heading):
    lines.extend([
        "",
        "## " + heading,
        "",
        "| \u6587\u4ef6 | \u539f\u6765\u5b58\u5728 | \u5199\u5165\u524d SHA-256 | \u5199\u5165\u540e SHA-256 | \u5907\u4efd\u76f8\u5bf9\u8def\u5f84 |",
        "| --- | --- | --- | --- | --- |",
    ])
    if not files:
        lines.append("| - | - | - | - | \u672c\u6b21\u6ca1\u6709\u6587\u4ef6\u8bb0\u5f55 |")
        return
    for item in files:
        lines.append(
            "| {path} | {existed} | {before} | {after} | {backup} |".format(
                path=_md_cell(item.get("path", "")),
                existed="\u662f" if item.get("existed_before") else "\u5426",
                before=_md_cell(item.get("before_sha256", "")),
                after=_md_cell(item.get("after_sha256", "")),
                backup=_md_cell(item.get("backup", "")),
            )
        )


def build_markdown(report):
    operation = report.get("operation", "")
    summary = report.get("summary", {})
    timing = report.get("timing", {})
    safety = report.get("safety", {})
    request = report.get("request", {})
    lines = [
        "# " + _title(operation),
        "",
        "> \u672c\u62a5\u544a\u7531 nui-wallfix \u5728\u672c\u6b21\u547d\u4ee4\u7ed3\u675f\u65f6\u81ea\u52a8\u751f\u6210\u3002\u5386\u53f2\u62a5\u544a\u4e0d\u4f1a\u88ab\u4e0b\u4e00\u6b21\u6267\u884c\u8986\u76d6\u3002",
        "",
        "## \u6267\u884c\u6982\u89c8",
        "",
        "| \u9879\u76ee | \u7ed3\u679c |",
        "| --- | --- |",
        "| \u6267\u884c\u7ed3\u679c | {} |".format(_md_cell(_outcome_text(report.get("outcome", "")))),
        "| \u539f\u751f\u547d\u4ee4\u72b6\u6001 | {} |".format(_md_cell(report.get("native_status", ""))),
        "| \u9000\u51fa\u7801 | {} |".format(_md_cell(report.get("exit_code", ""))),
        "| \u64cd\u4f5c | {} |".format(_md_cell(operation)),
        "| Execution ID | {} |".format(_md_cell(report.get("execution_id", ""))),
        "| \u76ee\u6807\u76ee\u5f55 | {} |".format(_md_cell(report.get("target", ""))),
        "| \u5f00\u59cb\u65f6\u95f4\uff08UTC\uff09 | {} |".format(_md_cell(timing.get("started_at_utc", ""))),
        "| \u7ed3\u675f\u65f6\u95f4\uff08UTC\uff09 | {} |".format(_md_cell(timing.get("finished_at_utc", ""))),
        "| \u8017\u65f6 | {} ms |".format(_md_cell(timing.get("duration_ms", 0))),
        "| \u662f\u5426\u6539\u5199\u76ee\u6807 | {} |".format("\u662f" if safety.get("target_modified") else "\u5426"),
        "| \u662f\u5426\u521b\u5efa\u6062\u590d\u5907\u4efd | {} |".format("\u662f" if safety.get("backup_created") else "\u5426"),
    ]

    if operation == "scan":
        details = report.get("scan_results", {})
        lines.extend([
            "",
            "## \u626b\u63cf\u7ed3\u679c",
            "",
            "- \u8bc6\u522b FiveM NUI resource\uff1a{} \u4e2a".format(summary.get("resources", 0)),
            "- \u53d1\u73b0\u5916\u94fe\u5f15\u7528\uff1a{} \u6761".format(summary.get("references", 0)),
            "- \u53ef\u81ea\u52a8\u5904\u7406\u5019\u9009\uff1a{} \u6761".format(details.get("automatic_candidates", 0)),
            "- \u4ec5\u62a5\u544a\u5f15\u7528\uff1a{} \u6761".format(details.get("report_only", 0)),
            "- \u672c\u6b21\u6ca1\u6709\u8054\u7f51\uff0c\u4e5f\u6ca1\u6709\u4fee\u6539\u76ee\u6807\u6587\u4ef6\u3002",
        ])
        _append_references(lines, details.get("external_references", []), operation)
        _append_diagnostics(lines, details.get("diagnostics", []))
    elif operation == "preview":
        details = report.get("resolution_preview", {})
        lines.extend([
            "",
            "## \u89e3\u6790\u9884\u89c8",
            "",
            "| \u51b3\u7b56 | \u6570\u91cf |",
            "| --- | ---: |",
            "| \u4fdd\u7559\u56fd\u5185\u8fdc\u7a0b\u5730\u5740 | {} |".format(summary.get("remote", 0)),
            "| \u8ba1\u5212\u672c\u5730\u5316 | {} |".format(summary.get("local", 0)),
            "| \u672a\u89e3\u51b3 | {} |".format(summary.get("unresolved", 0)),
            "| \u4ec5\u62a5\u544a | {} |".format(summary.get("report_only", 0)),
            "| \u8ba1\u5212\u8f93\u51fa\u6587\u4ef6 | {} |".format(details.get("planned_files", 0)),
            "| \u5b9e\u9645\u5199\u5165\u76ee\u6807\u6587\u4ef6 | 0 |",
            "",
            "\u6a21\u5f0f\uff1a`{}`\u3002\u672c\u6b21\u9884\u89c8\u6ca1\u6709\u5199\u5165\uff0c\u4e5f\u6ca1\u6709\u521b\u5efa\u53ef\u6062\u590d\u5907\u4efd\u3002".format(
                _md_cell(request.get("mode", "auto"))
            ),
        ])
        _append_references(lines, details.get("reference_decisions", []), operation)
        _append_assets(lines, details.get("planned_vendor_assets", []))
        _append_diagnostics(lines, details.get("diagnostics", []))
    elif operation == "apply":
        details = report.get("apply_results", {})
        lines.extend([
            "",
            "## \u5199\u5165\u7ed3\u679c",
            "",
            "| \u9879\u76ee | \u6570\u91cf/\u503c |",
            "| --- | --- |",
            "| \u8fdc\u7a0b\u66ff\u6362 | {} |".format(summary.get("remote", 0)),
            "| \u672c\u5730\u5316\u5f15\u7528 | {} |".format(summary.get("local", 0)),
            "| \u672a\u89e3\u51b3 | {} |".format(summary.get("unresolved", 0)),
            "| \u4ec5\u62a5\u544a | {} |".format(summary.get("report_only", 0)),
            "| \u4e0b\u8f7d/\u751f\u6210\u8d44\u4ea7 | {} |".format(summary.get("vendor_files", 0)),
            "| \u5b9e\u9645\u5199\u5165\u6587\u4ef6 | {} |".format(
                summary.get("written_files", summary.get("target_files_written", 0))
            ),
            "| Run ID | {} |".format(_md_cell(details.get("run_id", ""))),
            "| \u5907\u4efd\u76ee\u5f55 | {} |".format(_md_cell(details.get("state_dir", ""))),
            "| \u6062\u590d\u65e5\u5fd7 | {} |".format(_md_cell(details.get("journal_path", ""))),
            "| \u6062\u590d\u65e5\u5fd7\u72b6\u6001 | {} |".format(_md_cell(details.get("journal_status", ""))),
        ])
        _append_references(lines, details.get("reference_decisions", []), operation)
        _append_assets(lines, details.get("downloaded_vendor_assets", []))
        _append_files(lines, details.get("changed_files", []), "\u5b9e\u9645\u6539\u5199\u4e0e\u5907\u4efd")
        _append_diagnostics(lines, details.get("diagnostics", []))
    elif operation == "restore":
        details = report.get("restore_results", {})
        lines.extend([
            "",
            "## \u6062\u590d\u7ed3\u679c",
            "",
            "| \u9879\u76ee | \u7ed3\u679c |",
            "| --- | --- |",
            "| \u5173\u8054 Apply Run ID | {} |".format(_md_cell(details.get("run_id", ""))),
            "| \u6062\u590d\u6587\u4ef6 | {} |".format(len(details.get("restored_files", []))),
            "| \u51b2\u7a81\u6587\u4ef6 | {} |".format(len(details.get("conflict_files", []))),
            "| \u662f\u5426\u5f3a\u5236\u6062\u590d | {} |".format("\u662f" if details.get("forced") else "\u5426"),
            "| \u5907\u4efd\u76ee\u5f55 | {} |".format(_md_cell(details.get("state_dir", ""))),
            "| \u6062\u590d\u65e5\u5fd7 | {} |".format(_md_cell(details.get("journal_path", ""))),
            "| \u6062\u590d\u65e5\u5fd7\u72b6\u6001 | {} |".format(_md_cell(details.get("journal_status", ""))),
        ])
        conflicts = details.get("conflict_files", [])
        if conflicts:
            lines.extend(["", "### \u51b2\u7a81\u6587\u4ef6", ""])
            lines.extend("- `{}`".format(str(item).replace("`", "\\`")) for item in conflicts)
        _append_files(lines, details.get("restored_files", []), "\u672c\u6b21\u5df2\u6062\u590d\u6587\u4ef6")

    failure = report.get("failure")
    if failure:
        lines.extend([
            "",
            "## \u5931\u8d25\u4fe1\u606f",
            "",
            "- \u72b6\u6001\uff1a`{}`".format(_md_cell(failure.get("status", ""))),
            "- \u539f\u56e0\uff1a{}".format(str(failure.get("message", "")).replace("\n", " ")),
        ])

    lines.extend(["", "## \u6ce8\u610f\u4e8b\u9879", ""])
    notes = report.get("notes", [])
    if notes:
        lines.extend("- " + str(item) for item in notes)
    else:
        lines.append("- \u65e0\u3002")

    tool = report.get("tool", {})
    files = report.get("report_files", {})
    lines.extend([
        "",
        "## \u8fd0\u884c\u73af\u5883",
        "",
        "- nui-wallfix\uff1a`{}`".format(_md_cell(tool.get("version", ""))),
        "- Runtime\uff1a`{}`".format(_md_cell(tool.get("runtime_module", ""))),
        "- Python\uff1a`{}`".format(_md_cell(tool.get("python", ""))),
        "- providers SHA-256\uff1a`{}`".format(_md_cell(request.get("providers_sha256", ""))),
        "",
        "## \u62a5\u544a\u6587\u4ef6",
        "",
        "- \u5386\u53f2 JSON\uff1a`{}`".format(files.get("history_json", "")),
        "- \u5386\u53f2 Markdown\uff1a`{}`".format(files.get("history_markdown", "")),
        "- \u6700\u65b0 JSON\uff1a`{}`".format(files.get("latest_json", "")),
        "- \u6700\u65b0 Markdown\uff1a`{}`".format(files.get("latest_markdown", "")),
        "",
    ])
    return "\n".join(lines)


def _execution_metadata(execution):
    paths = execution["paths"]
    return {
        "execution_id": execution["execution_id"],
        "operation": execution["operation"],
        "json": str(paths["history_json"]),
        "markdown": str(paths["history_markdown"]),
        "latest_json": str(paths["latest_json"]),
        "latest_markdown": str(paths["latest_markdown"]),
    }


def _write_report_files(report, paths):
    json_data = (
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    markdown_data = (build_markdown(report).rstrip() + "\n").encode("utf-8")
    _v1._atomic_write(paths["history_json"], json_data)
    _v1._atomic_write(paths["history_markdown"], markdown_data)
    _v1._atomic_write(paths["latest_json"], json_data)
    _v1._atomic_write(paths["latest_markdown"], markdown_data)


def mark_output_failure(payload, message):
    metadata = payload.get("execution_report", {})
    history_json = Path(metadata.get("json", "")).expanduser().resolve()
    latest_json = Path(metadata.get("latest_json", "")).expanduser().resolve()
    root = latest_json.parent.resolve()
    paths = {
        "history_json": history_json,
        "history_markdown": Path(metadata.get("markdown", "")).expanduser().resolve(),
        "latest_json": latest_json,
        "latest_markdown": Path(metadata.get("latest_markdown", "")).expanduser().resolve(),
    }
    if not history_json.is_file():
        raise OSError("execution report JSON is missing")
    for path in paths.values():
        if not core._is_within(path, root):
            raise core.WallfixError("execution report update path escapes its report directory")
    report = json.loads(history_json.read_text(encoding="utf-8"))
    report["outcome"] = "error"
    report["exit_code"] = _v1.EXIT_WRITE
    report["failure"] = {
        "status": "json-output-error",
        "message": _sanitize(str(message), "error"),
        "conflict_files": [],
    }
    report["native_payload"] = _sanitize(copy.deepcopy(payload))
    notes = report.setdefault("notes", [])
    notes.append(
        "The core operation completed, but the separately requested --json-output file could not be written."
    )
    _write_report_files(report, paths)


def persist_report(payload, target, request, execution, runtime_module):
    metadata = _execution_metadata(execution)
    payload["execution_report"] = metadata
    report = _build_report(
        payload,
        target,
        request,
        execution,
        execution["paths"],
        runtime_module,
    )
    _write_report_files(report, execution["paths"])
    return metadata


def persist_report_safe(payload, target, request, execution, runtime_module):
    try:
        return persist_report(payload, target, request, execution, runtime_module)
    except Exception as exc:
        metadata = _execution_metadata(execution)
        metadata["write_error"] = str(exc)
        payload["execution_report"] = metadata
        return metadata
