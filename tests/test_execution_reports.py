import hashlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from nuiwallfix import core, reporting
from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


class _Handler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        route = self.routes.get(self.path.split("?", 1)[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        content_type, data = route
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format, *_args):
        return


@contextmanager
def route_server(routes):
    handler = type("ExecutionReportHandler", (_Handler,), {"routes": routes})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        yield "http://127.0.0.1:{}".format(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def write_resource(target, html):
    (target / "html").mkdir(parents=True)
    (target / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\n"
        "game 'gta5'\n"
        "ui_page 'html/index.html'\n"
        "files { 'html/index.html' }\n",
        encoding="utf-8",
    )
    (target / "html" / "index.html").write_text(html, encoding="utf-8")


def snapshot(root):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class ExecutionReportTests(unittest.TestCase):
    def test_scan_report_redacts_persistent_urls_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            report_dir = workspace / "reports"
            original_url = "https://user:pass@cdn.example/app.js?token=secret#section"
            write_resource(target, "<script src='{}'></script>".format(original_url))

            payload = RUNTIME.api_scan(target, report_dir=report_dir)
            self.assertEqual(payload["references"][0]["url"], original_url)
            metadata = payload["execution_report"]
            report_text = Path(metadata["json"]).read_text(encoding="utf-8")
            report = json.loads(report_text)

            self.assertEqual(report["operation"], "scan")
            self.assertEqual(report["outcome"], "success")
            self.assertFalse(report["safety"]["target_modified"])
            self.assertNotIn("user:pass", report_text)
            self.assertNotIn("token=secret", report_text)
            self.assertNotIn("#section", report_text)
            self.assertIn("<redacted>", report_text)
            self.assertTrue(Path(metadata["markdown"]).is_file())
            self.assertTrue(Path(metadata["latest_json"]).is_file())
            self.assertTrue(Path(metadata["latest_markdown"]).is_file())

            protocol_relative = reporting._sanitize({
                "url": "//user:pass@cdn.example/a.js?token=secret#frag"
            })["url"]
            malformed = reporting._sanitize({
                "url": "http://[bad?token=secret#frag"
            })["url"]
            self.assertNotIn("user:pass", protocol_relative)
            self.assertNotIn("token=secret", protocol_relative)
            self.assertNotIn("#frag", protocol_relative)
            self.assertEqual(malformed, "<redacted-url>")
            for prefix in (" ", "\t"):
                spaced = reporting._sanitize({
                    "url": prefix + "//user:pass@cdn.example/a.js?token=secret#frag"
                })["url"]
                self.assertNotIn("user:pass", spaced)
                self.assertNotIn("token=secret", spaced)
                self.assertNotIn("#frag", spaced)

    def test_preview_report_records_zero_target_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            write_resource(
                target,
                "<script>fetch('https://api.example/player?key=secret')</script>",
            )
            before = snapshot(target)

            payload = RUNTIME.api_apply(
                target,
                mode="auto",
                write=False,
                report_dir=workspace / "reports",
            )
            report = json.loads(Path(payload["execution_report"]["json"]).read_text(encoding="utf-8"))

            self.assertEqual(snapshot(target), before)
            self.assertEqual(report["operation"], "preview")
            self.assertFalse(report["safety"]["target_modified"])
            self.assertFalse(report["safety"]["backup_created"])
            self.assertEqual(report["resolution_preview"]["target_files_written"], 0)

    def test_apply_and_restore_have_independent_reports_and_conflict_evidence(self):
        routes = {"/app.js": ("application/javascript", b"window.reportTest = true;")}
        with route_server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                reports = workspace / "reports"
                state = workspace / "backups"
                providers = workspace / "providers.json"
                providers.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
                write_resource(target, "<script src='{}/app.js'></script>".format(base))

                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=providers,
                    state_dir=state,
                    allow_private_network=True,
                    report_dir=reports,
                )
                apply_report = json.loads(
                    Path(applied["execution_report"]["json"]).read_text(encoding="utf-8")
                )
                self.assertEqual(apply_report["operation"], "apply")
                self.assertEqual(apply_report["apply_results"]["run_id"], applied["run_id"])
                self.assertTrue(Path(apply_report["apply_results"]["journal_path"]).is_file())
                changed = apply_report["apply_results"]["changed_files"]
                self.assertTrue(changed)
                self.assertTrue(all("before_sha256" in item for item in changed))
                self.assertTrue(all("after_sha256" in item for item in changed))

                index = target / "html" / "index.html"
                index.write_text(index.read_text(encoding="utf-8") + "\n<!-- changed -->", encoding="utf-8")
                with self.assertRaises(core.RestoreConflict) as conflict:
                    RUNTIME.api_restore(
                        target,
                        applied["run_id"],
                        state_dir=state,
                        report_dir=reports,
                    )
                conflict_payload = conflict.exception.wallfix_payload
                conflict_report = json.loads(
                    Path(conflict_payload["execution_report"]["json"]).read_text(encoding="utf-8")
                )
                self.assertEqual(conflict_report["operation"], "restore")
                self.assertEqual(conflict_report["outcome"], "conflict")
                self.assertTrue(conflict_report["restore_results"]["conflict_files"])
                self.assertFalse(conflict_report["restore_results"]["restored_files"])

                restored = RUNTIME.api_restore(
                    target,
                    applied["run_id"],
                    state_dir=state,
                    force=True,
                    report_dir=reports,
                )
                restore_report = json.loads(
                    Path(restored["execution_report"]["json"]).read_text(encoding="utf-8")
                )
                ids = {
                    applied["execution_report"]["execution_id"],
                    conflict_payload["execution_report"]["execution_id"],
                    restored["execution_report"]["execution_id"],
                }
                self.assertEqual(len(ids), 3)
                self.assertEqual(restore_report["outcome"], "success")
                self.assertTrue(restore_report["restore_results"]["forced"])
                self.assertEqual(
                    restore_report["restore_results"]["conflict_files"],
                    ["html/index.html"],
                )
                self.assertTrue(restore_report["restore_results"]["restored_files"])

    def test_input_error_and_interrupt_still_write_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            reports = workspace / "reports"
            missing = workspace / "missing"
            with self.assertRaises(core.WallfixError) as failed:
                RUNTIME.api_scan(missing, report_dir=reports)
            failure_payload = failed.exception.wallfix_payload
            failure_report = json.loads(
                Path(failure_payload["execution_report"]["json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(failure_report["outcome"], "error")
            self.assertIn("failure", failure_report)

            target = workspace / "demo"
            write_resource(target, "<p>ok</p>")
            with mock.patch.object(RUNTIME._v11, "api_scan", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt) as interrupted:
                    RUNTIME.api_scan(target, report_dir=reports)
            interrupt_payload = interrupted.exception.wallfix_payload
            interrupt_report = json.loads(
                Path(interrupt_payload["execution_report"]["json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(interrupt_report["outcome"], "interrupted")
            self.assertEqual(interrupt_report["exit_code"], 130)

    def test_rollback_incomplete_report_recovers_run_id_and_warns_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            state = workspace / "state"
            reports = workspace / "reports"
            write_resource(target, "<p>ok</p>")
            run_id = "20260718-120000-abcdef"

            def fail_after_partial_write(*_args, **_kwargs):
                run_dir = state / "runs" / run_id
                run_dir.mkdir(parents=True)
                journal = {
                    "schema_version": 1,
                    "run_id": run_id,
                    "target": str(target.resolve()),
                    "mode": "auto",
                    "status": "rollback-incomplete",
                    "files": [{
                        "path": "html/index.html",
                        "existed_before": True,
                        "before_sha256": "before",
                        "after_sha256": "after",
                        "backup": "files/html/index.html",
                    }],
                    "result_summary": {
                        "resources": 1,
                        "references": 1,
                        "written_files": 0,
                    },
                    "rollback_errors": ["html/index.html: access denied"],
                }
                (run_dir / "run.json").write_text(json.dumps(journal), encoding="utf-8")
                raise core.WallfixError("apply failed and rollback was incomplete")

            with mock.patch.object(RUNTIME._v11, "api_apply", side_effect=fail_after_partial_write):
                with self.assertRaises(core.WallfixError) as failed:
                    RUNTIME.api_apply(
                        target,
                        write=True,
                        state_dir=state,
                        report_dir=reports,
                    )
            payload = failed.exception.wallfix_payload
            report = json.loads(
                Path(payload["execution_report"]["json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(report["apply_results"]["run_id"], run_id)
            self.assertEqual(report["apply_results"]["journal_status"], "rollback-incomplete")
            self.assertTrue(report["safety"]["target_modified"])
            self.assertEqual(report["safety"]["target_state"], "possibly-partial")
            self.assertTrue(any("CRITICAL" in note for note in report["notes"]))
            self.assertEqual(
                report["apply_results"]["rollback_errors"],
                ["html/index.html: access denied"],
            )

    def test_failed_apply_does_not_attach_recent_preexisting_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            state = workspace / "state"
            reports = workspace / "reports"
            write_resource(target, "<p>ok</p>")
            old_run_id = "20260718-110000-oldrun"
            run_dir = state / "runs" / old_run_id
            run_dir.mkdir(parents=True)
            (run_dir / "run.json").write_text(json.dumps({
                "schema_version": 1,
                "run_id": old_run_id,
                "target": str(target.resolve()),
                "mode": "auto",
                "status": "applied",
                "files": [],
                "result_summary": {"resources": 99},
            }), encoding="utf-8")

            with self.assertRaises(core.WallfixError) as failed:
                RUNTIME.api_apply(
                    target,
                    mode="invalid",
                    write=True,
                    state_dir=state,
                    report_dir=reports,
                )
            payload = failed.exception.wallfix_payload
            report = json.loads(
                Path(payload["execution_report"]["json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(report["apply_results"]["run_id"], "")
            self.assertEqual(report["apply_results"]["journal_status"], "")
            self.assertNotEqual(report["summary"].get("resources"), 99)

    def test_restore_conflict_precheck_matches_restoring_and_restored_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            state = workspace / "state"
            target.mkdir()
            relative = "file,with-comma.js"
            path = target / relative
            before = b"before"
            after = b"after"
            path.write_bytes(before)
            run_id = "20260718-130000-abcdef"
            run_dir = state / "runs" / run_id
            run_dir.mkdir(parents=True)
            journal_path = run_dir / "run.json"
            journal = {
                "schema_version": 1,
                "run_id": run_id,
                "target": str(target.resolve()),
                "status": "restoring",
                "files": [{
                    "path": relative,
                    "existed_before": True,
                    "before_sha256": hashlib.sha256(before).hexdigest(),
                    "after_sha256": hashlib.sha256(after).hexdigest(),
                    "backup": "files/" + relative,
                }],
            }
            journal_path.write_text(json.dumps(journal), encoding="utf-8")
            self.assertEqual(RUNTIME._inspect_restore_conflicts(target, run_id, state), [])
            journal["status"] = "restored"
            journal_path.write_text(json.dumps(journal), encoding="utf-8")
            self.assertEqual(RUNTIME._inspect_restore_conflicts(target, run_id, state), [])

    def test_report_write_failure_still_prints_applied_run_for_human_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            state = workspace / "state"
            write_resource(target, "<p>ok</p>")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                RUNTIME.reporting,
                "persist_report",
                side_effect=OSError("report disk unavailable"),
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = RUNTIME._main_impl([
                        "apply",
                        str(target),
                        "--write",
                        "--state-dir",
                        str(state),
                    ])
            self.assertEqual(code, 40)
            self.assertIn("Status: applied", stdout.getvalue())
            self.assertIn("Run ID:", stdout.getvalue())
            self.assertIn("execution report could not be written", stderr.getvalue())
            self.assertTrue(list((state / "runs").glob("*/run.json")))

    def test_json_output_failure_updates_execution_report_and_keeps_single_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            reports = workspace / "reports"
            invalid_output = workspace / "is-a-directory"
            invalid_output.mkdir()
            write_resource(target, "<p>ok</p>")
            launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"
            process = subprocess.run(
                [
                    sys.executable,
                    str(launcher),
                    "scan",
                    str(target),
                    "--json",
                    "--report-dir",
                    str(reports),
                    "--json-output",
                    str(invalid_output),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(process.returncode, 40)
            self.assertEqual(process.stderr, "")
            self.assertEqual(process.stdout.count("\n"), 1)
            payload = json.loads(process.stdout)
            self.assertIn("json_output_error", payload)
            report = json.loads(
                Path(payload["execution_report"]["json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(report["outcome"], "error")
            self.assertEqual(report["exit_code"], 40)
            self.assertEqual(report["failure"]["status"], "json-output-error")

    def test_cli_json_is_single_object_and_parse_error_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            reports = workspace / "reports"
            write_resource(target, "<script src='https://cdn.example/app.js'></script>")
            launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"

            process = subprocess.run(
                [
                    sys.executable,
                    str(launcher),
                    "scan",
                    str(target),
                    "--json",
                    "--report-dir",
                    str(reports),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            payload = json.loads(process.stdout)
            self.assertEqual(process.stdout.count("\n"), 1)
            self.assertTrue(Path(payload["execution_report"]["markdown"]).is_file())

            invalid = subprocess.run(
                [
                    sys.executable,
                    str(launcher),
                    "scan",
                    str(target),
                    "--not-an-option",
                    "--json",
                    "--report-dir",
                    str(reports),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(invalid.returncode, 20)
            self.assertEqual(invalid.stderr, "")
            invalid_payload = json.loads(invalid.stdout)
            self.assertEqual(invalid_payload["status"], "error")
            self.assertTrue(Path(invalid_payload["execution_report"]["json"]).is_file())

            traversal = subprocess.run(
                [
                    sys.executable,
                    str(launcher),
                    "x/../../escaped",
                    "--json",
                    "--report-dir",
                    str(reports),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(traversal.returncode, 20)
            traversal_payload = json.loads(traversal.stdout)
            latest = Path(traversal_payload["execution_report"]["latest_json"]).resolve()
            self.assertEqual(latest.parent, reports.resolve())
            self.assertEqual(latest.name, "latest-unknown.json")
            self.assertFalse((workspace / "escaped.json").exists())


if __name__ == "__main__":
    unittest.main()
