import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import nuiwallfix
from nuiwallfix import core
from nuiwallfix import runtime_v1
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
        content_type, body, headers = route
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@contextmanager
def server(routes):
    handler = type("ReviewHandler", (_Handler,), {"routes": routes})
    instance = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=instance.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        yield "http://127.0.0.1:{}".format(instance.server_port)
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def make_resource(root, html):
    root.mkdir(parents=True)
    (root / "html").mkdir()
    (root / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles {'html/**/*'}\n",
        encoding="utf-8",
    )
    (root / "html" / "index.html").write_text(html, encoding="utf-8")


def snapshot(root):
    return {
        str(path.relative_to(root)).replace("\\", "/"): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def providers(path, source=None, target=None):
    rules = []
    if source and target:
        rules.append({"name": "fixture", "type": "prefix", "source": source, "target": target})
    path.write_text(json.dumps({"schema_version": 1, "rules": rules}), encoding="utf-8")


class ReviewFixTests(unittest.TestCase):
    def test_external_module_src_without_cors_falls_back_local(self):
        body = b"export const ok = true;"
        routes = {
            "/origin/module.js": ("application/javascript", body, {}),
            "/mirror/module.js": ("application/javascript", body, {}),
        }
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                make_resource(target, "<script type='module' src='{}/origin/module.js'></script>".format(base))
                config = workspace / "providers.json"
                providers(config, base + "/origin/", base + "/mirror/")
                result = RUNTIME.api_apply(target, mode="auto", providers=config, allow_private_network=True)
                self.assertEqual(result["references"][0]["context"], "html-module-script")
                self.assertEqual(result["summary"]["remote"], 0)
                self.assertEqual(result["summary"]["local"], 1)

    def test_member_import_call_is_report_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            make_resource(target, "<script>loader.import('https://cdn.example/app.js');</script>")
            result = core.scan_target(target)
            self.assertEqual(len(result.references), 1)
            self.assertEqual(result.references[0].context, "js-member-import")
            self.assertFalse(result.references[0].auto_allowed)

    def test_invalid_limits_and_parse_errors_keep_json_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            make_resource(target, "<div>ok</div>")
            launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"
            for option, value in (("--max-bytes", "-2"), ("--timeout", "nan")):
                process = subprocess.run(
                    [sys.executable, str(launcher), "apply", str(target), option, value, "--json"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                self.assertEqual(process.returncode, 20)
                payload = json.loads(process.stdout)
                self.assertEqual(payload["status"], "error")
            malformed = subprocess.run(
                [sys.executable, str(launcher), "apply", "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(malformed.returncode, 20)
            self.assertEqual(json.loads(malformed.stdout)["status"], "error")

    def test_provider_config_types_are_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            make_resource(target, "<div>ok</div>")
            invalid = workspace / "providers.json"
            invalid.write_text("[]", encoding="utf-8")
            with self.assertRaises(core.WallfixError):
                RUNTIME.api_apply(target, providers=invalid)
            invalid.write_text('{"schema_version":1,"rules":[{"type":"prefix","source":4,"target":[]}]}', encoding="utf-8")
            with self.assertRaises(core.WallfixError):
                RUNTIME.api_apply(target, providers=invalid)

    def test_loaded_runtime_updates_public_scan_export(self):
        self.assertIs(nuiwallfix.scan_target, core.scan_target)

    def test_run_id_dot_segments_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            make_resource(target, "<div>ok</div>")
            for run_id in (".", ".."):
                with self.assertRaises(core.WallfixError):
                    RUNTIME.api_restore(target, run_id, state_dir=Path(temporary) / "state")

    def test_restore_can_continue_from_mixed_restoring_state(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;", {})}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                make_resource(target, "<script src='{}/app.js'></script>".format(base))
                config = workspace / "providers.json"
                providers(config)
                original = snapshot(target)
                state = workspace / "state"
                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=config,
                    state_dir=state,
                    allow_private_network=True,
                )
                run_dir = state / "runs" / applied["run_id"]
                journal_path = run_dir / "run.json"
                journal = json.loads(journal_path.read_text(encoding="utf-8"))
                first_existing = next(item for item in journal["files"] if item["existed_before"])
                target_file = target / first_existing["path"]
                target_file.write_bytes((run_dir / first_existing["backup"]).read_bytes())
                journal["status"] = "restoring"
                journal["restore_from_status"] = "applied"
                journal_path.write_text(json.dumps(journal), encoding="utf-8")
                restored = RUNTIME.api_restore(target, applied["run_id"], state_dir=state)
                self.assertEqual(restored["status"], "restored")
                self.assertEqual(snapshot(target), original)

    def test_restore_final_journal_failure_rolls_back_and_can_retry(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;", {})}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                make_resource(target, "<script src='{}/app.js'></script>".format(base))
                config = workspace / "providers.json"
                providers(config)
                state = workspace / "state"
                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=config,
                    state_dir=state,
                    allow_private_network=True,
                )
                applied_snapshot = snapshot(target)
                original_writer = runtime_v1._write_json

                def fail_finished_restore(path, payload):
                    if payload.get("status") in ("restored", "recovered"):
                        raise OSError("simulated restore journal failure")
                    return original_writer(path, payload)

                runtime_v1._write_json = fail_finished_restore
                try:
                    with self.assertRaises(OSError):
                        RUNTIME.api_restore(target, applied["run_id"], state_dir=state)
                finally:
                    runtime_v1._write_json = original_writer
                self.assertEqual(snapshot(target), applied_snapshot)
                journal = json.loads((state / "runs" / applied["run_id"] / "run.json").read_text(encoding="utf-8"))
                self.assertEqual(journal["status"], "restoring")
                restored = RUNTIME.api_restore(target, applied["run_id"], state_dir=state)
                self.assertEqual(restored["status"], "restored")


if __name__ == "__main__":
    unittest.main()
